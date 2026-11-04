package genesis

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	batchv1 "k8s.io/api/batch/v1"
	corek8s "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type upgradeTestClient struct {
	octeliumc.ClientInterface
	core rcorev1.ResourceServiceClient
}

func (c *upgradeTestClient) CoreC() rcorev1.ResourceServiceClient { return c.core }

type upgradeTestCore struct {
	rcorev1.ResourceServiceClient
	listService         func(context.Context, *rmetav1.ListOptions) (*corev1.ServiceList, error)
	getService          func(context.Context, *rmetav1.GetOptions) (*corev1.Service, error)
	updateService       func(context.Context, *corev1.Service) (*corev1.Service, error)
	listAuthenticator   func(context.Context, *rmetav1.ListOptions) (*corev1.AuthenticatorList, error)
	getAuthenticator    func(context.Context, *rmetav1.GetOptions) (*corev1.Authenticator, error)
	updateAuthenticator func(context.Context, *corev1.Authenticator) (*corev1.Authenticator, error)
	getSecret           func(context.Context, *rmetav1.GetOptions) (*corev1.Secret, error)
	createSecret        func(context.Context, *corev1.Secret) (*corev1.Secret, error)
	getRegion           func(context.Context, *rmetav1.GetOptions) (*corev1.Region, error)
	updateRegion        func(context.Context, *corev1.Region) (*corev1.Region, error)
}

func (c *upgradeTestCore) ListService(ctx context.Context, o *rmetav1.ListOptions, _ ...grpc.CallOption) (*corev1.ServiceList, error) {
	return c.listService(ctx, o)
}

func (c *upgradeTestCore) GetService(ctx context.Context, o *rmetav1.GetOptions, _ ...grpc.CallOption) (*corev1.Service, error) {
	return c.getService(ctx, o)
}

func (c *upgradeTestCore) UpdateService(ctx context.Context, o *corev1.Service, _ ...grpc.CallOption) (*corev1.Service, error) {
	return c.updateService(ctx, o)
}

func (c *upgradeTestCore) ListAuthenticator(ctx context.Context, o *rmetav1.ListOptions, _ ...grpc.CallOption) (*corev1.AuthenticatorList, error) {
	return c.listAuthenticator(ctx, o)
}

func (c *upgradeTestCore) GetAuthenticator(ctx context.Context, o *rmetav1.GetOptions, _ ...grpc.CallOption) (*corev1.Authenticator, error) {
	return c.getAuthenticator(ctx, o)
}

func (c *upgradeTestCore) UpdateAuthenticator(ctx context.Context, o *corev1.Authenticator, _ ...grpc.CallOption) (*corev1.Authenticator, error) {
	return c.updateAuthenticator(ctx, o)
}

func (c *upgradeTestCore) GetSecret(ctx context.Context, o *rmetav1.GetOptions, _ ...grpc.CallOption) (*corev1.Secret, error) {
	return c.getSecret(ctx, o)
}

func (c *upgradeTestCore) CreateSecret(ctx context.Context, o *corev1.Secret, _ ...grpc.CallOption) (*corev1.Secret, error) {
	return c.createSecret(ctx, o)
}

func (c *upgradeTestCore) GetRegion(ctx context.Context, o *rmetav1.GetOptions, _ ...grpc.CallOption) (*corev1.Region, error) {
	return c.getRegion(ctx, o)
}

func (c *upgradeTestCore) UpdateRegion(ctx context.Context, o *corev1.Region, _ ...grpc.CallOption) (*corev1.Region, error) {
	return c.updateRegion(ctx, o)
}

func upgradeTestGenesis(c *upgradeTestCore) *Genesis {
	return &Genesis{octeliumC: &upgradeTestClient{core: c}}
}

func TestRequiredUpgradeServiceMarkerFailure(t *testing.T) {
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "app.default", Uid: "service-uid"},
		Spec:     &corev1.Service_Spec{},
		Status:   &corev1.Service_Status{RegionRef: &metav1.ObjectReference{Uid: "region-uid"}},
	}
	c := &upgradeTestCore{
		listService: func(context.Context, *rmetav1.ListOptions) (*corev1.ServiceList, error) {
			return &corev1.ServiceList{Items: []*corev1.Service{svc}}, nil
		},
		getService: func(context.Context, *rmetav1.GetOptions) (*corev1.Service, error) { return svc, nil },
		updateService: func(context.Context, *corev1.Service) (*corev1.Service, error) {
			return nil, status.Error(codes.PermissionDenied, "marker write denied")
		},
	}
	err := upgradeTestGenesis(c).updateServicesUpgradeUID(t.Context(), &corev1.Region{Metadata: &metav1.Metadata{Uid: "region-uid"}})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRequiredUpgradeAuthenticatorFailure(t *testing.T) {
	authenticator := &corev1.Authenticator{Metadata: &metav1.Metadata{Name: "legacy", Uid: "authenticator-uid"}, Spec: &corev1.Authenticator_Spec{}}
	c := &upgradeTestCore{
		listAuthenticator: func(context.Context, *rmetav1.ListOptions) (*corev1.AuthenticatorList, error) {
			return &corev1.AuthenticatorList{Items: []*corev1.Authenticator{authenticator}}, nil
		},
		getAuthenticator: func(context.Context, *rmetav1.GetOptions) (*corev1.Authenticator, error) {
			return authenticator, nil
		},
		updateAuthenticator: func(context.Context, *corev1.Authenticator) (*corev1.Authenticator, error) {
			return nil, status.Error(codes.PermissionDenied, "migration write denied")
		},
	}
	err := upgradeTestGenesis(c).doPostUpgrade(t.Context())
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

func upgradeTestPod(jobUID string) *corek8s.Pod {
	return &corek8s.Pod{ObjectMeta: k8smetav1.ObjectMeta{
		Name: "attempt", Namespace: "octelium", UID: "pod-uid",
		OwnerReferences: []k8smetav1.OwnerReference{{Kind: "Job", Name: "legacy-random-job", UID: types.UID(jobUID), Controller: new(true)}},
	}}
}

func upgradeTestService() *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{Name: "app.default", Uid: "service-uid", ResourceVersion: "1", Labels: map[string]string{"user": "preserved"}, SystemLabels: map[string]string{"other": "preserved", vutils.UpgradeIDKey: "previous"}},
		Spec:     &corev1.Service_Spec{Port: 8080},
		Status:   &corev1.Service_Status{RegionRef: &metav1.ObjectReference{Uid: "region-uid"}},
	}
}

func TestUpgradeServiceMarkerRetries(t *testing.T) {
	for _, point := range []string{"conflict", "before-write", "after-write", "read-outage", "deleted-read", "deleted-write", "moved-region", "marked", "permission", "read-permission", "continuous-conflict", "continuous-unavailable"} {
		t.Run(point, func(t *testing.T) {
			stored := upgradeTestService()
			listed := proto.Clone(stored).(*corev1.Service)
			input := proto.Clone(listed)
			reads, writes := 0, 0
			c := &upgradeTestCore{
				listService: func(context.Context, *rmetav1.ListOptions) (*corev1.ServiceList, error) {
					return &corev1.ServiceList{Items: []*corev1.Service{listed}}, nil
				},
				getService: func(_ context.Context, o *rmetav1.GetOptions) (*corev1.Service, error) {
					assert.Equal(t, &rmetav1.GetOptions{Uid: listed.Metadata.Uid}, o)
					reads++
					if point == "deleted-read" {
						return nil, status.Error(codes.NotFound, "removed")
					}
					if point == "read-permission" {
						return nil, status.Error(codes.PermissionDenied, "read denied")
					}
					if point == "read-outage" && reads == 1 {
						return nil, status.Error(codes.Unavailable, "temporary read outage")
					}
					if point == "moved-region" {
						stored.Status.RegionRef.Uid = "other-region"
					}
					if point == "marked" {
						stored.Metadata.SystemLabels[vutils.UpgradeIDKey] = "job-uid"
					}
					return stored, nil
				},
				updateService: func(_ context.Context, current *corev1.Service) (*corev1.Service, error) {
					writes++
					if point == "permission" {
						return nil, status.Error(codes.PermissionDenied, "write denied")
					}
					if point == "deleted-write" {
						return nil, status.Error(codes.NotFound, "removed")
					}
					if point == "continuous-conflict" || (point == "conflict" && writes == 1) {
						assert.Equal(t, "previous", stored.Metadata.SystemLabels[vutils.UpgradeIDKey])
						stored = proto.Clone(stored).(*corev1.Service)
						stored.Metadata.ResourceVersion = "concurrent"
						stored.Spec.Port = 9090
						stored.Metadata.Annotations = map[string]string{"concurrent": "preserved"}
						return nil, status.Error(codes.OutOfRange, "resource changed")
					}
					if point == "continuous-unavailable" || (point == "before-write" && writes == 1) {
						return nil, status.Error(codes.Unavailable, "temporary write outage")
					}
					assert.Equal(t, "job-uid", current.Metadata.SystemLabels[vutils.UpgradeIDKey])
					assert.Equal(t, "preserved", current.Metadata.SystemLabels["other"])
					assert.Equal(t, "preserved", current.Metadata.Labels["user"])
					if point == "conflict" {
						assert.Equal(t, "concurrent", current.Metadata.ResourceVersion)
						assert.Equal(t, int32(9090), int32(current.Spec.Port))
						assert.Equal(t, "preserved", current.Metadata.Annotations["concurrent"])
					}
					stored = proto.Clone(current).(*corev1.Service)
					if point == "after-write" && writes == 1 {
						return nil, status.Error(codes.DeadlineExceeded, "response lost after commit")
					}
					return current, nil
				},
			}
			g := upgradeTestGenesis(c)
			g.pod = upgradeTestPod("job-uid")
			err := g.updateServicesUpgradeUID(t.Context(), &corev1.Region{Metadata: &metav1.Metadata{Uid: "region-uid"}})
			switch point {
			case "permission", "read-permission":
				require.Equal(t, codes.PermissionDenied, status.Code(err))
				assert.Equal(t, 1, reads)
			case "continuous-conflict":
				require.True(t, grpcerr.IsResourceChanged(err))
				assert.Equal(t, 5, writes)
			case "continuous-unavailable":
				require.True(t, grpcerr.IsUnavailable(err))
				assert.Equal(t, 5, writes)
			default:
				require.NoError(t, err)
			}
			switch point {
			case "conflict", "before-write":
				assert.Equal(t, 2, writes)
			case "after-write":
				assert.Equal(t, 1, writes)
				assert.Equal(t, 2, reads)
			case "deleted-read", "moved-region", "marked", "read-permission":
				assert.Zero(t, writes)
			}
			assert.True(t, proto.Equal(input, listed))
		})
	}
}

func TestUpgradeServiceMarkerPartialResume(t *testing.T) {
	first := upgradeTestService()
	second := proto.Clone(first).(*corev1.Service)
	second.Metadata.Name, second.Metadata.Uid = "second.default", "second-uid"
	stored := map[string]*corev1.Service{first.Metadata.Uid: first, second.Metadata.Uid: second}
	failed := true
	writes := map[string]int{}
	c := &upgradeTestCore{
		listService: func(context.Context, *rmetav1.ListOptions) (*corev1.ServiceList, error) {
			return &corev1.ServiceList{Items: []*corev1.Service{stored[first.Metadata.Uid], stored[second.Metadata.Uid]}}, nil
		},
		getService: func(_ context.Context, o *rmetav1.GetOptions) (*corev1.Service, error) { return stored[o.Uid], nil },
		updateService: func(_ context.Context, svc *corev1.Service) (*corev1.Service, error) {
			writes[svc.Metadata.Uid]++
			if failed && svc.Metadata.Uid == second.Metadata.Uid {
				return nil, status.Error(codes.PermissionDenied, "second Service denied")
			}
			stored[svc.Metadata.Uid] = proto.Clone(svc).(*corev1.Service)
			return svc, nil
		},
	}
	region := &corev1.Region{Metadata: &metav1.Metadata{Uid: "region-uid"}}
	g := upgradeTestGenesis(c)
	g.pod = upgradeTestPod("original-job")
	require.ErrorContains(t, g.updateServicesUpgradeUID(t.Context(), region), second.Metadata.Name)
	assert.Equal(t, "original-job", stored[first.Metadata.Uid].Metadata.SystemLabels[vutils.UpgradeIDKey])
	assert.Equal(t, "previous", stored[second.Metadata.Uid].Metadata.SystemLabels[vutils.UpgradeIDKey])
	failed = false
	restarted := upgradeTestGenesis(c)
	restarted.pod = upgradeTestPod("original-job")
	restarted.pod.Name, restarted.pod.UID = "retry-pod", "retry-pod-uid"
	for range 2 {
		require.NoError(t, restarted.updateServicesUpgradeUID(t.Context(), region))
	}
	assert.Equal(t, 1, writes[first.Metadata.Uid])
	assert.Equal(t, 2, writes[second.Metadata.Uid])
	restarted.pod = upgradeTestPod("next-job")
	require.NoError(t, restarted.updateServicesUpgradeUID(t.Context(), region))
	assert.Equal(t, 2, writes[first.Metadata.Uid])
	assert.Equal(t, 3, writes[second.Metadata.Uid])
	for _, svc := range stored {
		assert.Equal(t, "next-job", svc.Metadata.SystemLabels[vutils.UpgradeIDKey])
	}
}

func TestUpgradeServiceMarkerLegacyFallback(t *testing.T) {
	for _, pod := range []*corek8s.Pod{nil, {}, upgradeTestPod("")} {
		stored := upgradeTestService()
		stored.Metadata.SystemLabels = nil
		c := &upgradeTestCore{
			listService: func(context.Context, *rmetav1.ListOptions) (*corev1.ServiceList, error) {
				return &corev1.ServiceList{Items: []*corev1.Service{stored}}, nil
			},
			getService: func(context.Context, *rmetav1.GetOptions) (*corev1.Service, error) { return stored, nil },
			updateService: func(_ context.Context, svc *corev1.Service) (*corev1.Service, error) {
				stored = proto.Clone(svc).(*corev1.Service)
				return svc, nil
			},
		}
		g := upgradeTestGenesis(c)
		g.pod = pod
		previous := ""
		for range 2 {
			require.NoError(t, g.updateServicesUpgradeUID(t.Context(), &corev1.Region{Metadata: &metav1.Metadata{Uid: "region-uid"}}))
			current := stored.Metadata.SystemLabels[vutils.UpgradeIDKey]
			assert.Len(t, current, 12)
			assert.NotEqual(t, previous, current)
			previous = current
		}
	}
}

func TestUpgradeServicePagination(t *testing.T) {
	for _, failure := range []string{"recover", "permanent", "exhausted"} {
		t.Run(failure, func(t *testing.T) {
			calls := []uint32{}
			c := &upgradeTestCore{listService: func(_ context.Context, o *rmetav1.ListOptions) (*corev1.ServiceList, error) {
				calls = append(calls, o.Page)
				assert.True(t, o.Paginate)
				assert.Equal(t, uint32(500), o.ItemsPerPage)
				require.Len(t, o.Filters, 1)
				if o.Page == 1 && (len(calls) == 2 || failure != "recover") {
					if failure == "permanent" {
						return nil, status.Error(codes.PermissionDenied, "list denied")
					}
					return nil, status.Error(codes.Unavailable, "list outage")
				}
				return &corev1.ServiceList{
					Items:            []*corev1.Service{{Metadata: &metav1.Metadata{Uid: fmt.Sprint(o.Page)}}},
					ListResponseMeta: &metav1.ListResponseMeta{HasMore: o.Page < 2},
				}, nil
			}}
			list, err := upgradeTestGenesis(c).getAllServices(t.Context(), &corev1.Region{Metadata: &metav1.Metadata{Uid: "region-uid"}})
			switch failure {
			case "recover":
				require.NoError(t, err)
				require.Len(t, list, 3)
				assert.Equal(t, []uint32{0, 1, 1, 2}, calls)
			case "permanent":
				require.True(t, grpcerr.IsPermissionDenied(err))
				assert.Nil(t, list)
				assert.Equal(t, []uint32{0, 1}, calls)
			case "exhausted":
				require.True(t, grpcerr.IsUnavailable(err))
				assert.Nil(t, list)
				assert.Len(t, calls, 6)
			}
		})
	}
}

func TestUpgradeAuthenticatorMigrationRetries(t *testing.T) {
	for _, point := range []string{"legacy", "nil-spec", "conflict", "before-write", "after-write", "read-outage", "list-outage", "deleted-read", "deleted-write", "rejected", "pending", "active", "permission", "list-permission", "continuous-conflict", "continuous-unavailable"} {
		t.Run(point, func(t *testing.T) {
			stored := &corev1.Authenticator{
				Metadata: &metav1.Metadata{Name: "legacy", Uid: "authenticator-uid", ResourceVersion: "1", Labels: map[string]string{"user": "preserved"}},
				Spec:     &corev1.Authenticator_Spec{DisplayName: "Customer authenticator"},
				Status:   &corev1.Authenticator_Status{Description: "Preserved status", SuccessfulAuthentications: 7, IsRegistered: true},
			}
			if point == "nil-spec" {
				stored.Spec = nil
			}
			listed := proto.Clone(stored).(*corev1.Authenticator)
			input := proto.Clone(listed)
			lists, reads, writes := 0, 0, 0
			c := &upgradeTestCore{
				listAuthenticator: func(context.Context, *rmetav1.ListOptions) (*corev1.AuthenticatorList, error) {
					lists++
					if point == "list-permission" {
						return nil, status.Error(codes.PermissionDenied, "list denied")
					}
					if point == "list-outage" && lists == 1 {
						return nil, status.Error(codes.Unavailable, "list outage")
					}
					return &corev1.AuthenticatorList{Items: []*corev1.Authenticator{listed}}, nil
				},
				getAuthenticator: func(_ context.Context, o *rmetav1.GetOptions) (*corev1.Authenticator, error) {
					assert.Equal(t, &rmetav1.GetOptions{Uid: listed.Metadata.Uid}, o)
					reads++
					if point == "deleted-read" {
						return nil, status.Error(codes.NotFound, "deleted")
					}
					if point == "read-outage" && reads == 1 {
						return nil, status.Error(codes.Unavailable, "read outage")
					}
					switch point {
					case "rejected":
						stored.Spec.State = corev1.Authenticator_Spec_REJECTED
					case "pending":
						stored.Spec.State = corev1.Authenticator_Spec_PENDING
					case "active":
						stored.Spec.State = corev1.Authenticator_Spec_ACTIVE
					}
					return stored, nil
				},
				updateAuthenticator: func(_ context.Context, current *corev1.Authenticator) (*corev1.Authenticator, error) {
					writes++
					assert.Equal(t, corev1.Authenticator_Spec_STATE_UNKNOWN, stored.GetSpec().GetState())
					if point == "deleted-write" {
						return nil, status.Error(codes.NotFound, "deleted")
					}
					if point == "permission" {
						return nil, status.Error(codes.PermissionDenied, "write denied")
					}
					if point == "continuous-conflict" || (point == "conflict" && writes == 1) {
						stored = proto.Clone(stored).(*corev1.Authenticator)
						stored.Spec.State = corev1.Authenticator_Spec_REJECTED
						if point == "continuous-conflict" {
							stored.Spec.State = corev1.Authenticator_Spec_STATE_UNKNOWN
						}
						return nil, status.Error(codes.OutOfRange, "concurrent rejection")
					}
					if point == "continuous-unavailable" || (point == "before-write" && writes == 1) {
						return nil, status.Error(codes.Unavailable, "write outage")
					}
					assert.Equal(t, corev1.Authenticator_Spec_ACTIVE, current.Spec.State)
					assert.Equal(t, stored.GetSpec().GetDisplayName(), current.Spec.DisplayName)
					assert.True(t, proto.Equal(stored.Status, current.Status))
					assert.True(t, proto.Equal(stored.Metadata, current.Metadata))
					stored = proto.Clone(current).(*corev1.Authenticator)
					if point == "after-write" && writes == 1 {
						return nil, status.Error(codes.Unavailable, "response lost")
					}
					return current, nil
				},
			}
			err := upgradeTestGenesis(c).doPostUpgrade(t.Context())
			switch point {
			case "permission", "list-permission":
				require.Equal(t, codes.PermissionDenied, status.Code(err))
			case "continuous-conflict":
				require.True(t, grpcerr.IsResourceChanged(err))
				assert.Equal(t, 5, writes)
			case "continuous-unavailable":
				require.True(t, grpcerr.IsUnavailable(err))
				assert.Equal(t, 5, writes)
			default:
				require.NoError(t, err)
			}
			switch point {
			case "conflict":
				assert.Equal(t, corev1.Authenticator_Spec_REJECTED, stored.Spec.State)
				assert.Equal(t, 1, writes)
			case "after-write":
				assert.Equal(t, 1, writes)
				assert.Equal(t, 2, reads)
			case "deleted-read", "rejected", "pending", "active", "list-permission":
				assert.Zero(t, writes)
			case "legacy", "nil-spec":
				assert.Equal(t, corev1.Authenticator_Spec_ACTIVE, stored.Spec.State)
				assert.Equal(t, 1, writes)
			}
			assert.True(t, proto.Equal(input, listed))
		})
	}
}

func TestUpgradeAuthenticatorMigrationSkipsExplicitStates(t *testing.T) {
	for _, state := range []corev1.Authenticator_Spec_State{corev1.Authenticator_Spec_ACTIVE, corev1.Authenticator_Spec_PENDING, corev1.Authenticator_Spec_REJECTED} {
		t.Run(state.String(), func(t *testing.T) {
			c := &upgradeTestCore{listAuthenticator: func(context.Context, *rmetav1.ListOptions) (*corev1.AuthenticatorList, error) {
				return &corev1.AuthenticatorList{Items: []*corev1.Authenticator{{Metadata: &metav1.Metadata{Uid: "explicit-state"}, Spec: &corev1.Authenticator_Spec{State: state}}}}, nil
			}}
			require.NoError(t, upgradeTestGenesis(c).doPostUpgrade(t.Context()))
		})
	}
}

func TestUpgradeSeedPreservationAndRetry(t *testing.T) {
	for _, point := range []string{"existing", "legacy-empty", "new", "read-outage", "create-before", "create-after", "permission"} {
		t.Run(point, func(t *testing.T) {
			var stored *corev1.Secret
			if point == "existing" || point == "legacy-empty" {
				stored = &corev1.Secret{Metadata: &metav1.Metadata{Name: "sys:ssh-svc-seed", Uid: "legacy-seed"}, Data: &corev1.Secret_Data{Type: &corev1.Secret_Data_ValueBytes{ValueBytes: []byte("preserve existing seed bytes")}}}
				if point == "legacy-empty" {
					stored.Data = nil
				}
			}
			reads, creates := 0, 0
			var created *corev1.Secret
			c := &upgradeTestCore{
				getSecret: func(_ context.Context, o *rmetav1.GetOptions) (*corev1.Secret, error) {
					assert.Equal(t, "sys:ssh-svc-seed", o.Name)
					reads++
					if point == "permission" {
						return nil, status.Error(codes.PermissionDenied, "seed read denied")
					}
					if point == "read-outage" && reads == 1 {
						return nil, status.Error(codes.Unavailable, "seed read outage")
					}
					if stored == nil {
						return nil, status.Error(codes.NotFound, "seed missing")
					}
					return stored, nil
				},
				createSecret: func(_ context.Context, secret *corev1.Secret) (*corev1.Secret, error) {
					creates++
					if point == "create-before" && creates == 1 {
						return nil, status.Error(codes.Unavailable, "seed write outage")
					}
					stored = proto.Clone(secret).(*corev1.Secret)
					created = proto.Clone(secret).(*corev1.Secret)
					if point == "create-after" && creates == 1 {
						return nil, status.Error(codes.Unavailable, "seed write response lost")
					}
					return secret, nil
				},
			}
			g := upgradeTestGenesis(c)
			err := retryUpgrade(t.Context(), g.createSSHServiceSeedSecret)
			if point == "permission" {
				require.True(t, grpcerr.IsPermissionDenied(err))
				assert.Zero(t, creates)
				return
			}
			require.NoError(t, err)
			before := proto.Clone(stored)
			require.NoError(t, retryUpgrade(t.Context(), g.createSSHServiceSeedSecret))
			assert.True(t, proto.Equal(before, stored))
			switch point {
			case "existing", "legacy-empty":
				assert.Zero(t, creates)
			case "create-before":
				assert.Equal(t, 2, creates)
			default:
				assert.Equal(t, 1, creates)
			}
			if created != nil {
				assert.True(t, proto.Equal(created, stored))
				assert.Len(t, stored.Data.GetValueBytes(), 32)
			}
		})
	}
}

func TestUpgradeVersionPublicationRetries(t *testing.T) {
	for _, point := range []string{"success", "nil-status", "conflict", "before-write", "after-write", "read-outage", "permission", "continuous-conflict", "deleted"} {
		t.Run(point, func(t *testing.T) {
			t.Setenv("OCTELIUM_INSTALL_ID", "legacy-install-id")
			stored := &corev1.Region{
				Metadata: &metav1.Metadata{Name: "default", Uid: "region-uid", ResourceVersion: "1", Labels: map[string]string{"user": "preserved"}},
				Spec:     &corev1.Region_Spec{},
				Status:   &corev1.Region_Status{Version: "previous", VersionInfoMap: map[string]*corev1.Region_Status_VersionInfo{"octeliumee": {Version: "ee-previous"}, "cordium": {Version: "cordium-previous"}}},
			}
			if point == "nil-status" {
				stored.Status = nil
			}
			reads, writes := 0, 0
			c := &upgradeTestCore{
				getRegion: func(_ context.Context, o *rmetav1.GetOptions) (*corev1.Region, error) {
					reads++
					assert.Equal(t, &rmetav1.GetOptions{Uid: "region-uid"}, o)
					if point == "deleted" {
						return nil, status.Error(codes.NotFound, "region removed")
					}
					if point == "read-outage" && reads == 1 {
						return nil, status.Error(codes.Unavailable, "region read outage")
					}
					return stored, nil
				},
				updateRegion: func(_ context.Context, current *corev1.Region) (*corev1.Region, error) {
					writes++
					if point == "permission" {
						return nil, status.Error(codes.PermissionDenied, "version write denied")
					}
					if point == "continuous-conflict" || (point == "conflict" && writes == 1) {
						stored = proto.Clone(stored).(*corev1.Region)
						stored.Metadata.ResourceVersion = "concurrent"
						stored.Status.VersionInfoMap["octeliumee"] = &corev1.Region_Status_VersionInfo{Version: "ee-concurrent"}
						return nil, status.Error(codes.OutOfRange, "Region changed")
					}
					if point == "before-write" && writes == 1 {
						return nil, status.Error(codes.Unavailable, "version write outage")
					}
					assert.Equal(t, "preserved", current.Metadata.Labels["user"])
					assert.Equal(t, ldflags.GetVersion(), current.Status.Version)
					info := current.Status.VersionInfoMap["octelium"]
					assert.Equal(t, "octelium", info.Package)
					assert.Equal(t, "legacy-install-id", info.Id)
					assert.NotNil(t, info.SetAt)
					assert.Equal(t, "octelium-region-uid", current.Status.PublicHostname)
					if point == "conflict" {
						assert.Equal(t, "concurrent", current.Metadata.ResourceVersion)
						assert.Equal(t, "ee-concurrent", current.Status.VersionInfoMap["octeliumee"].Version)
					}
					if point != "nil-status" {
						assert.Equal(t, "cordium-previous", current.Status.VersionInfoMap["cordium"].Version)
					}
					stored = proto.Clone(current).(*corev1.Region)
					if point == "after-write" && writes == 1 {
						return nil, status.Error(codes.Unavailable, "version response lost")
					}
					return current, nil
				},
			}
			err := upgradeTestGenesis(c).finishUpgrade(t.Context(), "region-uid")
			switch point {
			case "permission":
				require.True(t, grpcerr.IsPermissionDenied(err))
				assert.Equal(t, "previous", stored.Status.Version)
			case "continuous-conflict":
				require.True(t, grpcerr.IsResourceChanged(err))
				assert.Equal(t, 5, writes)
				assert.Equal(t, "previous", stored.Status.Version)
			case "deleted":
				require.True(t, grpcerr.IsNotFound(err))
				assert.Zero(t, writes)
			default:
				require.NoError(t, err)
			}
			if point == "after-write" {
				assert.Equal(t, 1, writes)
				assert.Equal(t, 2, reads)
			}
		})
	}
}

func TestUpgradeRetryPolicy(t *testing.T) {
	for _, code := range []codes.Code{codes.Unavailable, codes.ResourceExhausted, codes.Aborted, codes.OutOfRange, codes.DeadlineExceeded, codes.PermissionDenied, codes.Unauthenticated, codes.InvalidArgument, codes.Internal, codes.Unimplemented, codes.NotFound, codes.Canceled, codes.Unknown} {
		t.Run(code.String(), func(t *testing.T) {
			calls := 0
			err := retryUpgrade(t.Context(), func(ctx context.Context) error {
				calls++
				deadline, ok := ctx.Deadline()
				assert.True(t, ok)
				assert.LessOrEqual(t, time.Until(deadline), 30*time.Second)
				return status.Error(code, "injected error")
			})
			require.Equal(t, code, status.Code(err))
			switch code {
			case codes.Unavailable, codes.ResourceExhausted, codes.Aborted, codes.OutOfRange, codes.DeadlineExceeded:
				assert.Equal(t, 5, calls)
			default:
				assert.Equal(t, 1, calls)
			}
		})
	}
	for _, point := range []string{"before", "during-call", "between-attempts", "deadline"} {
		t.Run(point, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if point == "before" {
				cancel()
			}
			if point == "deadline" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer deadlineCancel()
			}
			calls := 0
			err := retryUpgrade(ctx, func(ctx context.Context) error {
				calls++
				if point == "during-call" || point == "deadline" {
					if point == "during-call" {
						cancel()
					}
					<-ctx.Done()
					return ctx.Err()
				}
				cancel()
				return status.Error(codes.OutOfRange, "resource changed")
			})
			if point == "deadline" {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			} else {
				require.ErrorIs(t, err, context.Canceled)
			}
			if point == "before" {
				assert.Zero(t, calls)
			} else {
				assert.Equal(t, 1, calls)
			}
		})
	}
}

func TestRequiredUpgradeRecoveryE2E(t *testing.T) {
	for _, tc := range []struct {
		name, point string
		code        codes.Code
		once        bool
		missingSeed bool
	}{
		{name: "service-list-denied", point: "service-list", code: codes.PermissionDenied},
		{name: "service-write-denied", point: "service", code: codes.PermissionDenied},
		{name: "service-outage", point: "service", code: codes.Unavailable},
		{name: "service-conflicts", point: "service", code: codes.OutOfRange},
		{name: "seed-read-denied", point: "seed-read", code: codes.PermissionDenied},
		{name: "seed-create-denied", point: "seed-create", code: codes.PermissionDenied, missingSeed: true},
		{name: "authenticator-list-denied", point: "authenticator-list", code: codes.PermissionDenied},
		{name: "authenticator-read-denied", point: "authenticator-read", code: codes.PermissionDenied},
		{name: "authenticator-write-denied", point: "authenticator", code: codes.PermissionDenied},
		{name: "authenticator-conflicts", point: "authenticator", code: codes.OutOfRange},
		{name: "version-write-denied", point: "version", code: codes.PermissionDenied},
		{name: "seed-read-recovers", point: "seed-read", code: codes.Unavailable, once: true},
		{name: "service-response-lost", point: "service-after", code: codes.Unavailable, once: true},
		{name: "seed-response-lost", point: "seed-create-after", code: codes.Unavailable, once: true, missingSeed: true},
		{name: "authenticator-response-lost", point: "authenticator-after", code: codes.Unavailable, once: true},
		{name: "version-response-lost", point: "version-after", code: codes.Unavailable, once: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInitializationFixture(t)
			var upgrading, failing atomic.Bool
			var failures, publications, markerCommits atomic.Int32
			inject := func(point string) error {
				if !upgrading.Load() || !failing.Load() || tc.point != point {
					return nil
				}
				if failures.Add(1) > 1 && tc.once {
					return nil
				}
				return status.Error(tc.code, "injected "+point+" failure")
			}
			server, err := rscserver.NewServer(t.Context(), &rscserver.Opts{
				PostGet: func(_ context.Context, object umetav1.ResourceObjectI, _, _, kind string) error {
					if kind == ucorev1.KindSecret && object.GetMetadata().Name == "sys:ssh-svc-seed" {
						return inject("seed-read")
					}
					if kind == ucorev1.KindAuthenticator && object.GetMetadata().Name == "legacy-authenticator" {
						return inject("authenticator-read")
					}
					return nil
				},
				PreCreate: func(_ context.Context, object umetav1.ResourceObjectI, _, _, kind string) error {
					if kind == ucorev1.KindSecret && object.GetMetadata().Name == "sys:ssh-svc-seed" {
						return inject("seed-create")
					}
					return nil
				},
				PostCreate: func(_ context.Context, object umetav1.ResourceObjectI, _, _, kind string) error {
					if kind == ucorev1.KindSecret && object.GetMetadata().Name == "sys:ssh-svc-seed" {
						return inject("seed-create-after")
					}
					return nil
				},
				PostList: func(_ context.Context, _ *rscserver.ObjectList, _, _, kind string) error {
					switch kind {
					case ucorev1.KindService:
						return inject("service-list")
					case ucorev1.KindAuthenticator:
						return inject("authenticator-list")
					}
					return nil
				},
				PreUpdate: func(ctx context.Context, object, old umetav1.ResourceObjectI, _, _, kind string) error {
					if !upgrading.Load() {
						return nil
					}
					switch kind {
					case ucorev1.KindService:
						if object.GetMetadata().SystemLabels[vutils.UpgradeIDKey] != old.GetMetadata().SystemLabels[vutils.UpgradeIDKey] {
							return inject("service")
						}
					case ucorev1.KindAuthenticator:
						return inject("authenticator")
					case ucorev1.KindRegion:
						if object.(*corev1.Region).Status.Version == ldflags.GetVersion() {
							publications.Add(1)
							var authenticator corev1.Authenticator
							if err := getInitializationResource(ctx, f.db, ucorev1.KindAuthenticator, "legacy-authenticator", &authenticator); err != nil {
								return err
							}
							if authenticator.Spec.State != corev1.Authenticator_Spec_ACTIVE {
								return status.Error(codes.FailedPrecondition, "version published before authenticator migration")
							}
							var seed corev1.Secret
							if err := getInitializationResource(ctx, f.db, ucorev1.KindSecret, "sys:ssh-svc-seed", &seed); err != nil {
								return err
							}
							return inject("version")
						}
					}
					return nil
				},
				PostUpdate: func(_ context.Context, object, old umetav1.ResourceObjectI, _, _, kind string) error {
					if !upgrading.Load() {
						return nil
					}
					switch kind {
					case ucorev1.KindService:
						if object.GetMetadata().SystemLabels[vutils.UpgradeIDKey] != old.GetMetadata().SystemLabels[vutils.UpgradeIDKey] {
							markerCommits.Add(1)
							return inject("service-after")
						}
					case ucorev1.KindAuthenticator:
						return inject("authenticator-after")
					case ucorev1.KindRegion:
						return inject("version-after")
					}
					return nil
				},
			})
			require.NoError(t, err)
			f.genesis.rscServer = server
			require.NoError(t, server.Run(t.Context()))
			require.NoError(t, f.genesis.RunInit(t.Context(), nil))
			client := f.genesis.octeliumC.CoreC()
			seed, err := client.GetSecret(t.Context(), &rmetav1.GetOptions{Name: "sys:ssh-svc-seed"})
			require.NoError(t, err)
			if tc.missingSeed {
				_, err = client.DeleteSecret(t.Context(), &rmetav1.DeleteOptions{Uid: seed.Metadata.Uid})
				require.NoError(t, err)
			}
			keys := initializationSecrets(t, f.db)
			var authenticators []*corev1.Authenticator
			for index, state := range []corev1.Authenticator_Spec_State{corev1.Authenticator_Spec_STATE_UNKNOWN, corev1.Authenticator_Spec_PENDING, corev1.Authenticator_Spec_REJECTED, corev1.Authenticator_Spec_ACTIVE} {
				name := fmt.Sprintf("authenticator-%d", index)
				if index == 0 {
					name = "legacy-authenticator"
				}
				authenticator, err := client.CreateAuthenticator(t.Context(), &corev1.Authenticator{
					Metadata: &metav1.Metadata{Name: name, Labels: map[string]string{"customer": "preserved"}},
					Spec:     &corev1.Authenticator_Spec{State: state, DisplayName: "Customer authenticator"},
					Status:   &corev1.Authenticator_Status{Description: "Preserved legacy status", SuccessfulAuthentications: 7, IsRegistered: true},
				})
				require.NoError(t, err)
				authenticators = append(authenticators, authenticator)
			}
			region, err := client.GetRegion(t.Context(), &rmetav1.GetOptions{Name: "default"})
			require.NoError(t, err)
			region.Status.Version = "previous-version"
			region.Status.VersionInfoMap = map[string]*corev1.Region_Status_VersionInfo{
				"octelium":   {Version: "previous-version", Id: "previous-operation"},
				"octeliumee": {Version: "preserved-ee"}, "cordium": {Version: "preserved-cordium"},
			}
			region, err = client.UpdateRegion(t.Context(), region)
			require.NoError(t, err)
			pod := upgradeTestPod("legacy-upgrade-job-uid")
			pod.Labels = map[string]string{"octelium.com/component": "genesis"}
			pod.Status.Phase = corek8s.PodRunning
			owner := k8smetav1.GetControllerOf(pod)
			_, err = f.client.K8sC.BatchV1().Jobs(pod.Namespace).Create(t.Context(), &batchv1.Job{
				ObjectMeta: k8smetav1.ObjectMeta{Name: owner.Name, Namespace: pod.Namespace, UID: owner.UID, Labels: pod.Labels},
				Status:     batchv1.JobStatus{Active: 1},
			}, k8smetav1.CreateOptions{})
			require.NoError(t, err)
			pod, err = f.client.K8sC.CoreV1().Pods(pod.Namespace).Create(t.Context(), pod, k8smetav1.CreateOptions{})
			require.NoError(t, err)
			f.genesis.pod = pod
			upgrading.Store(true)
			failing.Store(true)
			err = f.genesis.RunUpgrade(t.Context(), nil)
			require.Positive(t, failures.Load())
			if tc.once {
				require.NoError(t, err)
			} else {
				require.Equal(t, tc.code, status.Code(err))
				current, err := client.GetRegion(t.Context(), &rmetav1.GetOptions{Uid: region.Metadata.Uid})
				require.NoError(t, err)
				assert.Equal(t, region.Status.Version, current.Status.Version)
				assert.True(t, proto.Equal(region.Status.VersionInfoMap["octelium"], current.Status.VersionInfoMap["octelium"]))
				if tc.point != "version" {
					assert.Zero(t, publications.Load())
				}
			}
			failing.Store(false)
			restarted := &Genesis{k8sC: f.client.K8sC, nadC: f.client.NadC, pod: pod}
			require.NoError(t, restarted.RunUpgrade(t.Context(), nil))
			commits := markerCommits.Load()
			require.NoError(t, restarted.RunUpgrade(t.Context(), nil))
			assert.Equal(t, commits, markerCommits.Load())
			services, err := restarted.getAllServices(t.Context(), region)
			require.NoError(t, err)
			require.NotEmpty(t, services)
			for _, svc := range services {
				assert.Equal(t, string(owner.UID), svc.Metadata.SystemLabels[vutils.UpgradeIDKey], svc.Metadata.Name)
			}
			assert.Equal(t, int32(len(services)), markerCommits.Load())
			for index, before := range authenticators {
				current, err := client.GetAuthenticator(t.Context(), &rmetav1.GetOptions{Uid: before.Metadata.Uid})
				require.NoError(t, err)
				state := before.Spec.State
				if index == 0 {
					state = corev1.Authenticator_Spec_ACTIVE
				}
				assert.Equal(t, state, current.Spec.State)
				assert.Equal(t, before.Spec.DisplayName, current.Spec.DisplayName)
				assert.True(t, proto.Equal(before.Status, current.Status))
				assertResourceMetadataPreserved(t, before.Metadata, current.Metadata)
			}
			current, err := client.GetRegion(t.Context(), &rmetav1.GetOptions{Uid: region.Metadata.Uid})
			require.NoError(t, err)
			assert.Equal(t, ldflags.GetVersion(), current.Status.Version)
			assert.Equal(t, "preserved-ee", current.Status.VersionInfoMap["octeliumee"].Version)
			assert.Equal(t, "preserved-cordium", current.Status.VersionInfoMap["cordium"].Version)
			for name, value := range keys {
				assert.Equal(t, value, initializationSecrets(t, f.db)[name], name)
			}
			currentSeed, err := client.GetSecret(t.Context(), &rmetav1.GetOptions{Name: "sys:ssh-svc-seed"})
			require.NoError(t, err)
			if tc.missingSeed {
				assert.Len(t, currentSeed.Data.GetValueBytes(), 32)
			} else {
				assert.True(t, proto.Equal(seed, currentSeed))
			}
			f.checkPreserved(t)
		})
	}
}
