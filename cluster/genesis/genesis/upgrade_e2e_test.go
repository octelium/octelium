package genesis

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	batchv1 "k8s.io/api/batch/v1"
	corek8s "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
