/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package genesis

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type resourceTestClient struct {
	octeliumc.ClientInterface
	core *resourceTestCore
}

func (c *resourceTestClient) CoreC() rcorev1.ResourceServiceClient { return c.core }

type resourceTestCore struct {
	rcorev1.ResourceServiceClient
	getService      func(*rmetav1.GetOptions) (*corev1.Service, error)
	updateService   func(*corev1.Service) (*corev1.Service, error)
	getNamespace    func(*rmetav1.GetOptions) (*corev1.Namespace, error)
	createNamespace func(*corev1.Namespace) (*corev1.Namespace, error)
	getPolicy       func(*rmetav1.GetOptions) (*corev1.Policy, error)
	createPolicy    func(*corev1.Policy) (*corev1.Policy, error)
}

func (c *resourceTestCore) GetService(_ context.Context, o *rmetav1.GetOptions, _ ...grpc.CallOption) (*corev1.Service, error) {
	return c.getService(o)
}

func (c *resourceTestCore) UpdateService(_ context.Context, o *corev1.Service, _ ...grpc.CallOption) (*corev1.Service, error) {
	return c.updateService(o)
}

func (c *resourceTestCore) GetNamespace(_ context.Context, o *rmetav1.GetOptions, _ ...grpc.CallOption) (*corev1.Namespace, error) {
	return c.getNamespace(o)
}

func (c *resourceTestCore) CreateNamespace(_ context.Context, o *corev1.Namespace, _ ...grpc.CallOption) (*corev1.Namespace, error) {
	return c.createNamespace(o)
}

func (c *resourceTestCore) GetPolicy(_ context.Context, o *rmetav1.GetOptions, _ ...grpc.CallOption) (*corev1.Policy, error) {
	return c.getPolicy(o)
}

func (c *resourceTestCore) CreatePolicy(_ context.Context, o *corev1.Policy, _ ...grpc.CallOption) (*corev1.Policy, error) {
	return c.createPolicy(o)
}

func resourceTestGenesis(c *resourceTestCore) *Genesis {
	return &Genesis{octeliumC: &resourceTestClient{core: c}}
}

func TestEnsureServicePreservesMutableResources(t *testing.T) {
	for _, system := range []bool{false, true} {
		existing := &corev1.Service{
			Metadata: &metav1.Metadata{Name: "demo-nginx.default", Uid: "user-service", IsSystem: system, Description: "custom", Labels: map[string]string{"user": "kept"}},
			Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_TCP, Port: 9000},
			Status:   &corev1.Service_Status{NamespaceRef: &metav1.ObjectReference{Uid: "namespace"}},
		}
		desired := &corev1.Service{Metadata: &metav1.Metadata{Name: existing.Metadata.Name}, Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_WEB}}
		before, input := proto.Clone(existing), proto.Clone(desired)
		c := &resourceTestCore{getService: func(*rmetav1.GetOptions) (*corev1.Service, error) { return existing, nil }}
		require.NoError(t, resourceTestGenesis(c).ensureService(t.Context(), desired))
		assert.True(t, proto.Equal(before, existing))
		assert.True(t, proto.Equal(input, desired))
	}
}

func TestEnsureSystemServicePreservesMetadataAndStatus(t *testing.T) {
	existing := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "dns.octelium", Uid: "legacy-service", ResourceVersion: "version-1", IsSystem: true,
			DisplayName: "Custom DNS", Description: "Custom description", Tags: []string{"custom"}, PicURL: "custom-picture",
			Labels: map[string]string{"owner": "user"}, Annotations: map[string]string{"note": "kept"},
			SpecLabels: map[string]string{"controller": "kept"}, SystemLabels: map[string]string{"runtime": "kept", "owned": "old"},
		},
		Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Port: 8080},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Uid: "namespace"}, RegionRef: &metav1.ObjectReference{Uid: "region"},
			PrimaryHostname: "existing-host", Port: 1234, ManagedService: &corev1.Service_Status_ManagedService{Image: "old-image"},
		},
	}
	desired := &corev1.Service{
		Metadata: &metav1.Metadata{Name: existing.Metadata.Name, IsSystem: true, IsUserHidden: true, DisplayName: "DNS", Description: "Default description", SystemLabels: map[string]string{"owned": "new"}},
		Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_DNS, Port: 53},
		Status:   &corev1.Service_Status{ManagedService: &corev1.Service_Status_ManagedService{Image: "new-image", Type: "dnsserver"}},
	}
	before, input := proto.Clone(existing), proto.Clone(desired)
	var updated *corev1.Service
	c := &resourceTestCore{
		getService: func(*rmetav1.GetOptions) (*corev1.Service, error) { return existing, nil },
		updateService: func(svc *corev1.Service) (*corev1.Service, error) {
			updated = svc
			return svc, nil
		},
	}
	require.NoError(t, resourceTestGenesis(c).ensureService(t.Context(), desired))
	require.NotNil(t, updated)
	assert.Equal(t, existing.Metadata.Uid, updated.Metadata.Uid)
	assert.Equal(t, existing.Metadata.ResourceVersion, updated.Metadata.ResourceVersion)
	assert.Equal(t, existing.Metadata.DisplayName, updated.Metadata.DisplayName)
	assert.Equal(t, existing.Metadata.Description, updated.Metadata.Description)
	assert.Equal(t, existing.Metadata.Labels, updated.Metadata.Labels)
	assert.Equal(t, existing.Metadata.Annotations, updated.Metadata.Annotations)
	assert.Equal(t, existing.Metadata.SpecLabels, updated.Metadata.SpecLabels)
	assert.Equal(t, existing.Metadata.Tags, updated.Metadata.Tags)
	assert.Equal(t, existing.Metadata.PicURL, updated.Metadata.PicURL)
	assert.Equal(t, map[string]string{"runtime": "kept", "owned": "new"}, updated.Metadata.SystemLabels)
	assert.True(t, updated.Metadata.IsUserHidden)
	assert.True(t, proto.Equal(desired.Spec, updated.Spec))
	assert.True(t, proto.Equal(desired.Status.ManagedService, updated.Status.ManagedService))
	assert.True(t, proto.Equal(existing.Status.NamespaceRef, updated.Status.NamespaceRef))
	assert.True(t, proto.Equal(existing.Status.RegionRef, updated.Status.RegionRef))
	assert.Equal(t, existing.Status.PrimaryHostname, updated.Status.PrimaryHostname)
	assert.Equal(t, existing.Status.Port, updated.Status.Port)
	assert.True(t, proto.Equal(before, existing))
	assert.True(t, proto.Equal(input, desired))
}

func TestEnsureSystemServiceOwnership(t *testing.T) {
	for _, system := range []bool{false, true} {
		existing := &corev1.Service{Metadata: &metav1.Metadata{Name: "portal.default", IsSystem: system}}
		desired := &corev1.Service{Metadata: &metav1.Metadata{Name: existing.Metadata.Name, IsSystem: true, Description: "Portal"}, Status: &corev1.Service_Status{ManagedService: &corev1.Service_Status_ManagedService{Image: "new-image"}}}
		updates := 0
		c := &resourceTestCore{
			getService: func(*rmetav1.GetOptions) (*corev1.Service, error) { return existing, nil },
			updateService: func(svc *corev1.Service) (*corev1.Service, error) {
				updates++
				assert.Equal(t, "Portal", svc.Metadata.Description)
				assert.Equal(t, "new-image", svc.Status.ManagedService.Image)
				return svc, nil
			},
		}
		err := resourceTestGenesis(c).ensureService(t.Context(), desired)
		if system {
			require.NoError(t, err)
			assert.Equal(t, 1, updates)
		} else {
			require.ErrorContains(t, err, "Refusing to replace")
			assert.Zero(t, updates)
		}
	}
}

func TestEnsureSystemServiceConflict(t *testing.T) {
	for _, state := range []string{"concurrent-edit", "ownership-changed", "cancelled", "continuous-conflict"} {
		t.Run(state, func(t *testing.T) {
			existing := &corev1.Service{Metadata: &metav1.Metadata{Name: "portal.default", ResourceVersion: "1", IsSystem: true}, Spec: &corev1.Service_Spec{}, Status: &corev1.Service_Status{}}
			desired := proto.Clone(existing).(*corev1.Service)
			desired.Status.ManagedService = &corev1.Service_Status_ManagedService{Image: "new-image"}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			updates := 0
			c := &resourceTestCore{
				getService: func(*rmetav1.GetOptions) (*corev1.Service, error) { return existing, nil },
				updateService: func(svc *corev1.Service) (*corev1.Service, error) {
					updates++
					if updates == 1 || state == "continuous-conflict" {
						existing = proto.Clone(existing).(*corev1.Service)
						existing.Metadata.ResourceVersion = "2"
						existing.Metadata.Labels = map[string]string{"concurrent": "preserved"}
						if state == "ownership-changed" {
							existing.Metadata.IsSystem = false
						}
						if state == "cancelled" {
							cancel()
						}
						return nil, status.Error(codes.OutOfRange, "resource changed")
					}
					assert.Equal(t, "2", svc.Metadata.ResourceVersion)
					assert.Equal(t, "preserved", svc.Metadata.Labels["concurrent"])
					return svc, nil
				},
			}
			err := resourceTestGenesis(c).ensureService(ctx, desired)
			switch state {
			case "concurrent-edit":
				require.NoError(t, err)
				assert.Equal(t, 2, updates)
			case "ownership-changed":
				require.ErrorContains(t, err, "Refusing to replace")
				assert.Equal(t, 1, updates)
			case "cancelled":
				require.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, 1, updates)
			case "continuous-conflict":
				assert.Equal(t, codes.OutOfRange, status.Code(err))
				assert.LessOrEqual(t, updates, 6)
			}
		})
	}
}

func TestEnsureServiceReadAndWriteFailures(t *testing.T) {
	for _, state := range []string{"read-failed", "response-lost"} {
		t.Run(state, func(t *testing.T) {
			existing := &corev1.Service{Metadata: &metav1.Metadata{Name: "portal.default", IsSystem: true}, Spec: &corev1.Service_Spec{}, Status: &corev1.Service_Status{}}
			desired := proto.Clone(existing).(*corev1.Service)
			desired.Status.ManagedService = &corev1.Service_Status_ManagedService{Image: "new-image"}
			want := status.Error(codes.Unavailable, state)
			updates := 0
			c := &resourceTestCore{
				getService: func(*rmetav1.GetOptions) (*corev1.Service, error) {
					if state == "read-failed" {
						return nil, want
					}
					return existing, nil
				},
				updateService: func(svc *corev1.Service) (*corev1.Service, error) {
					updates++
					existing = proto.Clone(svc).(*corev1.Service)
					return nil, want
				},
			}
			g := resourceTestGenesis(c)
			require.ErrorIs(t, g.ensureService(t.Context(), desired), want)
			if state == "response-lost" {
				require.NoError(t, g.ensureService(t.Context(), desired))
				assert.Equal(t, 1, updates)
			} else {
				assert.Zero(t, updates)
			}
		})
	}
}

func TestEnsureNamespacePreservesExistingResources(t *testing.T) {
	for _, system := range []bool{false, true} {
		existing := &corev1.Namespace{Metadata: &metav1.Metadata{Name: "default", Uid: "original", IsSystem: system, Description: "Custom", Labels: map[string]string{"user": "kept"}}, Spec: &corev1.Namespace_Spec{}, Status: &corev1.Namespace_Status{}}
		before := proto.Clone(existing)
		c := &resourceTestCore{getNamespace: func(*rmetav1.GetOptions) (*corev1.Namespace, error) { return existing, nil }}
		require.NoError(t, resourceTestGenesis(c).ensureNamespace(t.Context(), &corev1.Namespace{Metadata: &metav1.Metadata{Name: "default", IsSystem: true}}))
		assert.True(t, proto.Equal(before, existing))
	}
}

func TestBuiltinPolicyDefaultsAreCreateOnly(t *testing.T) {
	existing := &corev1.Policy{Metadata: &metav1.Metadata{Name: "allow-all", Description: "Custom restrictive policy"}, Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{Effect: corev1.Policy_Spec_Rule_DENY}}}}
	before := proto.Clone(existing)
	created := 0
	c := &resourceTestCore{
		getPolicy: func(o *rmetav1.GetOptions) (*corev1.Policy, error) {
			if o.Name == existing.Metadata.Name {
				return existing, nil
			}
			return nil, status.Error(codes.NotFound, "missing")
		},
		createPolicy: func(pol *corev1.Policy) (*corev1.Policy, error) {
			created++
			return pol, nil
		},
	}
	require.NoError(t, resourceTestGenesis(c).installBuiltinPolicies(t.Context()))
	assert.Equal(t, 4, created)
	assert.True(t, proto.Equal(before, existing))
	want := status.Error(codes.Unavailable, "temporary policy read failure")
	c.getPolicy = func(*rmetav1.GetOptions) (*corev1.Policy, error) { return nil, want }
	require.ErrorIs(t, resourceTestGenesis(c).installBuiltinPolicies(t.Context()), want)
	assert.Equal(t, 4, created)
}

func TestEnsureNamespaceCreationRace(t *testing.T) {
	for _, raced := range []bool{false, true} {
		desired := &corev1.Namespace{Metadata: &metav1.Metadata{Name: "default", IsSystem: true}}
		before := proto.Clone(desired)
		gets, creates := 0, 0
		c := &resourceTestCore{
			getNamespace: func(*rmetav1.GetOptions) (*corev1.Namespace, error) {
				gets++
				if gets == 1 {
					return nil, status.Error(codes.NotFound, "missing")
				}
				return &corev1.Namespace{Metadata: &metav1.Metadata{Name: "default", Description: "Concurrent user namespace"}}, nil
			},
			createNamespace: func(ns *corev1.Namespace) (*corev1.Namespace, error) {
				creates++
				require.NotNil(t, ns.Spec)
				require.NotNil(t, ns.Status)
				if raced {
					return nil, status.Error(codes.AlreadyExists, "created concurrently")
				}
				ns.Metadata.Uid = "assigned-by-server"
				return ns, nil
			},
		}
		require.NoError(t, resourceTestGenesis(c).ensureNamespace(t.Context(), desired))
		assert.Equal(t, 1, creates)
		assert.True(t, proto.Equal(before, desired))
		if raced {
			assert.Equal(t, 2, gets)
		}
	}
}

func TestEnsureServiceCreationRace(t *testing.T) {
	for _, system := range []bool{false, true} {
		existing := &corev1.Service{Metadata: &metav1.Metadata{Name: "portal.default", Description: "Concurrent user service"}, Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_TCP}}
		before := proto.Clone(existing)
		gets := 0
		c := &resourceTestCore{
			getNamespace: func(*rmetav1.GetOptions) (*corev1.Namespace, error) {
				return &corev1.Namespace{Metadata: &metav1.Metadata{Name: "default", Uid: "namespace"}}, nil
			},
			getService: func(*rmetav1.GetOptions) (*corev1.Service, error) {
				gets++
				if gets == 1 {
					return nil, status.Error(codes.NotFound, "missing")
				}
				return existing, nil
			},
		}
		err := resourceTestGenesis(c).ensureService(t.Context(), &corev1.Service{Metadata: &metav1.Metadata{Name: existing.Metadata.Name, IsSystem: system}})
		if system {
			require.ErrorContains(t, err, "Refusing to replace")
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, 3, gets)
		assert.True(t, proto.Equal(before, existing))
	}
}

func TestBuiltinPolicyCreationRace(t *testing.T) {
	gets := 0
	created := 0
	c := &resourceTestCore{
		getPolicy: func(o *rmetav1.GetOptions) (*corev1.Policy, error) {
			gets++
			if gets == 1 {
				return nil, status.Error(codes.NotFound, "missing")
			}
			return &corev1.Policy{Metadata: &metav1.Metadata{Name: o.Name, Description: "Concurrent policy"}}, nil
		},
		createPolicy: func(*corev1.Policy) (*corev1.Policy, error) {
			created++
			return nil, status.Error(codes.AlreadyExists, "created concurrently")
		},
	}
	require.NoError(t, resourceTestGenesis(c).installBuiltinPolicies(t.Context()))
	assert.Equal(t, 1, created)
	assert.Equal(t, 6, gets)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, resourceTestGenesis(c).installBuiltinPolicies(ctx), context.Canceled)
	assert.Equal(t, 6, gets)
}
