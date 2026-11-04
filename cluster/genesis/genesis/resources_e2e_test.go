package genesis

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/genesisutils"
	"github.com/octelium/octelium/cluster/rscserver/rscserver"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func assertResourceMetadataPreserved(t *testing.T, before, after *metav1.Metadata) {
	t.Helper()
	assert.Equal(t, before.Name, after.Name)
	assert.Equal(t, before.Uid, after.Uid)
	assert.Equal(t, before.CreatedAt, after.CreatedAt)
	assert.Equal(t, before.DisplayName, after.DisplayName)
	assert.Equal(t, before.Description, after.Description)
	assert.Equal(t, before.Labels, after.Labels)
	assert.Equal(t, before.Annotations, after.Annotations)
	assert.Equal(t, before.Tags, after.Tags)
	assert.Equal(t, before.PicURL, after.PicURL)
	assert.Equal(t, before.IsSystem, after.IsSystem)
}

func TestUpgradePreservesMutableResourcesE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	c := f.genesis.octeliumC.CoreC()
	var services []*corev1.Service
	for _, name := range []string{"demo-nginx.default", "essh.octelium", "socks5.octelium"} {
		svc, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: name})
		require.NoError(t, err)
		svc.Metadata.DisplayName = "Customer service"
		svc.Metadata.Description = "Customer description"
		svc.Metadata.Labels = map[string]string{"owner": "customer"}
		svc.Metadata.Annotations = map[string]string{"note": "preserve"}
		svc.Metadata.Tags = []string{"custom"}
		svc.Metadata.PicURL = "customer-picture"
		svc.Spec.IsPublic = false
		svc.Spec.Port = 9099
		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{InlinePolicies: []*corev1.InlinePolicy{{
			Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{Effect: corev1.Policy_Spec_Rule_DENY, Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}}}},
		}}}
		if container := svc.Spec.GetConfig().GetUpstream().GetContainer(); container != nil {
			container.Image = "customer.example/nginx:pinned"
		}
		svc, err = c.UpdateService(t.Context(), svc)
		require.NoError(t, err)
		services = append(services, svc)
	}
	policies, err := f.genesis.getBuiltinPolicies(t.Context())
	require.NoError(t, err)
	var savedPolicies []*corev1.Policy
	for _, desired := range policies.Items {
		pol, err := c.GetPolicy(t.Context(), &rmetav1.GetOptions{Name: desired.Metadata.Name})
		require.NoError(t, err)
		pol.Metadata.Description = "Customer policy"
		pol.Metadata.Annotations = map[string]string{"owner": "customer"}
		pol.Spec = &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{Effect: corev1.Policy_Spec_Rule_DENY, Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}}}}
		pol, err = c.UpdatePolicy(t.Context(), pol)
		require.NoError(t, err)
		savedPolicies = append(savedPolicies, pol)
	}
	ns, err := c.GetNamespace(t.Context(), &rmetav1.GetOptions{Name: "default"})
	require.NoError(t, err)
	ns.Metadata.IsSystem = false
	ns.Metadata.Description = "Legacy namespace description"
	ns.Metadata.Labels = map[string]string{"owner": "customer"}
	ns.Spec.Attrs, err = structpb.NewStruct(map[string]any{"custom": "preserved"})
	require.NoError(t, err)
	ns.Spec.Authorization = &corev1.Namespace_Spec_Authorization{Policies: []string{"deny-all"}}
	ns, err = c.UpdateNamespace(t.Context(), ns)
	require.NoError(t, err)
	cc, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
	require.NoError(t, err)
	region, err := c.GetRegion(t.Context(), &rmetav1.GetOptions{Name: "default"})
	require.NoError(t, err)
	require.NoError(t, f.genesis.installOcteliumResources(t.Context(), cc, region, true))
	require.NoError(t, f.genesis.installBuiltinPolicies(t.Context()))
	for range 2 {
		require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
		for _, before := range services {
			after, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: before.Metadata.Name})
			require.NoError(t, err)
			assertResourceMetadataPreserved(t, before.Metadata, after.Metadata)
			assert.True(t, proto.Equal(before.Spec, after.Spec), before.Metadata.Name)
			assert.True(t, proto.Equal(before.Status, after.Status), before.Metadata.Name)
		}
		for _, before := range savedPolicies {
			after, err := c.GetPolicy(t.Context(), &rmetav1.GetOptions{Name: before.Metadata.Name})
			require.NoError(t, err)
			assert.True(t, proto.Equal(before, after), before.Metadata.Name)
		}
		after, err := c.GetNamespace(t.Context(), &rmetav1.GetOptions{Name: ns.Metadata.Name})
		require.NoError(t, err)
		assert.True(t, proto.Equal(ns, after))
	}
	f.checkPreserved(t)
}

func TestUpgradeDoesNotReinstallDefaultsE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	c := f.genesis.octeliumC.CoreC()
	names := []string{"demo-nginx.default", "essh.octelium", "socks5.octelium"}
	for _, name := range names {
		svc, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: name})
		require.NoError(t, err)
		_, err = c.DeleteService(t.Context(), &rmetav1.DeleteOptions{Uid: svc.Metadata.Uid})
		require.NoError(t, err)
	}
	policies, err := f.genesis.getBuiltinPolicies(t.Context())
	require.NoError(t, err)
	for _, desired := range policies.Items {
		pol, err := c.GetPolicy(t.Context(), &rmetav1.GetOptions{Name: desired.Metadata.Name})
		require.NoError(t, err)
		_, err = c.DeletePolicy(t.Context(), &rmetav1.DeleteOptions{Uid: pol.Metadata.Uid})
		require.NoError(t, err)
	}
	portal, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: "portal.default"})
	require.NoError(t, err)
	portal.Metadata.Description = "Customer portal"
	portal.Metadata.Labels = map[string]string{"owner": "customer"}
	portal.Metadata.Annotations = map[string]string{"custom": "kept"}
	portal.Status.ManagedService.Image = "legacy-image"
	portal, err = c.UpdateService(t.Context(), portal)
	require.NoError(t, err)
	dns, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: "dns.octelium"})
	require.NoError(t, err)
	dns.Status.ManagedService = nil
	_, err = c.UpdateService(t.Context(), dns)
	require.NoError(t, err)
	for range 2 {
		require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
		for _, name := range names {
			_, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: name})
			assert.True(t, grpcerr.IsNotFound(err), name)
		}
		for _, pol := range policies.Items {
			_, err := c.GetPolicy(t.Context(), &rmetav1.GetOptions{Name: pol.Metadata.Name})
			assert.True(t, grpcerr.IsNotFound(err), pol.Metadata.Name)
		}
		current, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: portal.Metadata.Name})
		require.NoError(t, err)
		assertResourceMetadataPreserved(t, portal.Metadata, current.Metadata)
		assert.NotEqual(t, "legacy-image", current.Status.ManagedService.Image)
		assert.NotEmpty(t, current.Status.ManagedService.Image)
		for _, name := range []string{"dns.octelium", "default.octelium-api", "auth.octelium-api", "default.default"} {
			svc, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: name})
			require.NoError(t, err)
			assert.True(t, svc.Metadata.IsSystem)
			require.NotNil(t, svc.Status.ManagedService)
			assert.NotEmpty(t, svc.Status.ManagedService.Image)
		}
	}
	f.checkPreserved(t)
}

func TestUpgradeRefusesUnownedSystemServiceE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	c := f.genesis.octeliumC.CoreC()
	portal, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: "portal.default"})
	require.NoError(t, err)
	_, err = c.DeleteService(t.Context(), &rmetav1.DeleteOptions{Uid: portal.Metadata.Uid})
	require.NoError(t, err)
	require.NoError(t, genesisutils.CreateOrUpdateService(t.Context(), f.genesis.octeliumC, &corev1.Service{
		Metadata: &metav1.Metadata{Name: portal.Metadata.Name, Description: "User-owned collision"},
		Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Port: 9000, Config: &corev1.Service_Spec_Config{
			Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "https://customer.example"}},
		}},
	}))
	before, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: portal.Metadata.Name})
	require.NoError(t, err)
	assert.False(t, before.Metadata.IsSystem)
	require.ErrorContains(t, f.genesis.RunUpgrade(t.Context(), nil), "Refusing to replace")
	after, err := c.GetService(t.Context(), &rmetav1.GetOptions{Name: portal.Metadata.Name})
	require.NoError(t, err)
	assert.True(t, proto.Equal(before, after))
	f.checkPreserved(t)
}

func TestInitialResourceSeedRecoveryE2E(t *testing.T) {
	for _, point := range []struct{ kind, name string }{{"Service", "demo-nginx.default"}, {"Policy", "allow-all"}} {
		for _, committed := range []bool{false, true} {
			t.Run(point.kind+"/"+map[bool]string{false: "before-commit", true: "after-commit"}[committed], func(t *testing.T) {
				f := newInitializationFixture(t)
				failed := false
				hook := func(_ context.Context, object umetav1.ResourceObjectI, _, _, kind string) error {
					if !failed && kind == point.kind && object.GetMetadata().Name == point.name {
						failed = true
						return status.Error(codes.Unavailable, "injected initial resource failure")
					}
					return nil
				}
				opts := &rscserver.Opts{PreCreate: hook}
				if committed {
					opts = &rscserver.Opts{PostCreate: hook}
				}
				server, err := rscserver.NewServer(t.Context(), opts)
				require.NoError(t, err)
				f.genesis.rscServer = server
				require.NoError(t, server.Run(t.Context()))
				require.Error(t, f.genesis.RunInit(t.Context(), nil))
				require.True(t, failed)
				_, err = f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), "init-token", k8smetav1.GetOptions{})
				assert.True(t, k8serr.IsNotFound(err))
				var modified *corev1.Service
				if committed || point.kind == "Policy" {
					modified, err = f.genesis.octeliumC.CoreC().GetService(t.Context(), &rmetav1.GetOptions{Name: "demo-nginx.default"})
					require.NoError(t, err)
					modified.Metadata.Description = "Preserve edits during resume"
					modified.Spec.Config.Upstream.GetContainer().Image = "customer.example/nginx:pinned"
					modified, err = f.genesis.octeliumC.CoreC().UpdateService(t.Context(), modified)
					require.NoError(t, err)
				}
				keys := initializationSecrets(t, f.db)
				require.NoError(t, f.genesis.RunInit(t.Context(), nil))
				for name, key := range keys {
					assert.Equal(t, key, initializationSecrets(t, f.db)[name], name)
				}
				if modified != nil {
					current, err := f.genesis.octeliumC.CoreC().GetService(t.Context(), &rmetav1.GetOptions{Name: modified.Metadata.Name})
					require.NoError(t, err)
					assert.True(t, proto.Equal(modified, current))
				}
				policies, err := f.genesis.getBuiltinPolicies(t.Context())
				require.NoError(t, err)
				for _, desired := range policies.Items {
					_, err := f.genesis.octeliumC.CoreC().GetPolicy(t.Context(), &rmetav1.GetOptions{Name: desired.Metadata.Name})
					require.NoError(t, err)
				}
				_, err = f.genesis.getInitAuthenticationToken(t.Context())
				require.NoError(t, err)
				f.checkPreserved(t)
			})
		}
	}
}
