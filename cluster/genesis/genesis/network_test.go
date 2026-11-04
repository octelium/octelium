package genesis

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/clusterconfig"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	k8scorev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func networkValidationConfig(t *testing.T) *corev1.ClusterConfig {
	t.Helper()
	c := &corev1.ClusterConfig{Status: &corev1.ClusterConfig_Status{Network: &corev1.ClusterConfig_Status_Network{V6RangePrefix: []byte{1, 2, 3, 4}}}}
	require.NoError(t, clusterconfig.SetClusterSubnets(c))
	return c
}

func TestGenesisNetworkOverlap(t *testing.T) {
	for _, tc := range []struct {
		name   string
		object runtime.Object
	}{
		{"pod-v4", &k8scorev1.Node{Spec: k8scorev1.NodeSpec{PodCIDR: "100.64.1.0/24"}}},
		{"pod-in-routed-parent", &k8scorev1.Node{Spec: k8scorev1.NodeSpec{PodCIDR: "100.100.0.0/16"}}},
		{"pod-v6", &k8scorev1.Node{Spec: k8scorev1.NodeSpec{PodCIDRs: []string{"fdee:102:304:0:1::/80"}}}},
		{"mapped-pod-v4", &k8scorev1.Node{Spec: k8scorev1.NodeSpec{PodCIDR: "::ffff:100.64.0.0/112"}}},
		{"node-v4", &k8scorev1.Node{Status: k8scorev1.NodeStatus{Addresses: []k8scorev1.NodeAddress{{Type: k8scorev1.NodeInternalIP, Address: "100.65.1.1"}}}}},
		{"node-v6", &k8scorev1.Node{Status: k8scorev1.NodeStatus{Addresses: []k8scorev1.NodeAddress{{Type: k8scorev1.NodeExternalIP, Address: "fdee:102:304:0:2::1"}}}}},
		{"service-v4", &k8scorev1.Service{Spec: k8scorev1.ServiceSpec{ClusterIP: "100.66.0.1"}}},
		{"service-v6", &k8scorev1.Service{Spec: k8scorev1.ServiceSpec{ClusterIPs: []string{"10.96.0.1", "fdee:102:304::1"}}}},
		{"service-cidr-v4", &networkingv1.ServiceCIDR{Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"100.64.0.0/10"}}}},
		{"service-cidr-v6", &networkingv1.ServiceCIDR{Spec: networkingv1.ServiceCIDRSpec{CIDRs: []string{"fdee:102:304::/64"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewSimpleClientset(tc.object)
			g := &Genesis{k8sC: c}
			require.ErrorContains(t, g.validateClusterNetwork(t.Context(), networkValidationConfig(t), newInitializationInput(t).Bootstrap), "overlaps")
			for _, action := range c.Actions() {
				assert.Equal(t, "list", action.GetVerb())
			}
		})
	}
}

func TestGenesisNetworkStorageOverlap(t *testing.T) {
	for _, host := range []string{"100.64.0.1", "100.65.0.1", "100.66.0.1", "100.100.0.1", "::ffff:100.64.0.1", "fdee:102:304::1", "fdee:102:304:0:ff::1"} {
		for _, storage := range []string{"postgresql", "redis"} {
			t.Run(storage+"/"+host, func(t *testing.T) {
				c := fake.NewSimpleClientset()
				g := &Genesis{k8sC: c}
				bs := newInitializationInput(t).Bootstrap
				if storage == "postgresql" {
					bs.Spec.PrimaryStorage.GetPostgresql().Host = host
				} else {
					bs.Spec.SecondaryStorage.GetRedis().Host = host
				}
				require.ErrorContains(t, g.validateClusterNetwork(t.Context(), networkValidationConfig(t), bs), "storage endpoint")
				assert.Empty(t, c.Actions())
			})
		}
	}
}

func TestGenesisNetworkCompatibility(t *testing.T) {
	for _, mode := range []corev1.ClusterConfig_Status_NetworkConfig_Mode{
		corev1.ClusterConfig_Status_NetworkConfig_MODE_DEFAULT, corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK,
		corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY, corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			objects := []runtime.Object{
				&k8scorev1.Node{Spec: k8scorev1.NodeSpec{PodCIDRs: []string{"10.244.0.0/16", "fd00::/64"}}, Status: k8scorev1.NodeStatus{Addresses: []k8scorev1.NodeAddress{{Type: k8scorev1.NodeInternalIP, Address: "192.0.2.1"}, {Type: k8scorev1.NodeHostName, Address: "node.example"}}}},
				&k8scorev1.Service{ObjectMeta: k8smetav1.ObjectMeta{Name: "kubernetes"}, Spec: k8scorev1.ServiceSpec{ClusterIP: "10.96.0.1", ClusterIPs: []string{"10.96.0.1", "fd01::1"}}},
				&k8scorev1.Service{ObjectMeta: k8smetav1.ObjectMeta{Name: "headless"}, Spec: k8scorev1.ServiceSpec{ClusterIP: k8scorev1.ClusterIPNone, ClusterIPs: []string{k8scorev1.ClusterIPNone}}},
			}
			if mode == corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY {
				objects = append(objects, &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "unused-v6"}, Spec: k8scorev1.NodeSpec{PodCIDR: "fdee:102:304::/64"}})
			} else if mode == corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY {
				objects = append(objects, &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "unused-v4"}, Spec: k8scorev1.NodeSpec{PodCIDR: "100.64.0.0/16"}})
			}
			c := fake.NewSimpleClientset(objects...)
			c.PrependReactor("list", "servicecidrs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, k8serr.NewNotFound(action.GetResource().GroupResource(), "")
			})
			cc := networkValidationConfig(t)
			cc.Status.NetworkConfig = &corev1.ClusterConfig_Status_NetworkConfig{Mode: mode}
			bs := newInitializationInput(t).Bootstrap
			bs.Spec.PrimaryStorage.GetPostgresql().Host = "postgres.example.test"
			bs.Spec.SecondaryStorage.GetRedis().Host = "redis.example.test"
			require.NoError(t, (&Genesis{k8sC: c}).validateClusterNetwork(t.Context(), cc, bs))
		})
	}
}

func TestGenesisNetworkRetriesReadFailures(t *testing.T) {
	for _, resource := range []string{"nodes", "servicecidrs", "services"} {
		t.Run(resource, func(t *testing.T) {
			c := fake.NewSimpleClientset()
			calls := 0
			c.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				if calls == 1 {
					return true, nil, k8serr.NewServiceUnavailable("temporary outage")
				}
				return false, nil, nil
			})
			require.NoError(t, (&Genesis{k8sC: c}).validateClusterNetwork(t.Context(), networkValidationConfig(t), newInitializationInput(t).Bootstrap))
			assert.Equal(t, 2, calls)
		})
	}
}

func TestGenesisNetworkFailsClosed(t *testing.T) {
	for _, resource := range []string{"nodes", "servicecidrs", "services"} {
		t.Run(resource, func(t *testing.T) {
			c := fake.NewSimpleClientset()
			want := k8serr.NewForbidden(schema.GroupResource{Resource: resource}, "", io.EOF)
			calls := 0
			c.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				return true, nil, want
			})
			require.ErrorIs(t, (&Genesis{k8sC: c}).validateClusterNetwork(t.Context(), networkValidationConfig(t), newInitializationInput(t).Bootstrap), want)
			assert.Equal(t, 1, calls)
			for _, action := range c.Actions() {
				assert.Equal(t, "list", action.GetVerb())
			}
		})
	}
	c := fake.NewSimpleClientset()
	g := &Genesis{k8sC: c}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, g.validateClusterNetwork(ctx, networkValidationConfig(t), newInitializationInput(t).Bootstrap), context.Canceled)
	assert.Empty(t, c.Actions())
	c.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serr.NewServiceUnavailable("unavailable")
	})
	ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, g.validateClusterNetwork(ctx, networkValidationConfig(t), newInitializationInput(t).Bootstrap), context.DeadlineExceeded)
}

func TestGenesisRejectsInvalidNetworkBeforeMutation(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "true"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, tc := range []struct {
		name, yaml, want string
	}{
		{"malformed", "v4: {clusterNetwork: invalid}", "network.v4.clusterNetwork"},
		{"wrong-family", "v4: {clusterNetwork: 'fd00::/64'}", "network.v4.clusterNetwork"},
		{"too-small", "v4: {clusterNetwork: 10.20.30.0/24}", "network.v4.clusterNetwork"},
		{"host-bits", "v4: {clusterNetwork: 10.0.0.1/8}", "network.v4.clusterNetwork"},
		{"mode", "mode: 99", "network.mode"},
		{"allocation", "v4: {regionBits: 7, gatewayBits: 5}", "regionBits"},
		{"port", "wireguard: {gatewayPort: 65536}", "gatewayPort"},
		{"mtu", "wireguard: {mtu: 1279}", "mtu"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := newInitializationInput(t)
			input.Bootstrap.Spec.Network = &cbootstrapv1.Config_Spec_Network{}
			require.NoError(t, pbutils.UnmarshalYAML([]byte(tc.yaml), input.Bootstrap.Spec.Network))
			c := fake.NewSimpleClientset(&k8scorev1.Secret{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "default"},
				Data:       map[string][]byte{"domain": []byte(input.Domain), "bootstrap": pbutils.MarshalMust(input.Bootstrap), "region": pbutils.MarshalMust(input.Region)},
			})
			require.ErrorContains(t, (&Genesis{k8sC: c}).RunInit(t.Context(), nil), tc.want)
			for _, action := range c.Actions() {
				assert.Contains(t, []string{"get", "list"}, action.GetVerb())
			}
			_, err := c.CoreV1().Namespaces().Get(t.Context(), vutils.K8sNS, k8smetav1.GetOptions{})
			assert.True(t, k8serr.IsNotFound(err))
		})
	}
}

func TestInitializationPreservesLegacyNetworkCheckpoint(t *testing.T) {
	c := fake.NewSimpleClientset()
	g := &Genesis{k8sC: c}
	input := newInitializationInput(t)
	state, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	input.Bootstrap.Spec.Network = &cbootstrapv1.Config_Spec_Network{V4: &cbootstrapv1.Config_Spec_Network_V4{ClusterNetwork: "10.20.30.0/24"}}
	state.clusterConfig.Status.NetworkConfig = &corev1.ClusterConfig_Status_NetworkConfig{V4: &corev1.ClusterConfig_Status_NetworkConfig_V4{ClusterNetwork: "10.20.30.0/24"}}
	hash, err := initializationInputHash(input)
	require.NoError(t, err)
	secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	secret.Data["input-hash"] = []byte(hash)
	secret.Data["clusterConfig"] = pbutils.MarshalMust(state.clusterConfig)
	require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
	c.ClearActions()
	for _, resource := range []string{"nodes", "services", "servicecidrs"} {
		c.PrependReactor("list", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
			t.Errorf("Checkpoint resume unexpectedly requested network preflight for %s", action.GetResource())
			return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "", nil)
		})
	}
	resumed, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	assert.Equal(t, state.id, resumed.id)
	assert.True(t, proto.Equal(state.clusterConfig, resumed.clusterConfig))
	for _, action := range c.Actions() {
		assert.Equal(t, "get", action.GetVerb())
	}
}
