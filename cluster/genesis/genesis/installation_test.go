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
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/clusterconfig"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestGetInstallationFromBootstrapWithoutOptions(t *testing.T) {
	for _, bs := range []*cbootstrapv1.Config{
		nil,
		{},
		{Spec: &cbootstrapv1.Config_Spec{}},
		{Spec: &cbootstrapv1.Config_Spec{
			PrimaryStorage: &cbootstrapv1.Config_Spec_PrimaryStorage{},
		}},
	} {
		ret, err := getInstallationFromBootstrap(bs)
		assert.Nil(t, err)
		assert.Nil(t, ret)
	}
}

func TestGetInstallationFromBootstrap(t *testing.T) {
	ret, err := getInstallationFromBootstrap(&cbootstrapv1.Config{
		Spec: &cbootstrapv1.Config_Spec{
			Spiffe: &cbootstrapv1.Config_Spec_SPIFFE{
				Enable:      true,
				TrustDomain: "octelium.local",
				CsiDriver: &cbootstrapv1.Config_Spec_SPIFFE_CSIDriver{
					Name: "csi.example.com",
				},
			},
			Cni: &cbootstrapv1.Config_Spec_CNI{
				ConfDirType: &cbootstrapv1.Config_Spec_CNI_MultusConfDir{
					MultusConfDir: "/opt/multus/conf",
				},
			},
			Ingress: &cbootstrapv1.Config_Spec_Ingress{
				FrontProxy: &cbootstrapv1.Config_Spec_Ingress_FrontProxy{
					Enable: true,
				},
			},
		},
	})
	assert.Nil(t, err)

	assert.True(t, ret.GetSpiffe().GetEnable())
	assert.Equal(t, "octelium.local", ret.GetSpiffe().GetTrustDomain())
	assert.Equal(t, "csi.example.com", ret.GetSpiffe().GetCsiDriver().GetName())

	assert.Empty(t, ret.GetCni().GetConfDir())
	assert.Equal(t, "/opt/multus/conf", ret.GetCni().GetMultusConfDir())

	assert.True(t, ret.GetIngress().GetFrontProxy().GetEnable())
}

func TestGetInstallationFromBootstrapPartial(t *testing.T) {
	ret, err := getInstallationFromBootstrap(&cbootstrapv1.Config{
		Spec: &cbootstrapv1.Config_Spec{
			Spiffe: &cbootstrapv1.Config_Spec_SPIFFE{Enable: true},
		},
	})
	assert.Nil(t, err)

	assert.True(t, ret.GetSpiffe().GetEnable())
	assert.Empty(t, ret.GetSpiffe().GetCsiDriver().GetName())
	assert.Nil(t, ret.GetCni())
	assert.Nil(t, ret.GetIngress())
}

func TestGetInstallationFromBootstrapYAML(t *testing.T) {
	y := `
spec:
  primaryStorage:
    postgresql:
      username: postgres
      password: "pass"
      host: localhost
      port: 5432
  secondaryStorage:
    redis:
      password: "pass"
      host: localhost
      port: 6379
  spiffe:
    enable: true
    trustDomain: octelium.local
    csiDriver:
      name: csi.example.com
  cni:
    confDir: /var/lib/rancher/k3s/agent/etc/cni
  ingress:
    frontProxy:
      enable: true
`
	bs := &cbootstrapv1.Config{}
	assert.Nil(t, pbutils.UnmarshalYAML([]byte(y), bs))

	ret, err := getInstallationFromBootstrap(bs)
	assert.Nil(t, err)

	assert.True(t, ret.GetSpiffe().GetEnable())
	assert.Equal(t, "octelium.local", ret.GetSpiffe().GetTrustDomain())
	assert.Equal(t, "csi.example.com", ret.GetSpiffe().GetCsiDriver().GetName())
	assert.Equal(t, "/var/lib/rancher/k3s/agent/etc/cni", ret.GetCni().GetConfDir())
	assert.Empty(t, ret.GetCni().GetMultusConfDir())
	assert.True(t, ret.GetIngress().GetFrontProxy().GetEnable())
}

func TestGetInstallationFromBootstrapYAMLBothConfDirs(t *testing.T) {
	y := `
spec:
  cni:
    confDir: /var/lib/rancher/k3s/agent/etc/cni
    multusConfDir: /opt/multus/conf
`
	assert.NotNil(t, pbutils.UnmarshalYAML([]byte(y), &cbootstrapv1.Config{}))
}

func TestGetInstallationFromBootstrapYAMLMultusConfDir(t *testing.T) {
	y := `
spec:
  cni:
    multusConfDir: /opt/multus/conf
`
	bs := &cbootstrapv1.Config{}
	assert.Nil(t, pbutils.UnmarshalYAML([]byte(y), bs))

	ret, err := getInstallationFromBootstrap(bs)
	assert.Nil(t, err)

	assert.Equal(t, "/opt/multus/conf", ret.GetCni().GetMultusConfDir())
	assert.Empty(t, ret.GetCni().GetConfDir())
}

func TestOctopsBootstrapHandoff(t *testing.T) {
	for _, cni := range []string{"confDir: /var/lib/rancher/k3s/agent/etc/cni", "multusConfDir: /opt/multus/conf"} {
		t.Run(cni, func(t *testing.T) {
			ctx := context.Background()
			bs := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.UnmarshalYAML([]byte(fmt.Sprintf("spec:\n  primaryStorage:\n    postgresql: {host: postgres, username: installer, passwordFromSecret: {name: postgres-auth, namespace: storage, key: custom}}\n  secondaryStorage:\n    redis: {host: redis, password: redis-secret}\n  spiffe: {enable: true, trustDomain: test.local, csiDriver: {name: custom.csi}}\n  cni: {%s}\n  ingress: {frontProxy: {enable: true}}\n", cni)), bs))
			region := &corev1.Region{Kind: "Region", Metadata: &metav1.Metadata{Name: "default", SystemLabels: map[string]string{"external-ips": `["203.0.113.10"]`}}, Spec: &corev1.Region_Spec{}, Status: &corev1.Region_Status{}}
			c := fakek8s.NewSimpleClientset(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "default"}, Data: map[string][]byte{"domain": []byte("example.com"), "region": pbutils.MarshalMust(region), "bootstrap": pbutils.MarshalMust(bs)}})
			g := &Genesis{k8sC: c}
			loaded, err := g.loadClusterInitResources(ctx, "")
			require.NoError(t, err)
			assert.Equal(t, "example.com", loaded.Domain)
			assert.True(t, pbutils.IsEqual(bs, loaded.Bootstrap))
			assert.True(t, pbutils.IsEqual(region, loaded.Region))
			initialized, err := g.initRegion(loaded)
			require.NoError(t, err)
			assert.True(t, initialized.Metadata.IsSystem)
			assert.Equal(t, `["203.0.113.10"]`, initialized.Metadata.SystemLabels["external-ips"])
			assert.NotEmpty(t, initialized.Status.Version)
			assert.Equal(t, initialized.Status.Version, initialized.Status.VersionInfoMap["octelium"].Version)
			installation, err := getInstallationFromBootstrap(loaded.Bootstrap)
			require.NoError(t, err)
			require.NoError(t, g.setInstallationConfigMap(ctx, &corev1.ClusterConfig{Status: &corev1.ClusterConfig_Status{Installation: installation}}))
			cm, err := c.CoreV1().ConfigMaps("octelium").Get(ctx, "octelium-installation", k8smetav1.GetOptions{})
			require.NoError(t, err)
			decoded := &corev1.ClusterConfig_Status_Installation{}
			require.NoError(t, pbutils.UnmarshalJSON([]byte(cm.Data["installation.json"]), decoded))
			assert.True(t, pbutils.IsEqual(installation, decoded))
			assert.Equal(t, "custom.csi", decoded.Spiffe.GetCsiDriver().Name)
			assert.Equal(t, "test.local", decoded.Spiffe.TrustDomain)
			assert.True(t, decoded.Ingress.FrontProxy.Enable)
			assert.NotContains(t, cm.Data["installation.json"], "redis-secret")
			require.NoError(t, g.moveClusterInitResources(ctx))
			_, err = c.CoreV1().Secrets("default").Get(ctx, "octelium-init", k8smetav1.GetOptions{})
			assert.True(t, k8serr.IsNotFound(err))
			upgraded, err := g.loadClusterInitResources(ctx, "octelium")
			require.NoError(t, err)
			assert.Equal(t, loaded.Domain, upgraded.Domain)
			assert.True(t, pbutils.IsEqual(bs, upgraded.Bootstrap))
			assert.True(t, pbutils.IsEqual(region, upgraded.Region))
			require.NoError(t, g.setInstallationConfigMap(ctx, &corev1.ClusterConfig{Status: &corev1.ClusterConfig_Status{}}))
			cm, err = c.CoreV1().ConfigMaps("octelium").Get(ctx, "octelium-installation", k8smetav1.GetOptions{})
			require.NoError(t, err)
			decoded = &corev1.ClusterConfig_Status_Installation{}
			require.NoError(t, pbutils.UnmarshalJSON([]byte(cm.Data["installation.json"]), decoded))
			assert.Nil(t, decoded.Spiffe)
		})
	}
}

func TestOctopsBootstrapLoadErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		data map[string][]byte
	}{
		{"missing bootstrap", map[string][]byte{"domain": []byte("example.com")}},
		{"corrupt bootstrap", map[string][]byte{"bootstrap": {0xff}}},
		{"corrupt region", map[string][]byte{"bootstrap": pbutils.MarshalMust(&cbootstrapv1.Config{}), "region": {0xff}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fakek8s.NewSimpleClientset(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "default"}, Data: tc.data})
			g := &Genesis{k8sC: c}
			_, err := g.loadClusterInitResources(context.Background(), "default")
			assert.Error(t, err)
		})
	}
	c := fakek8s.NewSimpleClientset()
	g := &Genesis{k8sC: c}
	_, err := g.loadClusterInitResources(context.Background(), "default")
	assert.True(t, k8serr.IsNotFound(err))
	bs := &cbootstrapv1.Config{Spec: &cbootstrapv1.Config_Spec{}}
	require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "default"}, Data: map[string][]byte{"bootstrap": pbutils.MarshalMust(bs)}}))
	loaded, err := g.loadClusterInitResources(context.Background(), "default")
	require.NoError(t, err)
	assert.Nil(t, loaded.Region)
	assert.Empty(t, loaded.Domain)
	want := errors.New("read forbidden")
	c.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
	_, err = g.loadClusterInitResources(context.Background(), "default")
	assert.ErrorIs(t, err, want)
}

func TestOctopsBootstrapMoveErrors(t *testing.T) {
	c := fakek8s.NewSimpleClientset()
	g := &Genesis{k8sC: c}
	assert.True(t, k8serr.IsNotFound(g.moveClusterInitResources(context.Background())))
	require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "default"}, Data: map[string][]byte{"domain": []byte("example.com")}}))
	want := errors.New("destination unavailable")
	c.PrependReactor("create", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
	assert.ErrorIs(t, g.moveClusterInitResources(context.Background()), want)
	_, err := c.CoreV1().Secrets("default").Get(context.Background(), "octelium-init", k8smetav1.GetOptions{})
	assert.NoError(t, err)
}

func TestOctopsInstallationConfigMapErrors(t *testing.T) {
	for _, verb := range []string{"create", "get", "update"} {
		t.Run(verb, func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
			if verb != "create" {
				require.NoError(t, c.Tracker().Add(&k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-installation", Namespace: "octelium"}}))
			}
			want := errors.New("configmap unavailable")
			c.PrependReactor(verb, "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
			g := &Genesis{k8sC: c}
			assert.ErrorIs(t, g.setInstallationConfigMap(context.Background(), &corev1.ClusterConfig{Status: &corev1.ClusterConfig_Status{}}), want)
		})
	}
}

func TestOctopsBootstrapNetworkSettings(t *testing.T) {
	for _, mode := range []string{"DEFAULT", "DUAL_STACK", "V4_ONLY", "V6_ONLY"} {
		t.Run(mode, func(t *testing.T) {
			bs := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.UnmarshalYAML([]byte(fmt.Sprintf("spec:\n  network:\n    mode: %s\n    v4: {clusterNetwork: 100.96.0.0/11, gatewayBits: 3, regionBits: 5}\n    wireguard: {gatewayPort: 51820, mtu: 1380}\n    quicv0: {enable: true, gatewayPort: 9443, mtu: 1280}\n  spiffe: {enable: true, trustDomain: test.local}\n", mode)), bs))
			g := &Genesis{}
			cc, err := g.initClusterConfig(context.Background(), bs, "example.com")
			require.NoError(t, err)
			assert.Equal(t, "example.com", cc.Status.Domain)
			assert.Equal(t, "default", cc.Metadata.Name)
			assert.True(t, cc.Metadata.IsSystem)
			assert.Equal(t, int32(bs.Spec.Network.Mode), int32(cc.Status.NetworkConfig.Mode))
			assert.Equal(t, "100.96.0.0/11", cc.Status.Network.ClusterNetwork.V4)
			assert.Equal(t, "100.96.0.0/16", cc.Status.Network.ServiceSubnet.V4)
			assert.Equal(t, "100.97.0.0/16", cc.Status.Network.WgConnSubnet.V4)
			assert.Equal(t, "100.98.0.0/16", cc.Status.Network.QuicConnSubnet.V4)
			assert.Equal(t, bs.Spec.Network.V4.GatewayBits, cc.Status.NetworkConfig.V4.GatewayBits)
			assert.Equal(t, bs.Spec.Network.V4.RegionBits, cc.Status.NetworkConfig.V4.RegionBits)
			assert.Equal(t, bs.Spec.Network.Wireguard.GatewayPort, cc.Status.NetworkConfig.Wireguard.GatewayPort)
			assert.Equal(t, bs.Spec.Network.Wireguard.Mtu, cc.Status.NetworkConfig.Wireguard.Mtu)
			assert.Equal(t, bs.Spec.Network.Quicv0.GatewayPort, cc.Status.NetworkConfig.Quicv0.GatewayPort)
			assert.Equal(t, bs.Spec.Network.Quicv0.Mtu, cc.Status.NetworkConfig.Quicv0.Mtu)
			assert.True(t, cc.Status.NetworkConfig.Quicv0.Enable)
			assert.Len(t, cc.Status.Network.V6RangePrefix, 4)
			assert.True(t, cc.Status.Installation.Spiffe.Enable)
		})
	}
	g := &Genesis{}
	cc, err := g.initClusterConfig(context.Background(), &cbootstrapv1.Config{Spec: &cbootstrapv1.Config_Spec{}}, "example.com")
	require.NoError(t, err)
	assert.Equal(t, "100.64.0.0/10", cc.Status.Network.ClusterNetwork.V4)
	assert.Nil(t, cc.Status.NetworkConfig)
	assert.Nil(t, cc.Status.Installation)
}

func setNetworkBootstrap(t *testing.T, f *initializationFixture, network *cbootstrapv1.Config_Spec_Network) {
	t.Helper()
	f.input.Bootstrap.Spec.Network = network
	secret, err := f.client.K8sC.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	secret.Data["bootstrap"] = pbutils.MarshalMust(f.input.Bootstrap)
	_, err = f.client.K8sC.CoreV1().Secrets("default").Update(t.Context(), secret, k8smetav1.UpdateOptions{})
	require.NoError(t, err)
}

func TestGenesisNetworkInitializationE2E(t *testing.T) {
	for _, mode := range []cbootstrapv1.Config_Spec_Network_Mode{
		cbootstrapv1.Config_Spec_Network_DUAL_STACK, cbootstrapv1.Config_Spec_Network_V4_ONLY, cbootstrapv1.Config_Spec_Network_V6_ONLY,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newInitializationFixture(t)
			setNetworkBootstrap(t, f, &cbootstrapv1.Config_Spec_Network{
				Mode: mode, V4: &cbootstrapv1.Config_Spec_Network_V4{ClusterNetwork: "10.0.0.0/14", RegionBits: 3, GatewayBits: 5},
			})
			reads := 0
			c := f.client.K8sC.(*fakek8s.Clientset)
			c.PrependReactor("list", "servicecidrs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				reads++
				if reads == 1 {
					_, err := c.Tracker().Get(k8scorev1.SchemeGroupVersion.WithResource("secrets"), vutils.K8sNS, initializationSecretName)
					assert.True(t, k8serr.IsNotFound(err))
					return true, nil, k8serr.NewServiceUnavailable("temporary discovery failure")
				}
				return true, nil, k8serr.NewNotFound(action.GetResource().GroupResource(), "")
			})
			require.NoError(t, f.genesis.RunInit(t.Context(), nil))
			cc, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
			require.NoError(t, err)
			assert.Equal(t, "10.0.0.0/14", cc.Status.Network.ClusterNetwork.V4)
			assert.Equal(t, "10.0.0.0/16", cc.Status.Network.ServiceSubnet.V4)
			assert.Equal(t, "10.1.0.0/16", cc.Status.Network.WgConnSubnet.V4)
			assert.Equal(t, "10.2.0.0/16", cc.Status.Network.QuicConnSubnet.V4)
			network := proto.Clone(cc.Status.Network)
			keys := initializationSecrets(t, f.db)
			require.NoError(t, f.genesis.RunInit(t.Context(), nil))
			require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
			cc, err = f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
			require.NoError(t, err)
			assert.True(t, proto.Equal(network, cc.Status.Network))
			assert.Equal(t, keys, initializationSecrets(t, f.db))
			assert.Equal(t, 2, reads)
			f.checkPreserved(t)
		})
	}
}

func TestGenesisNetworkRejectsBeforeStorageE2E(t *testing.T) {
	for _, state := range []string{"invalid-cidr", "pod-overlap", "storage-overlap"} {
		t.Run(state, func(t *testing.T) {
			f := newInitializationFixture(t)
			want := "overlaps"
			switch state {
			case "invalid-cidr":
				setNetworkBootstrap(t, f, &cbootstrapv1.Config_Spec_Network{V4: &cbootstrapv1.Config_Spec_Network_V4{ClusterNetwork: "10.20.30.0/24"}})
				want = "network.v4.clusterNetwork"
			case "pod-overlap":
				require.NoError(t, f.client.K8sC.(*fakek8s.Clientset).Tracker().Add(&k8scorev1.Node{
					ObjectMeta: k8smetav1.ObjectMeta{Name: "overlapping-node"}, Spec: k8scorev1.NodeSpec{PodCIDR: "100.65.1.0/24"},
				}))
			case "storage-overlap":
				f.input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "100.64.1.1"
				setNetworkBootstrap(t, f, nil)
			}
			c := f.client.K8sC.(*fakek8s.Clientset)
			start := len(c.Actions())
			require.ErrorContains(t, f.genesis.RunInit(t.Context(), nil), want)
			for _, action := range c.Actions()[start:] {
				assert.Contains(t, []string{"get", "list"}, action.GetVerb())
			}
			var exists bool
			require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT to_regclass('octelium_resources') IS NOT NULL`).Scan(&exists))
			assert.False(t, exists)
			marker, err := f.redis.Exists(t.Context(), initializationRedisKey).Result()
			require.NoError(t, err)
			assert.Zero(t, marker)
			for _, name := range []string{initializationSecretName, "octelium-postgres", "octelium-redis", "init-token"} {
				_, err := f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
				assert.True(t, k8serr.IsNotFound(err))
			}
			f.checkPreserved(t)
		})
	}
}

func TestGenesisLegacyNetworkUpgradeE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	cc, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
	require.NoError(t, err)
	cc.Status.NetworkConfig = &corev1.ClusterConfig_Status_NetworkConfig{V4: &corev1.ClusterConfig_Status_NetworkConfig_V4{
		ClusterNetwork: "10.20.30.0/24", RegionBits: 3, GatewayBits: 5,
	}}
	cc, err = f.genesis.octeliumC.CoreC().UpdateClusterConfig(t.Context(), cc)
	require.NoError(t, err)
	network := proto.Clone(cc.Status.Network)
	config := proto.Clone(cc.Status.NetworkConfig)
	keys := initializationSecrets(t, f.db)
	require.NoError(t, f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Delete(t.Context(), initializationSecretName, k8smetav1.DeleteOptions{}))
	require.NoError(t, f.redis.Del(t.Context(), initializationRedisKey).Err())
	for _, resource := range []string{"services", "servicecidrs"} {
		f.client.K8sC.(*fakek8s.Clientset).PrependReactor("list", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
			t.Errorf("Upgrade unexpectedly requested network preflight for %s", action.GetResource())
			return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "", nil)
		})
	}
	for range 2 {
		require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
		cc, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
		require.NoError(t, err)
		assert.True(t, proto.Equal(network, cc.Status.Network))
		assert.True(t, proto.Equal(config, cc.Status.NetworkConfig))
		assert.Equal(t, keys, initializationSecrets(t, f.db))
	}
	f.checkPreserved(t)
}

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
			c := fakek8s.NewSimpleClientset(tc.object)
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
				c := fakek8s.NewSimpleClientset()
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
			c := fakek8s.NewSimpleClientset(objects...)
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
			c := fakek8s.NewSimpleClientset()
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
			c := fakek8s.NewSimpleClientset()
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
	c := fakek8s.NewSimpleClientset()
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
			c := fakek8s.NewSimpleClientset(&k8scorev1.Secret{
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
	c := fakek8s.NewSimpleClientset()
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

func preserveRepairStorageEnvironment(t *testing.T) func() {
	t.Helper()
	values := map[string]string{}
	for _, prefix := range []string{"OCTELIUM_POSTGRES_", "OCTELIUM_REDIS_"} {
		for _, suffix := range []string{"HOST", "PORT", "DATABASE", "USERNAME", "PASSWORD", "NOSSL", "USE_TLS"} {
			key := prefix + suffix
			values[key] = os.Getenv(key)
			t.Setenv(key, values[key])
		}
	}
	return func() {
		for key, value := range values {
			os.Setenv(key, value)
		}
	}
}

func assertRepairBeforeStorage(t *testing.T, f *initializationFixture) {
	t.Helper()
	var exists bool
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT to_regclass('octelium_resources') IS NOT NULL`).Scan(&exists))
	assert.False(t, exists)
	marker, err := f.redis.Exists(t.Context(), initializationRedisKey).Result()
	require.NoError(t, err)
	assert.Zero(t, marker)
	for _, name := range []string{initializationSecretName, "octelium-postgres", "octelium-redis", "init-token"} {
		_, err := f.client.K8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
		assert.True(t, k8serr.IsNotFound(err), name)
	}
	f.checkPreserved(t)
}

func TestRepairConnectionFailureBeforeBindingE2E(t *testing.T) {
	for _, point := range []string{"postgres-host", "postgres-auth", "redis-host", "redis-auth"} {
		t.Run(point, func(t *testing.T) {
			f := newInitializationFixture(t)
			restore := preserveRepairStorageEnvironment(t)
			good := proto.Clone(f.input.Bootstrap).(*cbootstrapv1.Config)
			good.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password{Password: ""}
			f.input.Bootstrap = proto.Clone(good).(*cbootstrapv1.Config)
			pg, redis := f.input.Bootstrap.Spec.PrimaryStorage.GetPostgresql(), f.input.Bootstrap.Spec.SecondaryStorage.GetRedis()
			if point == "postgres-host" {
				pg.Host = "gen037-does-not-exist.invalid"
			}
			if point == "redis-host" {
				redis.Host = "gen037-does-not-exist.invalid"
			}
			if point == "redis-auth" {
				redis.PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password{Password: "private-invalid-redis-password"}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { listener.Close() })
				redis.Host, redis.Port = "127.0.0.1", int32(listener.Addr().(*net.TCPAddr).Port)
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(2 * time.Second))
					reader := bufio.NewReader(conn)
					for {
						line, err := reader.ReadString('\n')
						if err != nil || !strings.HasPrefix(line, "*") {
							return
						}
						count, err := strconv.Atoi(strings.TrimSpace(line[1:]))
						if err != nil || count < 1 || count > 100 {
							return
						}
						for range count {
							line, err := reader.ReadString('\n')
							if err != nil || !strings.HasPrefix(line, "$") {
								return
							}
							length, err := strconv.Atoi(strings.TrimSpace(line[1:]))
							if err != nil || length < 0 || length > 100000 {
								return
							}
							if _, err := io.CopyN(io.Discard, reader, int64(length+2)); err != nil {
								return
							}
						}
						if _, err := io.WriteString(conn, "-WRONGPASS invalid username-password pair\r\n"); err != nil {
							return
						}
					}
				}()
			}
			if point == "postgres-auth" {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				t.Cleanup(func() { listener.Close() })
				pg.Host, pg.Port = "127.0.0.1", int32(listener.Addr().(*net.TCPAddr).Port)
				pg.PasswordType = &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_Password{Password: "private-invalid-postgres-password"}
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(2 * time.Second))
					var length uint32
					if err := binary.Read(conn, binary.BigEndian, &length); err != nil || length < 4 || length > 100000 {
						return
					}
					if _, err := io.CopyN(io.Discard, conn, int64(length-4)); err != nil {
						return
					}
					body := []byte("SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00")
					conn.Write([]byte{'E'})
					binary.Write(conn, binary.BigEndian, uint32(len(body)+4))
					conn.Write(body)
				}()
			}
			savePasswordBootstrap(t, f)
			_, err := f.client.K8sC.CoreV1().Nodes().Create(t.Context(), &k8scorev1.Node{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "ready-node"},
				Status:     k8scorev1.NodeStatus{Conditions: []k8scorev1.NodeCondition{{Type: k8scorev1.NodeReady, Status: k8scorev1.ConditionTrue}}},
			}, k8smetav1.CreateOptions{})
			require.NoError(t, err)
			ldflags.TestMode = "false"
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			err = f.genesis.RunInit(ctx, nil)
			cancel()
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "private-invalid-")
			assertRepairBeforeStorage(t, f)
			restore()
			ldflags.TestMode = "true"
			f.input.Bootstrap = good
			savePasswordBootstrap(t, f)
			require.NoError(t, f.genesis.RunInit(t.Context(), nil))
			keys := initializationSecrets(t, f.db)
			require.NoError(t, f.genesis.RunInit(t.Context(), nil))
			require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
			assert.Equal(t, keys, initializationSecrets(t, f.db))
			f.checkPreserved(t)
		})
	}
}

func TestRepairStalledStoragePreflight(t *testing.T) {
	for _, storage := range []string{"postgres", "redis", "redis-tls"} {
		t.Run(storage, func(t *testing.T) {
			f := newInitializationFixture(t)
			preserveRepairStorageEnvironment(t)
			ldflags.TestMode = "false"
			bootstrap := proto.Clone(f.input.Bootstrap).(*cbootstrapv1.Config)
			bootstrap.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password{Password: ""}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })
			port := int32(listener.Addr().(*net.TCPAddr).Port)
			if storage == "postgres" {
				bootstrap.Spec.PrimaryStorage.GetPostgresql().Host, bootstrap.Spec.PrimaryStorage.GetPostgresql().Port = "127.0.0.1", port
			} else {
				bootstrap.Spec.SecondaryStorage.GetRedis().Host, bootstrap.Spec.SecondaryStorage.GetRedis().Port = "127.0.0.1", port
				bootstrap.Spec.SecondaryStorage.GetRedis().IsTLS = storage == "redis-tls"
			}
			closed := make(chan struct{})
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				io.Copy(io.Discard, conn)
				close(closed)
			}()
			passwords, err := f.genesis.resolveStoragePasswords(t.Context(), bootstrap)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			err = preflightInitializationStorage(ctx, bootstrap, passwords)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Less(t, time.Since(start), 2*time.Second)
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("Storage connection was not closed on cancellation")
			}
			assertRepairBeforeStorage(t, f)
		})
	}
}

func TestRepairStoragePreflightAcceptsSpecialCredentials(t *testing.T) {
	f := newInitializationFixture(t)
	preserveRepairStorageEnvironment(t)
	ldflags.TestMode = "false"
	name := "gen037 user /?@" + strconv.FormatInt(time.Now().UnixNano(), 36)
	password := " pa:ss/@?#&% ' \\ π "
	_, err := f.db.ExecContext(t.Context(), "CREATE ROLE "+pq.QuoteIdentifier(name)+" LOGIN PASSWORD "+pq.QuoteLiteral(password))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := f.db.ExecContext(context.Background(), "DROP ROLE "+pq.QuoteIdentifier(name))
		assert.NoError(t, err)
	})
	bootstrap := proto.Clone(f.input.Bootstrap).(*cbootstrapv1.Config)
	bootstrap.Spec.PrimaryStorage.GetPostgresql().Username = name
	bootstrap.Spec.PrimaryStorage.GetPostgresql().PasswordType = &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_Password{Password: password}
	redisUser := "gen037:user@" + strconv.FormatInt(time.Now().UnixNano(), 36)
	require.NoError(t, f.redis.Do(t.Context(), "ACL", "SETUSER", redisUser, "on", ">"+password, "+@all", "~*").Err())
	t.Cleanup(func() { assert.NoError(t, f.redis.Do(context.Background(), "ACL", "DELUSER", redisUser).Err()) })
	bootstrap.Spec.SecondaryStorage.GetRedis().Username = redisUser
	bootstrap.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password{Password: password}
	passwords, err := f.genesis.resolveStoragePasswords(t.Context(), bootstrap)
	require.NoError(t, err)
	require.NoError(t, preflightInitializationStorage(t.Context(), bootstrap, passwords))
	assertRepairBeforeStorage(t, f)
}

func TestRepairCheckpointOnlyInitializationE2E(t *testing.T) {
	f := newInitializationFixture(t)
	state, err := f.genesis.prepareInitialization(t.Context(), f.input)
	require.NoError(t, err)
	c := f.client.K8sC.(*fakek8s.Clientset)
	checkpoint, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	checkpoint.ResourceVersion = "1"
	require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), checkpoint, vutils.K8sNS))
	f.input.Bootstrap.Spec.Cni = &cbootstrapv1.Config_Spec_CNI{ConfDirType: &cbootstrapv1.Config_Spec_CNI_MultusConfDir{MultusConfDir: "/custom/multus"}}
	savePasswordBootstrap(t, f)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	current, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.NotEqual(t, state.id, string(current.Data["id"]))
	assert.Equal(t, "true", current.Annotations[initializationCompleteKey])
	keys := initializationSecrets(t, f.db)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	assert.NotEmpty(t, current.Data["aes-key-name"])
}

func attachRepairJob(t *testing.T, f *initializationFixture, binding string) *k8scorev1.Pod {
	t.Helper()
	pod := upgradeTestPod("init-job-uid")
	pod.Namespace, pod.Name = "default", "genesis-attempt"
	pod.Annotations = map[string]string{initializationInputHashKey: binding}
	pod.Labels = map[string]string{"octelium.com/component": "genesis"}
	pod.Status.Phase = k8scorev1.PodRunning
	pod.OwnerReferences[0].Name = "octelium-genesis"
	owner := k8smetav1.GetControllerOf(pod)
	_, err := f.client.K8sC.BatchV1().Jobs(pod.Namespace).Create(t.Context(), &batchv1.Job{
		ObjectMeta: k8smetav1.ObjectMeta{Name: owner.Name, Namespace: pod.Namespace, UID: owner.UID, Labels: pod.Labels},
		Status:     batchv1.JobStatus{Active: 1},
	}, k8smetav1.CreateOptions{})
	require.NoError(t, err)
	pod, err = f.client.K8sC.CoreV1().Pods(pod.Namespace).Create(t.Context(), pod, k8smetav1.CreateOptions{})
	require.NoError(t, err)
	f.genesis.pod = pod
	return pod
}

func TestRepairInputBindingFailureIsReadOnlyE2E(t *testing.T) {
	f := newInitializationFixture(t)
	attachRepairJob(t, f, "different-input-binding")
	require.ErrorContains(t, f.genesis.RunInit(t.Context(), nil), "no longer matches")
	assertRepairBeforeStorage(t, f)
}

func TestRepairBoundInitializationResumesAfterHandoffE2E(t *testing.T) {
	f := newInitializationFixture(t)
	source, err := f.client.K8sC.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	source.Data[initializationInputKey] = []byte("01234567890123456789012345678901")
	_, err = f.client.K8sC.CoreV1().Secrets("default").Update(t.Context(), source, k8smetav1.UpdateOptions{})
	require.NoError(t, err)
	input, err := f.genesis.loadInitializationInput(t.Context())
	require.NoError(t, err)
	hash, err := initializationInputHash(input)
	require.NoError(t, err)
	sourceUID := string(source.UID)
	pod := attachRepairJob(t, f, initializationInputBinding(hash, f.genesis.inputBindingKey))
	c := f.client.K8sC.(*fakek8s.Clientset)
	failed := false
	c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		secret := action.(k8stesting.CreateAction).GetObject().(*k8scorev1.Secret)
		if secret.Name == "init-token" && !failed {
			failed = true
			return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), secret.Name, io.EOF)
		}
		return false, nil, nil
	})
	require.Error(t, f.genesis.RunInit(t.Context(), nil))
	assert.True(t, failed)
	_, err = c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.True(t, k8serr.IsNotFound(err))
	installed, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.NotEqual(t, sourceUID, string(installed.UID))
	keys := initializationSecrets(t, f.db)
	restarted := &Genesis{k8sC: c, nadC: f.client.NadC, pod: pod, rscServer: f.genesis.rscServer}
	require.NoError(t, restarted.RunInit(t.Context(), nil))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	require.NoError(t, restarted.RunInit(t.Context(), nil))
	require.NoError(t, restarted.RunUpgrade(t.Context(), nil))
	assert.Equal(t, keys, initializationSecrets(t, f.db))
	f.checkPreserved(t)
}

func TestRepairTLSConnection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	dialer := &initializationDialer{ctx: ctx, tlsConfig: config}
	conn, err := dialer.DialContext(ctx, "tcp", server.Listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	defer response.Body.Close()
	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func TestRepairStorageEnvironmentKeepsLegacyFallbacks(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	values := map[string]string{
		"OCTELIUM_POSTGRES_HOST": "::1", "OCTELIUM_POSTGRES_PORT": "6432", "OCTELIUM_POSTGRES_DATABASE": "tenant/db?@",
		"OCTELIUM_POSTGRES_USERNAME": "custom user", "OCTELIUM_POSTGRES_PASSWORD": " p@ss:/?& ", "OCTELIUM_POSTGRES_NOSSL": "true",
		"OCTELIUM_REDIS_HOST": "cache.example", "OCTELIUM_REDIS_PORT": "6380", "OCTELIUM_REDIS_DATABASE": "7",
		"OCTELIUM_REDIS_USERNAME": "custom:user", "OCTELIUM_REDIS_PASSWORD": "p@ss:/?&", "OCTELIUM_REDIS_USE_TLS": "true",
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
	bootstrap := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {isTLS: true}}, secondaryStorage: {redis: {}}}"), bootstrap))
	setStorageEnvironment(bootstrap, &storagePasswords{})
	for key, value := range values {
		assert.Equal(t, value, os.Getenv(key), key)
	}
}

func TestRepairCheckpointBeforeStorage(t *testing.T) {
	c := fakek8s.NewSimpleClientset()
	g := &Genesis{k8sC: c}
	input := newInitializationInput(t)
	first, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	checkpoint, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	checkpoint.UID, checkpoint.ResourceVersion = "checkpoint-uid", "1"
	require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), checkpoint, vutils.K8sNS))
	input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "corrected-postgres.example"
	repaired, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	assert.NotEqual(t, first.id, repaired.id)
	assert.NotEqual(t, first.inputHash, repaired.inputHash)
	assert.Equal(t, input.Domain, repaired.clusterConfig.Status.Domain)
	assert.NotEmpty(t, repaired.aesKeyName)
	current, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, repaired.id, string(current.Data["id"]))
}

func newRepairCheckpoint(t *testing.T) (*Genesis, *fakek8s.Clientset, *LoadedClusterResource, *k8scorev1.Secret) {
	t.Helper()
	c := fakek8s.NewSimpleClientset(&k8scorev1.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS, UID: "namespace-uid"}})
	g := &Genesis{k8sC: c}
	input := newInitializationInput(t)
	_, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	checkpoint, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	checkpoint.UID, checkpoint.ResourceVersion = "checkpoint-uid", "1"
	require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), checkpoint, vutils.K8sNS))
	return g, c, input, checkpoint
}

func TestRepairCheckpointPreservesStartedInstallation(t *testing.T) {
	for _, phase := range []string{"octelium-postgres", "octelium-redis", "octelium-init", "init-token", "configuration", "complete", "namespace", "corrupt", "version", "uid", "resource-version"} {
		t.Run(phase, func(t *testing.T) {
			g, c, input, checkpoint := newRepairCheckpoint(t)
			input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "corrected.example"
			switch phase {
			case "configuration":
				require.NoError(t, c.Tracker().Add(&k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: installationConfigMapName, Namespace: vutils.K8sNS}}))
			case "complete":
				checkpoint.Annotations = map[string]string{initializationCompleteKey: "true"}
			case "namespace":
				checkpoint.Data["namespace-uid"] = []byte("previous-namespace")
			case "corrupt":
				checkpoint.Data["clusterConfig"] = []byte("invalid")
			case "version":
				previous := ldflags.GitTag
				t.Cleanup(func() { ldflags.GitTag = previous })
				ldflags.GitTag = "v987.0.0"
			case "uid":
				checkpoint.UID = ""
			case "resource-version":
				checkpoint.ResourceVersion = ""
			default:
				require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: phase, Namespace: vutils.K8sNS, UID: "preserved"}, Data: map[string][]byte{"value": []byte("preserved")}}))
			}
			require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), checkpoint, vutils.K8sNS))
			c.ClearActions()
			_, err := g.prepareInitialization(t.Context(), input)
			require.Error(t, err)
			for _, action := range c.Actions() {
				assert.Contains(t, []string{"get", "list"}, action.GetVerb())
			}
			current, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, checkpoint, current)
		})
	}
}

func TestRepairCheckpointWaitsForSuccessfulPreflight(t *testing.T) {
	for _, phase := range []string{"new", "repair", "storage-appears"} {
		t.Run(phase, func(t *testing.T) {
			g, c, input, checkpoint := newRepairCheckpoint(t)
			if phase == "new" {
				require.NoError(t, c.Tracker().Delete(k8scorev1.SchemeGroupVersion.WithResource("secrets"), vutils.K8sNS, initializationSecretName))
			}
			input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "corrected.example"
			calls := 0
			want := fmt.Errorf("storage not available")
			_, err := g.prepareInitializationWithPreflight(t.Context(), input, func(ctx context.Context, passwords *storagePasswords) error {
				calls++
				assert.NoError(t, ctx.Err())
				assert.Equal(t, "postgres", passwords.postgres)
				if phase == "storage-appears" {
					require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-postgres", Namespace: vutils.K8sNS}}))
					return nil
				}
				return want
			})
			require.Error(t, err)
			assert.Equal(t, 1, calls)
			if phase != "storage-appears" {
				assert.ErrorIs(t, err, want)
			}
			current, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
			if phase == "new" {
				assert.True(t, k8serr.IsNotFound(err))
			} else {
				require.NoError(t, err)
				assert.Equal(t, checkpoint, current)
			}
		})
	}
}

func TestRepairCheckpointDeletionSafety(t *testing.T) {
	for _, point := range []string{"before", "after", "replaced", "completed", "forbidden", "cancelled"} {
		t.Run(point, func(t *testing.T) {
			g, c, input, checkpoint := newRepairCheckpoint(t)
			input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "corrected.example"
			deletes := 0
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			c.PrependReactor("delete", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				deletes++
				deleteAction := action.(k8stesting.DeleteAction)
				require.Equal(t, initializationSecretName, deleteAction.GetName())
				preconditions := deleteAction.GetDeleteOptions().Preconditions
				require.NotNil(t, preconditions)
				assert.Equal(t, new(checkpoint.UID), preconditions.UID)
				assert.Equal(t, new(checkpoint.ResourceVersion), preconditions.ResourceVersion)
				if deletes > 1 {
					return false, nil, nil
				}
				switch point {
				case "after":
					require.NoError(t, c.Tracker().Delete(action.GetResource(), action.GetNamespace(), initializationSecretName))
				case "replaced":
					current := checkpoint.DeepCopy()
					current.UID, current.ResourceVersion = "replacement-uid", "2"
					require.NoError(t, c.Tracker().Update(action.GetResource(), current, action.GetNamespace()))
					return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), initializationSecretName, io.EOF)
				case "completed":
					current := checkpoint.DeepCopy()
					current.Annotations, current.ResourceVersion = map[string]string{initializationCompleteKey: "true"}, "2"
					require.NoError(t, c.Tracker().Update(action.GetResource(), current, action.GetNamespace()))
					return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), initializationSecretName, io.EOF)
				case "forbidden":
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), initializationSecretName, io.EOF)
				case "cancelled":
					cancel()
					return true, nil, context.Canceled
				}
				return true, nil, io.ErrUnexpectedEOF
			})
			repaired, err := g.prepareInitialization(ctx, input)
			switch point {
			case "before", "after":
				require.NoError(t, err)
				assert.NotEqual(t, string(checkpoint.Data["id"]), repaired.id)
				if point == "before" {
					assert.Equal(t, 2, deletes)
				} else {
					assert.Equal(t, 1, deletes)
				}
			default:
				require.Error(t, err)
				assert.Equal(t, 1, deletes)
				current, getErr := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
				require.NoError(t, getErr)
				if point == "replaced" {
					assert.Equal(t, "replacement-uid", string(current.UID))
				} else if point == "completed" {
					assert.Equal(t, "true", current.Annotations[initializationCompleteKey])
				} else {
					assert.Equal(t, checkpoint, current)
				}
			}
		})
	}
}

func TestRepairMatchingCheckpointSkipsNewPreflight(t *testing.T) {
	g, _, input, checkpoint := newRepairCheckpoint(t)
	result, err := g.prepareInitializationWithPreflight(t.Context(), input, func(context.Context, *storagePasswords) error {
		t.Fatal("Matching checkpoint must retain legacy replay behavior")
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, string(checkpoint.Data["id"]), result.id)
}

func TestRepairInputHashCompatibility(t *testing.T) {
	for _, tc := range []struct{ name, hash, binding string }{
		{"region", "44642b94e6da0fa7b5e5e944c5449349ae595f3980853843c35f62812964161c", "c02a415829ae7399191ecc015fed96410e70696d2529ad2a5e7f1ee249614d97"},
		{"nil-region", "06ff4e8bba40f04f913a4f55d7b50d0a44162095cc334f17f68f34fece97c0a9", "b6fb5dbd76337d2b30299063fc3991835dfe25f151cb708446006d6e59aa04e2"},
		{"unknown", "16ec771cc69f6f92bf580c017c28f942763fbafdfa4bae41705f356f484f18cc", "2d65e18f02d1112d75ea0ee7761dbbb09623fc502cff52aeb124baa2101e0245"},
		{"empty", "3babbfe6662c6fd5437cef3d4c7e5a590ce20ab4fba62412dd3c4d2cb9f5ae50", "5920145142603dd5c2de668f49e7780a254965c718c0d2a0ec4d40621593e5f2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bootstrap := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: localhost, username: postgres, password: ' p@ss:/?& ' }}, secondaryStorage: {redis: {host: localhost, database: 7}}}"), bootstrap))
			region := &corev1.Region{Metadata: &metav1.Metadata{Name: "default", Labels: map[string]string{"z": "2", "a": "1"}}, Spec: &corev1.Region_Spec{}, Status: &corev1.Region_Status{}}
			if tc.name == "nil-region" {
				region = nil
			}
			if tc.name == "unknown" {
				bootstrap.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01})
			}
			if tc.name == "empty" {
				bootstrap, region = &cbootstrapv1.Config{}, nil
			}
			hash, err := initializationInputHash(&LoadedClusterResource{Bootstrap: bootstrap, Region: region, Domain: "example.com"})
			require.NoError(t, err)
			assert.Equal(t, tc.hash, hash)
			assert.Equal(t, tc.binding, initializationInputBinding(hash, []byte("input-secret-uid")))
			assert.NotEqual(t, tc.binding, initializationInputBinding(hash, []byte("other-secret-uid")))
		})
	}
}
