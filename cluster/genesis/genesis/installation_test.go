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
	"errors"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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
			require.NoError(t, pbutils.UnmarshalYAML([]byte(fmt.Sprintf("spec:\n  network:\n    mode: %s\n    v4: {clusterNetwork: 100.96.0.0/11, gatewayBits: 7, regionBits: 5}\n    wireguard: {gatewayPort: 51820, mtu: 1380}\n    quicv0: {enable: true, gatewayPort: 9443, mtu: 1280}\n  spiffe: {enable: true, trustDomain: test.local}\n", mode)), bs))
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
