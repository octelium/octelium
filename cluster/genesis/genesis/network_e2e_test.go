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
	"testing"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

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
			c := f.client.K8sC.(*k8sfake.Clientset)
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
				require.NoError(t, f.client.K8sC.(*k8sfake.Clientset).Tracker().Add(&k8scorev1.Node{
					ObjectMeta: k8smetav1.ObjectMeta{Name: "overlapping-node"}, Spec: k8scorev1.NodeSpec{PodCIDR: "100.65.1.0/24"},
				}))
			case "storage-overlap":
				f.input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "100.64.1.1"
				setNetworkBootstrap(t, f, nil)
			}
			c := f.client.K8sC.(*k8sfake.Clientset)
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
		f.client.K8sC.(*k8sfake.Clientset).PrependReactor("list", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
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
