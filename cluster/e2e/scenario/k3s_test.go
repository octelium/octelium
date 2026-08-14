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

package scenario

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func node(name string, status k8scorev1.ConditionStatus, reason, msg string) *k8scorev1.Node {
	return &k8scorev1.Node{
		ObjectMeta: k8smetav1.ObjectMeta{Name: name},
		Status: k8scorev1.NodeStatus{
			Conditions: []k8scorev1.NodeCondition{
				{Type: k8scorev1.NodeMemoryPressure, Status: k8scorev1.ConditionFalse},
				{Type: k8scorev1.NodeReady, Status: status, Reason: reason, Message: msg},
			},
		},
	}
}

func TestNodeNotReady(t *testing.T) {
	t.Run("a Ready node reports nothing", func(t *testing.T) {
		assert.Empty(t, nodeNotReady(node("n1", k8scorev1.ConditionTrue, "KubeletReady", "")))
	})

	t.Run("a node without a CNI names the reason", func(t *testing.T) {
		got := nodeNotReady(node("n1", k8scorev1.ConditionFalse, "KubeletNotReady",
			"container runtime network not ready: NetworkReady=false reason:NetworkPluginNotReady "+
				"message:Network plugin returns error: cni plugin not initialized"))

		assert.Contains(t, got, "n1")
		assert.Contains(t, got, "KubeletNotReady")
		assert.Contains(t, got, "cni plugin not initialized")
	})

	t.Run("an unknown status is reported too", func(t *testing.T) {
		got := nodeNotReady(node("n1", k8scorev1.ConditionUnknown, "NodeStatusUnknown",
			"Kubelet stopped posting node status"))

		assert.Contains(t, got, "Kubelet stopped posting node status")
	})

	t.Run("a node that has not posted a Ready condition yet", func(t *testing.T) {
		n := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "n1"}}
		assert.Contains(t, nodeNotReady(n), "no Ready condition")
	})
}

func TestK3sCNIPaths(t *testing.T) {
	t.Run("k3s points the runtime at its own directories only for flannel",
		func(t *testing.T) {
			for _, cni := range []CNI{"", CNIFlannel} {
				paths := k3sCNIPaths(cni)
				assert.Equal(t, k3sFlannelBinDir, paths.BinDir, "cni=%q", cni)
				assert.Equal(t, k3sFlannelNetDir, paths.NetDir, "cni=%q", cni)
			}
		})

	t.Run("--flannel-backend=none leaves the runtime on the standard directories",
		func(t *testing.T) {
			for _, cni := range []CNI{CNICilium, CNICalico, CNICanal} {
				paths := k3sCNIPaths(cni)
				assert.Equal(t, stdCNIBinDir, paths.BinDir, "cni=%q", cni)
				assert.Equal(t, stdCNINetDir, paths.NetDir, "cni=%q", cni)
			}
		})
}

func TestK3sProvisionerCNIWiring(t *testing.T) {
	t.Run("flannel is served by k3s itself", func(t *testing.T) {
		p := k3sProvisioner(CNIFlannel)

		assert.NotContains(t, p.ServerArgs, "--flannel-backend=none")
		assert.NotContains(t, p.InstallExec, "--flannel-backend=none")
		assert.Equal(t, k3sFlannelNetDir, p.CNIPaths().NetDir)
	})

	t.Run("another CNI disables flannel and moves the paths with it",
		func(t *testing.T) {
			for _, cni := range []CNI{CNICilium, CNICalico} {
				p := k3sProvisioner(cni)

				assert.Contains(t, p.ServerArgs, "--flannel-backend=none", "cni=%q", cni)
				assert.Contains(t, p.InstallExec, "--flannel-backend=none", "cni=%q", cni)

				assert.Equal(t, stdCNIBinDir, p.CNIPaths().BinDir, "cni=%q", cni)
				assert.Equal(t, stdCNINetDir, p.CNIPaths().NetDir, "cni=%q", cni)
			}
		})

	t.Run("Multus follows the CNI the scenario runs", func(t *testing.T) {
		for _, id := range []string{"k3s-flannel", "k3s-cilium", "k3s-calico"} {
			s, err := Get(id)
			require.NoError(t, err)

			paths := s.Provisioner.CNIPaths()
			require.NotEmpty(t, paths.BinDir, id)
			require.NotEmpty(t, paths.NetDir, id)

			want := k3sCNIPaths(s.CNI)
			assert.Equal(t, want, paths, id)
		}
	})
}

func TestK3sProvisionScheduleInstallsTheCNIBeforeWaitingOnReadiness(t *testing.T) {
	p := k3sProvisioner(CNICilium)

	var names []string
	for _, step := range p.provisionSteps() {
		names = append(names, step.Name)
	}

	registered := slices.Index(names, "k3s/nodes-registered")
	install := slices.Index(names, "cni/install")
	plugins := slices.Index(names, "cni/plugins")
	ready := slices.Index(names, "k3s/nodes-ready")

	require.NotEqual(t, -1, registered)
	require.NotEqual(t, -1, install)
	require.NotEqual(t, -1, plugins)
	require.NotEqual(t, -1, ready)

	assert.Less(t, registered, install)
	assert.Less(t, install, plugins)
	assert.Less(t, plugins, ready)
}

func TestK3sReferencePluginsOnlyWhereTheCNIDoesNotShipThem(t *testing.T) {
	stepsFor := func(cni CNI) map[string]Step {
		ret := map[string]Step{}
		for _, step := range k3sProvisioner(cni).provisionSteps() {
			ret[step.Name] = step
		}
		return ret
	}

	t.Run("k3s ships bridge and host-local alongside flannel", func(t *testing.T) {
		steps := stepsFor(CNIFlannel)

		require.NotNil(t, steps["cni/plugins"].Skip)
		assert.True(t, steps["cni/plugins"].Skip(nil))
		assert.True(t, steps["cni/install"].Skip(nil))
	})

	t.Run("cilium and calico ship only their own plugin", func(t *testing.T) {
		for _, cni := range []CNI{CNICilium, CNICalico} {
			steps := stepsFor(cni)

			require.NotNil(t, steps["cni/plugins"].Skip, "cni=%q", cni)
			assert.False(t, steps["cni/plugins"].Skip(nil), "cni=%q", cni)
			assert.False(t, steps["cni/install"].Skip(nil), "cni=%q", cni)
		}
	})
}
