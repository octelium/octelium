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
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
)

func TestParseSpec(t *testing.T) {
	t.Run("the base forms are unchanged", func(t *testing.T) {
		for id, want := range map[string]Spec{
			"k3s-flannel":        {Distro: DistroK3s, CNI: CNIFlannel},
			"k3s-cilium-spiffe":  {Distro: DistroK3s, CNI: CNICilium, SPIFFE: true},
			"rke2-canal":         {Distro: DistroRKE2, CNI: CNICanal},
			"k8s-calico-spiffe":  {Distro: DistroK8s, CNI: CNICalico, SPIFFE: true},
			"k3s-calico-chaos":   {Distro: DistroK3s, CNI: CNICalico, Chaos: true},
			"k3s-flannel-nodes4": {Distro: DistroK3s, CNI: CNIFlannel, Nodes: 4},
		} {
			got, err := ParseSpec(id)
			require.NoError(t, err, id)
			assert.Equal(t, want, got, id)
			assert.Equal(t, id, got.ID(), "the ID must round-trip")
		}
	})

	t.Run("modifiers are accepted in any order and the ID is canonical", func(t *testing.T) {
		for _, id := range []string{
			"k3s-flannel-nodes8-spiffe-chaos",
			"k3s-flannel-chaos-spiffe-nodes8",
			"k3s-flannel-spiffe-nodes8-chaos",
		} {
			got, err := ParseSpec(id)
			require.NoError(t, err, id)
			assert.Equal(t, Spec{
				Distro: DistroK3s, CNI: CNIFlannel, Nodes: 8, SPIFFE: true, Chaos: true,
			}, got, id)
			assert.Equal(t, "k3s-flannel-nodes8-spiffe-chaos", got.ID(), id)
		}
	})

	t.Run("a single node is the default topology", func(t *testing.T) {
		got, err := ParseSpec("k3s-flannel-nodes1")
		require.NoError(t, err)

		assert.False(t, got.IsMultiNode())
		assert.Equal(t, "k3s-flannel", got.ID())
	})

	t.Run("malformed IDs are rejected", func(t *testing.T) {
		for _, id := range []string{
			"k3s",
			"k3s-flannel-chaos-chaos",
			"k3s-flannel-spiffe-spiffe",
			"k3s-flannel-nodes",
			"k3s-flannel-nodesx",
			"k3s-flannel-nodes2-nodes4",
			"k3s-flannel-gpu",
		} {
			_, err := ParseSpec(id)
			require.Error(t, err, id)
			assert.Contains(t, err.Error(), "Malformed", id)
		}
	})

	t.Run("invalid topologies are rejected", func(t *testing.T) {
		for _, id := range []string{
			"k3s-flannel-nodes33",
			"k3s-flannel-nodes-1",
			"k3s-cilium-nodes4",
			"k3s-calico-nodes2",
			"rke2-canal-nodes2",
		} {
			_, err := ParseSpec(id)
			require.Error(t, err, id)
		}
	})
}

func TestSpecsListsTheChaosAndMultiNodeVariants(t *testing.T) {
	ids := map[string]bool{}
	for _, spec := range Specs() {
		require.NoError(t, spec.Validate(), spec.ID())
		assert.False(t, ids[spec.ID()], "the ID %s is listed more than once", spec.ID())
		ids[spec.ID()] = true
	}

	for _, id := range []string{
		"k3s-flannel",
		"k3s-flannel-chaos",
		"k3s-flannel-spiffe-chaos",
		"k3s-flannel-nodes2",
		"k3s-flannel-nodes32-chaos",
	} {
		assert.True(t, ids[id], id)
	}
}

func TestBuildMultiNode(t *testing.T) {
	withCustomizers(t)

	s, err := Get("k3s-flannel-nodes4")
	require.NoError(t, err)

	assert.Equal(t, "k3s-flannel-nodes4", s.ID)
	assert.Equal(t, 4, s.Topology.Nodes)
	assert.True(t, s.Caps.Has(CapMultiNode))
	assert.False(t, s.Caps.Has(CapChaos))

	assert.Contains(t, s.Topology.Labels, vutils.NodeLabelControlPlane,
		"the server node keeps the control plane")
	assert.Contains(t, s.Topology.AgentLabels, vutils.NodeLabelDataPlane)
	assert.NotContains(t, s.Topology.AgentLabels, vutils.NodeLabelControlPlane,
		"the agent nodes only run Gateways and Services")

	p, ok := s.Provisioner.(*K3s)
	require.True(t, ok)
	assert.Equal(t, 3, p.Agents, "the server is the first of the 4 nodes")
	assert.Contains(t, p.Packages, "wireguard-tools")
	assert.False(t, p.Tuned)

	var hooks []string
	for _, step := range s.Hooks.PostInstall {
		hooks = append(hooks, step.Name)
	}
	assert.Contains(t, hooks, "octelium/gateway-hosts")

	single, err := Get("k3s-flannel")
	require.NoError(t, err)
	assert.Greater(t, s.Install.WaitTimeout, single.Install.WaitTimeout)
}

func TestBuildChaos(t *testing.T) {
	withCustomizers(t)

	s, err := Get("k3s-flannel-chaos")
	require.NoError(t, err)

	assert.True(t, s.Caps.Has(CapChaos))
	assert.False(t, s.Caps.Has(CapMultiNode))
	assert.Equal(t, 1, s.Topology.Nodes)

	p, ok := s.Provisioner.(*K3s)
	require.True(t, ok)
	assert.True(t, p.Tuned)
	assert.Zero(t, p.Agents)
	assert.Contains(t, p.ServerArgs, "--kube-proxy-arg=conntrack-max-per-core=0",
		"kube-proxy must leave the tuned conntrack table alone")

	base, err := Get("k3s-flannel")
	require.NoError(t, err)

	baseP := base.Provisioner.(*K3s)
	assert.False(t, baseP.Tuned, "the base scenario must not be tuned")
	assert.NotContains(t, baseP.ServerArgs, "--kube-proxy-arg=conntrack-max-per-core=0")
}

func TestK3sProvisionScheduleForAgents(t *testing.T) {
	stepsOf := func(p *K3s) ([]string, map[string]Step) {
		var names []string
		ret := map[string]Step{}
		for _, step := range p.provisionSteps() {
			names = append(names, step.Name)
			ret[step.Name] = step
		}
		return names, ret
	}

	t.Run("the agents join after the server is Ready", func(t *testing.T) {
		p := k3sProvisioner(CNIFlannel)
		p.withAgents(3)

		names, steps := stepsOf(p)

		start := slices.Index(names, "k3s/start")
		serverReady := slices.Index(names, "k3s/server-ready")
		network := slices.Index(names, "agents/network")
		mirrors := slices.Index(names, "agents/mirrors")
		agents := slices.Index(names, "agents/start")
		registered := slices.Index(names, "k3s/nodes-registered")
		labels := slices.Index(names, "k3s/node-labels")

		for _, idx := range []int{start, serverReady, network, mirrors, agents, registered, labels} {
			require.NotEqual(t, -1, idx)
		}

		assert.Less(t, start, serverReady)
		assert.Less(t, serverReady, network)
		assert.Less(t, network, mirrors)
		assert.Less(t, mirrors, agents)
		assert.Less(t, agents, registered)
		assert.Less(t, registered, labels)

		for _, name := range []string{"k3s/server-ready", "agents/network", "agents/mirrors", "agents/start"} {
			assert.False(t, steps[name].Skip(nil), name)
		}
		assert.True(t, steps["host/tuning"].Skip(nil))
	})

	t.Run("a single node skips the agent steps", func(t *testing.T) {
		p := k3sProvisioner(CNIFlannel)

		_, steps := stepsOf(p)
		for _, name := range []string{"k3s/server-ready", "agents/network", "agents/mirrors", "agents/start"} {
			assert.True(t, steps[name].Skip(nil), name)
		}
	})

	t.Run("tuning runs after the packages are installed", func(t *testing.T) {
		p := k3sProvisioner(CNIFlannel)
		p.tune()

		names, steps := stepsOf(p)
		assert.False(t, steps["host/tuning"].Skip(nil))
		assert.Less(t, slices.Index(names, "host/packages"), slices.Index(names, "host/tuning"))
		assert.Less(t, slices.Index(names, "host/tuning"), slices.Index(names, "k3s/start"),
			"docker is restarted by the tuning, so it must happen before k3s starts")
	})
}

func TestRegistriesYAML(t *testing.T) {
	got := registriesYAML()

	for _, m := range registryMirrors {
		assert.Contains(t, got, "  "+m.registry+":\n")
		assert.Contains(t, got, "http://"+m.ip+":5000")
	}
}

func TestGatewayHostsScript(t *testing.T) {
	gw := func(name, hostname string, ips ...string) *corev1.Gateway {
		return &corev1.Gateway{
			Metadata: &metav1.Metadata{Name: name},
			Status: &corev1.Gateway_Status{
				Hostname:  hostname,
				PublicIPs: ips,
			},
		}
	}

	t.Run("one line per Gateway on its first public address", func(t *testing.T) {
		got, err := gatewayHostsScript([]*corev1.Gateway{
			gw("gw-1", "octelium-gw-abc.localhost", "10.0.0.4"),
			gw("gw-2", "octelium-gw-def.localhost", "172.29.128.2", "172.29.128.3"),
		})
		require.NoError(t, err)

		assert.True(t, strings.HasPrefix(got, "sudo sed -i '/# octelium-e2e-gateway$/d' /etc/hosts"),
			"the previous entries are removed first so that reinstalling does not stack them")
		assert.Contains(t, got, "'10.0.0.4 octelium-gw-abc.localhost # octelium-e2e-gateway'")
		assert.Contains(t, got, "'172.29.128.2 octelium-gw-def.localhost # octelium-e2e-gateway'")
		assert.NotContains(t, got, "172.29.128.3")
	})

	t.Run("a Gateway that is not ready yet fails the step", func(t *testing.T) {
		_, err := gatewayHostsScript([]*corev1.Gateway{gw("gw-1", "", "10.0.0.4")})
		require.Error(t, err)

		_, err = gatewayHostsScript([]*corev1.Gateway{gw("gw-1", "octelium-gw-abc.localhost")})
		require.Error(t, err)
	})
}

func TestNodePublicIP(t *testing.T) {
	server := node("server", "True", "", "")
	server.Labels = map[string]string{"node-role.kubernetes.io/control-plane": "true"}
	server.Status.Addresses = []k8scorev1.NodeAddress{
		{Type: "InternalIP", Address: "10.1.0.5"},
	}

	agent := node(AgentName(1), "True", "", "")
	agent.Status.Addresses = []k8scorev1.NodeAddress{
		{Type: "Hostname", Address: AgentName(1)},
		{Type: "InternalIP", Address: "fd00::5"},
		{Type: "InternalIP", Address: "172.29.128.2"},
	}

	assert.Equal(t, "203.0.113.10", nodePublicIP(server, "203.0.113.10"),
		"the server publishes the host address")
	assert.Equal(t, "172.29.128.2", nodePublicIP(agent, "203.0.113.10"),
		"an agent publishes its own container address")

	bare := node(AgentName(2), "True", "", "")
	assert.Empty(t, nodePublicIP(bare, "203.0.113.10"))

	assert.True(t, IsAgentNode(AgentName(7)))
	assert.False(t, IsAgentNode("fv-az123-456"))
}
