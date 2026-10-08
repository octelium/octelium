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

package suite

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const maxIsolationNodes = 4

var criticalOwners = []string{
	"svc/default.octelium-api",
	"svc/auth.octelium-api",
	"svc/dns.octelium",
	"svc/default.default",
	"component/ingress-dataplane",
	"component/ingress",
	"component/rscserver",
	"component/octovigil",
	"component/nocturne",
}

func gatewayPrefixes(gw *corev1.Gateway) []netip.Prefix {
	var ret []netip.Prefix
	for _, s := range []string{gw.GetStatus().GetCidr().GetV4(), gw.GetStatus().GetCidr().GetV6()} {
		if pfx, err := netip.ParsePrefix(s); err == nil {
			ret = append(ret, pfx)
		}
	}
	return ret
}

func dataPlaneNodes(t *testing.T, h *harness.H) []k8scorev1.Node {
	t.Helper()

	nodes, err := h.K8sC().CoreV1().Nodes().List(t.Context(), k8smetav1.ListOptions{
		LabelSelector: vutils.NodeLabelDataPlane,
	})
	require.NoError(t, err)
	return nodes.Items
}

func testMultiNodeGateways(t *testing.T, h *harness.H) {
	h.Require(t, capMultiNode)

	nodes := dataPlaneNodes(t, h)
	gws := h.Gateways(t)

	require.Len(t, gws, len(nodes), "every data-plane node must run exactly one Gateway")

	byNode := map[string]*corev1.Gateway{}
	ids := map[string]bool{}
	var prefixes []netip.Prefix

	for _, gw := range gws {
		node := gw.GetStatus().GetNodeRef().GetName()
		require.NotEmpty(t, node)
		require.Nil(t, byNode[node], "the node %s runs more than one Gateway", node)
		byNode[node] = gw

		assert.False(t, ids[gw.Status.Id], "the Gateway ID %s is not unique", gw.Status.Id)
		ids[gw.Status.Id] = true

		for _, pfx := range gatewayPrefixes(gw) {
			for _, other := range prefixes {
				assert.False(t, pfx.Overlaps(other),
					"the Gateway CIDR %s overlaps %s", pfx, other)
			}
			prefixes = append(prefixes, pfx)
		}
	}

	t.Run("PublicAddresses", func(t *testing.T) {
		for _, node := range nodes {
			gw := byNode[node.Name]
			require.NotNil(t, gw, "the node %s runs no Gateway", node.Name)

			want := node.Annotations["octelium.com/public-ip-test"]
			assert.Equal(t, []string{want}, gw.Status.PublicIPs,
				"the Gateway of %s must publish its own node address", node.Name)

			addrs, err := net.LookupHost(gw.Status.Hostname)
			if assert.NoError(t, err, "the Gateway hostname %s must resolve", gw.Status.Hostname) {
				assert.Contains(t, addrs, want,
					"the Gateway hostname %s must resolve to its own node", gw.Status.Hostname)
			}
		}
	})

	t.Run("Routing", func(t *testing.T) {
		testMultiNodeRouting(t, h, byNode)
	})
}

func multiNodeTarget(t *testing.T, h *harness.H, replicas int) (*chaosTarget, []targetAddr) {
	t.Helper()

	e := &chaosEnv{h: h, ipv6: h.Scenario.Caps.Has(capIPv6), report: &chaosReport{
		Phases: map[string]map[string]any{},
	}}
	t.Cleanup(func() {
		for i := len(e.closers) - 1; i >= 0; i-- {
			e.closers[i]()
		}
	})

	target := e.ensureTarget(t)
	require.GreaterOrEqual(t, len(target.addrs), replicas)

	gwSeen := map[string]bool{}
	var spread []targetAddr
	for _, a := range target.addrs {
		if a.addr.Is4() && !gwSeen[a.gateway] {
			gwSeen[a.gateway] = true
			spread = append(spread, a)
		}
	}

	return target, spread
}

func peerHandshakes(t *testing.T, h *harness.H, gws map[string]*corev1.Gateway, pub string) map[string]bool {
	t.Helper()

	ret := map[string]bool{}
	for _, gw := range gws {
		peers, err := h.GatewayWGPeers(t.Context(), gw)
		require.NoError(t, err)

		for _, peer := range peers {
			if peer.PublicKey == pub {
				ret[gw.Status.Id] = !peer.LatestHandshake.IsZero() || peer.RxBytes > 0
			}
		}
	}
	return ret
}

func testMultiNodeRouting(t *testing.T, h *harness.H, byNode map[string]*corev1.Gateway) {
	target, spread := multiNodeTarget(t, h, len(byNode))

	if len(spread) < 2 {
		t.Logf("The %d replicas of the target Service were all scheduled behind %d Gateway(s)",
			len(target.addrs), len(spread))
	}

	for _, a := range target.addrs {
		gw := byNode[a.node]
		require.NotNil(t, gw)

		inside := slices.ContainsFunc(gatewayPrefixes(gw), func(p netip.Prefix) bool { return p.Contains(a.addr) })
		assert.True(t, inside, "the Service address %s of the pod %s is outside of the CIDR of its node Gateway %s",
			a.addr, a.pod, gw.Status.Id)
	}

	inspect := h.CanInspectWireGuard(t.Context()) == nil

	fleet, err := h.NewFleet(t.Context(), harness.FleetOpts{Sessions: maxIsolationNodes + 1, Users: 1})
	require.NoError(t, err)
	t.Cleanup(func() { fleet.Close(context.Background()) })

	dialer, err := h.IngressDialer(h.APIServerName())
	require.NoError(t, err)
	pool := harness.NewVConnPool(dialer, 1)
	t.Cleanup(pool.Close)

	e := &chaosEnv{h: h, report: &chaosReport{Phases: map[string]map[string]any{}}}

	connect := func(t *testing.T, sess *harness.FleetSession,
		tunnel userv1.ConnectRequest_Initialize_ConnectionType) *chaosSample {
		t.Helper()

		c := harness.NewVClient(sess, pool, harness.VClientOpts{
			Tunnel: tunnel,
			L3Mode: userv1.ConnectRequest_Initialize_V4,
		})

		ctx, cancel := context.WithTimeout(t.Context(), 2*harness.VClientInitBudget)
		defer cancel()

		_, err := connectWithRetry(ctx, c, 5)
		require.NoError(t, err)
		t.Cleanup(func() { c.Disconnect(context.Background()) })

		s, err := e.newSample(t, c, harness.DataPlaneOpts{})
		require.NoError(t, err)
		t.Cleanup(s.dp.Close)

		return s
	}

	tunnels := []userv1.ConnectRequest_Initialize_ConnectionType{userv1.ConnectRequest_Initialize_WIREGUARD}
	if h.Scenario.Caps.Has(capQUICv0) {
		tunnels = append(tunnels, userv1.ConnectRequest_Initialize_QUICV0)
	}

	t.Run("ClientSide", func(t *testing.T) {
		for i, tunnel := range tunnels {
			t.Run(wantTunnel(tunnel).String(), func(t *testing.T) {
				s := connect(t, fleet.Sessions[i], tunnel)

				for _, a := range spread {
					h.Eventually(t, fmt.Sprintf("the Service behind %s to answer", a.gateway),
						harness.DecisionBudget, func(ctx context.Context) error {
							return e.sampleGet(ctx, target, s, a, nextRequestID("mn"))
						})

					beforeStats, err := s.dp.Stats()
					require.NoError(t, err)

					for range 3 {
						require.NoError(t, e.sampleGet(t.Context(), target, s, a, nextRequestID("mn")))
					}

					afterStats, err := s.dp.Stats()
					require.NoError(t, err)

					assert.Equal(t, a.gateway, harness.DominantGateway(harness.StatsDelta(beforeStats, afterStats)),
						"the traffic to %s must go through the Gateway of %s", a.addr, a.node)
				}
			})
		}
	})

	t.Run("ServerSide", func(t *testing.T) {
		if !inspect {
			t.Skip("wireguard-tools are not usable on this host")
		}

		gws := map[string]*corev1.Gateway{}
		for _, gw := range byNode {
			gws[gw.Status.Id] = gw
		}

		for i, a := range firstN(spread, maxIsolationNodes) {
			t.Run(a.node, func(t *testing.T) {
				s := connect(t, fleet.Sessions[len(tunnels)+i], userv1.ConnectRequest_Initialize_WIREGUARD)

				pub, err := s.vc.X25519PublicKey()
				require.NoError(t, err)
				key := base64.StdEncoding.EncodeToString(pub)

				h.Eventually(t, "the Service to answer through its own Gateway", harness.DecisionBudget,
					func(ctx context.Context) error {
						return e.sampleGet(ctx, target, s, a, nextRequestID("mn-iso"))
					})

				got := peerHandshakes(t, h, gws, key)

				assert.True(t, got[a.gateway],
					"the Gateway %s serving %s has no handshake with the client", a.gateway, a.addr)

				for id, ok := range got {
					if id != a.gateway {
						assert.False(t, ok,
							"the Gateway %s saw traffic that was only sent to the Service behind %s", id, a.gateway)
					}
				}

				assert.Len(t, got, len(gws), "every Gateway must hold a peer for the connected client")
			})
		}
	})
}

func (e *chaosEnv) safeAgentNode(t *testing.T) (string, error) {
	t.Helper()

	pods, err := e.h.K8sC().CoreV1().Pods(vutils.K8sNS).List(t.Context(), k8smetav1.ListOptions{})
	if err != nil {
		return "", err
	}

	unsafe := map[string]bool{}
	for i := range pods.Items {
		if slices.Contains(criticalOwners, harness.PodOwner(&pods.Items[i])) {
			unsafe[pods.Items[i].Spec.NodeName] = true
		}
	}

	target := e.ensureTarget(t)

	for _, a := range target.addrs {
		if scenario.IsAgentNode(a.node) && !unsafe[a.node] {
			return a.node, nil
		}
	}

	return "", errors.Errorf("every agent node hosting the target Service also hosts a critical component")
}

func (e *chaosEnv) restartGatewayAgentOn(t *testing.T, node string) time.Duration {
	t.Helper()

	h := e.h

	pods, err := h.ComponentPods(t.Context(), "gwagent")
	require.NoError(t, err)

	var victim string
	for _, pod := range pods {
		if pod.Spec.NodeName == node {
			victim = pod.Name
		}
	}
	require.NotEmpty(t, victim, "no Gateway Agent runs on %s", node)

	started := time.Now()
	require.NoError(t, h.K8sC().CoreV1().Pods(vutils.K8sNS).Delete(t.Context(), victim, k8smetav1.DeleteOptions{}))

	h.Eventually(t, "the Gateway Agent of "+node+" to be replaced", harness.DeploymentBudget,
		func(ctx context.Context) error {
			pods, err := h.ComponentPods(ctx, "gwagent")
			if err != nil {
				return err
			}
			for _, pod := range pods {
				if pod.Spec.NodeName != node || pod.Name == victim {
					continue
				}
				for _, cs := range pod.Status.ContainerStatuses {
					if !cs.Ready {
						return errors.Errorf("the new Gateway Agent pod %s is not ready", pod.Name)
					}
				}
				if pod.Status.Phase == k8scorev1.PodRunning {
					return nil
				}
			}
			return errors.Errorf("the Gateway Agent of %s has not been replaced yet", node)
		})

	return time.Since(started)
}

func (e *chaosEnv) watchOthers(ctx context.Context, target *chaosTarget, skipGateway string,
	out *probeStats) {
	e.mu.Lock()
	samples := e.samples
	e.mu.Unlock()

	var others []targetAddr
	for _, a := range target.addrs {
		if a.gateway != skipGateway {
			others = append(others, a)
		}
	}
	if len(others) == 0 {
		return
	}

	for ctx.Err() == nil {
		var wg sync.WaitGroup
		for _, s := range samples {
			for _, v6 := range modeFamilies(s.vc.Opts().L3Mode) {
				for _, a := range firstN(rotate(others, s.idx), sampleTargets) {
					if a.addr.Is6() != v6 {
						continue
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						started := time.Now()
						err := e.sampleGet(ctx, target, s, a, nextRequestID("isolation"))
						if ctx.Err() != nil {
							return
						}
						if err != nil {
							out.errs.Add(errors.Wrapf(err, "%s to %s behind %s", s.name(), a.addr, a.gateway))
							return
						}
						out.lat.Add(time.Since(started))
					}()
				}
			}
		}
		wg.Wait()
		harness.Sleep(ctx, 2*time.Second)
	}
}

func rotate[T any](vals []T, by int) []T {
	if len(vals) == 0 {
		return vals
	}
	by %= len(vals)
	return append(slices.Clone(vals[by:]), vals[:by]...)
}

func testChaosMultiNode(t *testing.T, e *chaosEnv) {
	e.h.Require(t, capMultiNode)

	population := e.ensurePopulation(t)
	target := e.ensureTarget(t)
	h := e.h

	t.Run("Placement", func(t *testing.T) {
		gws := target.gateways()
		e.set(t, "gatewaysHostingTheTarget", len(gws))
		e.set(t, "gateways", h.Scenario.Topology.Nodes)

		if len(gws) < min(2, h.Scenario.Topology.Nodes) {
			e.failf(t, "The %d replicas of the target Service all run behind %d Gateway(s)",
				len(target.addrs), len(gws))
		}
	})

	t.Run("GatewayAgentIsolation", func(t *testing.T) {
		node, err := e.safeAgentNode(t)
		if err != nil {
			t.Skipf("%+v", err)
		}

		byNode, err := e.gatewayByNode(t.Context())
		require.NoError(t, err)
		gw := byNode[node]
		require.NotNil(t, gw)

		keysBefore := gatewayKeys(t, e)
		since := time.Now()
		before := e.healthSnapshot(t)

		ctx, cancel := context.WithCancel(t.Context())
		others := newProbeStats()
		done := make(chan struct{})
		go func() { defer close(done); e.watchOthers(ctx, target, gw.Status.Id, others) }()

		replaced := e.restartGatewayAgentOn(t, node)
		e.markRestarted("component/gwagent")
		e.set(t, "replaced", replaced.String())

		var keysAfter map[string]string
		h.Eventually(t, "the restarted Gateway to rotate its key", 3*time.Minute,
			func(ctx context.Context) error {
				keysAfter = gatewayKeys(t, e)
				if keysAfter[gw.Status.Id] == keysBefore[gw.Status.Id] {
					return errors.Errorf("the Gateway %s still publishes its previous key", gw.Status.Id)
				}
				return nil
			})

		for id, key := range keysAfter {
			if id != gw.Status.Id && key != keysBefore[id] {
				e.failf(t, "Restarting the Gateway Agent of %s rotated the key of the Gateway %s too", node, id)
			}
		}

		e.waitGatewayKeys(t, population, keysAfter, since, scaled(time.Minute, 10*time.Millisecond, len(population)))

		recovered := e.waitSamples(t, "the tunnels to the restarted Gateway to recover", 3*time.Minute)
		e.set(t, "recovered", recovered.String())

		cancel()
		<-done
		others.assert(t, e, "otherGateways", 10*time.Second)

		e.assertNoDrops(t, "while one Gateway Agent was replaced", population, since)
		e.assertHealthy(t, before, "component/gwagent")
	})

	t.Run("NodePartition", func(t *testing.T) {
		node, err := e.safeAgentNode(t)
		if err != nil {
			t.Skipf("%+v", err)
		}

		byNode, err := e.gatewayByNode(t.Context())
		require.NoError(t, err)
		gw := byNode[node]
		require.NotNil(t, gw)

		const partition = 30 * time.Second

		since := time.Now()

		ctx, cancel := context.WithCancel(t.Context())
		others := newProbeStats()
		done := make(chan struct{})
		go func() { defer close(done); e.watchOthers(ctx, target, gw.Status.Id, others) }()

		h.MustRun(t, fmt.Sprintf("sudo -n docker pause %s", node))
		paused := true
		t.Cleanup(func() {
			if paused {
				h.Run(context.Background(), fmt.Sprintf("sudo -n docker unpause %s", node))
			}
		})

		harness.Sleep(t.Context(), partition)

		h.MustRun(t, fmt.Sprintf("sudo -n docker unpause %s", node))
		paused = false

		recovered := e.waitSamples(t, "the tunnels to the partitioned node to recover", 5*time.Minute)
		e.set(t, "recovered", recovered.String())

		cancel()
		<-done
		others.assert(t, e, "otherGateways", 10*time.Second)

		e.assertNoDrops(t, "while a data-plane node was partitioned", population, since)

		zap.L().Info("Node partition",
			zap.String("node", node), zap.Duration("partition", partition),
			zap.Duration("recovered", recovered))
	})
}
