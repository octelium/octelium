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
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func publishedAddrs(t *testing.T, h *harness.H, name string) []string {
	t.Helper()

	svc, err := h.CoreC().GetService(t.Context(), &metav1.GetOptions{Name: name})
	require.NoError(t, err)

	var ret []string
	for _, addr := range svc.GetStatus().GetAddresses() {
		for _, s := range []string{addr.GetDualStackIP().GetIpv4(), addr.GetDualStackIP().GetIpv6()} {
			if s != "" {
				ret = append(ret, s)
			}
		}
	}
	slices.Sort(ret)
	return ret
}

func eventLatencies(clients []*harness.VClient, name string, since, origin time.Time) (*harness.Latencies, []*harness.VClient) {
	lat := &harness.Latencies{}
	var missing []*harness.VClient

	for _, c := range clients {
		at, _ := c.LastEvent(name)
		if at.Before(since) {
			missing = append(missing, c)
			continue
		}
		lat.Add(max(0, at.Sub(origin)))
	}

	return lat, missing
}

func testChaosDNSBroadcast(t *testing.T, e *chaosEnv) {
	const dnsService = "dns.octelium"

	population := e.ensurePopulation(t)
	h := e.h

	before := e.healthSnapshot(t)
	since := time.Now()

	addrsBefore := publishedAddrs(t, h, dnsService)

	replaced := h.RestartService(t, dnsService)
	e.markRestarted("svc/" + dnsService)

	var addrsAfter []string
	err := h.EventuallyErr(t.Context(), "the DNS Service to publish new addresses", 2*time.Minute,
		func(ctx context.Context) error {
			addrsAfter = publishedAddrs(t, h, dnsService)
			if len(addrsAfter) == 0 || slices.Equal(addrsAfter, addrsBefore) {
				return errors.Errorf("the DNS Service still publishes %v", addrsAfter)
			}
			return nil
		})
	if err != nil {
		t.Skipf("The replaced DNS pod kept its address %v, so no DNS update is broadcast", addrsBefore)
	}
	changedAt := time.Now()

	budget := scaled(time.Minute, 10*time.Millisecond, len(population))

	var missing []*harness.VClient
	var lat *harness.Latencies
	err = h.EventuallyErr(t.Context(), "every connected client to receive the new DNS servers", budget,
		func(ctx context.Context) error {
			lat, missing = eventLatencies(population, harness.EventUpdateDNS, since, changedAt)
			if len(missing) > 0 {
				return errors.Errorf("%d of %d clients have not received the DNS update",
					len(missing), len(population))
			}
			return nil
		})

	e.set(t, "replaced", replaced.String())
	e.set(t, "addresses", map[string][]string{"before": addrsBefore, "after": addrsAfter})
	e.set(t, "fanout", lat.Summary())
	e.set(t, "missing", len(missing))

	if err != nil {
		e.failf(t, "%d of %d connected clients never received the DNS update within %s",
			len(missing), len(population), budget)
	}

	t.Run("PerFamily", func(t *testing.T) {
		var wrong []string
		for _, c := range population {
			_, msg := c.LastEvent(harness.EventUpdateDNS)
			if msg == nil {
				continue
			}

			mode := wantL3Mode(c.Opts().L3Mode)
			if !dnsMatchesMode(msg.GetUpdateDNS().GetDns().GetServers(), mode) {
				wrong = append(wrong, mode.String())
			}
		}

		e.set(t, "mismatched", len(wrong))
		if len(wrong) > 0 {
			e.failf(t, "%d single-stack clients received DNS servers of a family they cannot reach "+
				"(the initial state is filtered by the L3 mode but the broadcast is not), e.g. %v",
				len(wrong), firstN(wrong, 3))
		}
	})

	e.assertNoDrops(t, "while the DNS Service was replaced", population, since)
	e.assertHealthy(t, before, "svc/"+dnsService)
}

func gatewayKeys(t *testing.T, e *chaosEnv) map[string]string {
	t.Helper()

	gws, err := e.h.ListGateways(t.Context())
	require.NoError(t, err)

	ret := map[string]string{}
	for _, gw := range gws {
		ret[gw.GetStatus().GetId()] = gw.GetStatus().GetWireguard().GetPublicKey()
	}
	return ret
}

func clientKnowsKeys(c *harness.VClient, keys map[string]string) bool {
	got := map[string]string{}
	for _, gw := range c.Gateways() {
		got[gw.Id] = gw.GetWireguard().GetPublicKey()
	}

	for id, key := range keys {
		if got[id] != key {
			return false
		}
	}
	return true
}

func (e *chaosEnv) waitGatewayKeys(t *testing.T, clients []*harness.VClient, keys map[string]string,
	since time.Time, budget time.Duration) {
	t.Helper()

	var stale int
	err := e.h.EventuallyErr(t.Context(), "every client to learn the new Gateway keys", budget,
		func(ctx context.Context) error {
			stale = 0
			for _, c := range clients {
				if !clientKnowsKeys(c, keys) {
					stale++
				}
			}
			if stale > 0 {
				return errors.Errorf("%d of %d clients still use a stale Gateway key", stale, len(clients))
			}
			return nil
		})

	lat, _ := eventLatencies(clients, harness.EventUpdateGateway, since, since)
	e.set(t, "updateGatewayFanout", lat.Summary())

	if err != nil {
		e.failf(t, "%d of %d connected clients never learned the rotated Gateway keys within %s",
			stale, len(clients), budget)
	}
}

func testChaosGatewayAgentRestart(t *testing.T, e *chaosEnv) {
	population := e.ensurePopulation(t)
	h := e.h

	before := e.healthSnapshot(t)
	since := time.Now()

	keysBefore := gatewayKeys(t, e)

	replaced := h.RestartComponent(t, "gwagent")
	e.markRestarted("component/gwagent")
	e.set(t, "replaced", replaced.String())

	var keysAfter map[string]string
	h.Eventually(t, "every Gateway to publish its new WireGuard key", 3*time.Minute,
		func(ctx context.Context) error {
			keysAfter = gatewayKeys(t, e)
			for id, key := range keysAfter {
				if key == keysBefore[id] {
					return errors.Errorf("the Gateway %s still publishes its previous key", id)
				}
			}
			return nil
		})

	e.waitGatewayKeys(t, population, keysAfter, since, scaled(time.Minute, 10*time.Millisecond, len(population)))

	e.checkInvariants(t, "after every Gateway Agent was replaced",
		scaled(2*time.Minute, 20*time.Millisecond, len(population)),
		invariantsOpts{connected: population})

	recovered := e.waitSamples(t, "the sample tunnels to recover after the Gateway Agent restart", 3*time.Minute)
	e.set(t, "dataPlaneRecovered", recovered.String())

	e.assertNoDrops(t, "while the Gateway Agents were replaced", population, since)
	e.assertHealthy(t, before, "component/gwagent")
	e.logUsage(t)
}

func reconnectLatencies(clients []*harness.VClient, since time.Time) (*harness.Latencies, int) {
	lat := &harness.Latencies{}
	var dropped int

	for _, c := range clients {
		down := c.DroppedAt()
		if down.Before(since) {
			continue
		}
		dropped++
		if up := c.ConnectedAt(); up.After(down) {
			lat.Add(up.Sub(down))
		}
	}

	return lat, dropped
}

func (e *chaosEnv) testReconnectStorm(t *testing.T, what string, restart func() time.Duration, owner string) {
	t.Helper()

	population := e.ensurePopulation(t)

	before := e.healthSnapshot(t)
	since := time.Now()

	replaced := restart()
	e.markRestarted(owner)
	e.set(t, "replaced", replaced.String())

	budget := scaled(5*time.Minute, 50*time.Millisecond, len(population))
	recovered := e.waitConnected(t, "the population to reconnect "+what, population, budget)

	lat, dropped := reconnectLatencies(population, since)
	e.set(t, "recovered", recovered.String())
	e.set(t, "dropped", dropped)
	e.set(t, "reconnectLatency", lat.Summary())

	errs := harness.NewErrorCounter()
	for _, c := range population {
		if c.DroppedAt().After(since) {
			if err := c.StreamErr(); err != nil {
				errs.Add(err)
			}
		}
	}
	e.set(t, "streamErrors", errs.Classes())

	zap.L().Info("Reconnect storm",
		zap.String("what", what), zap.Int("dropped", dropped),
		zap.Duration("recovered", recovered), zap.String("reconnect", lat.Summary().String()))

	e.checkInvariants(t, "after the reconnect storm "+what,
		scaled(3*time.Minute, 20*time.Millisecond, len(population)),
		invariantsOpts{connected: population})

	e.rebuildSamples(t)
	recoveredDP := e.waitSamples(t, "the sample tunnels to recover "+what, 3*time.Minute)
	e.set(t, "dataPlaneRecovered", recoveredDP.String())

	e.assertHealthy(t, before, owner)
	e.logUsage(t)
}

func testChaosAPIServerRestart(t *testing.T, e *chaosEnv) {
	const apiService = "default.octelium-api"

	e.testReconnectStorm(t, "after the API Server was replaced", func() time.Duration {
		return e.h.RestartService(t, apiService)
	}, "svc/"+apiService)
}

func testChaosComponentRestarts(t *testing.T, e *chaosEnv) {
	population := e.ensurePopulation(t)

	for _, tc := range []struct {
		name      string
		component string
		drops     bool
	}{
		{name: "RscServer", component: "rscserver"},
		{name: "Octovigil", component: "octovigil"},
		{name: "Nocturne", component: "nocturne"},
		{name: "IngressControlPlane", component: "ingress"},
		{name: "IngressDataPlane", component: "ingress-dataplane", drops: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := "component/" + tc.component

			if tc.drops {
				e.testReconnectStorm(t, "after the "+tc.component+" was replaced", func() time.Duration {
					return e.h.RestartComponent(t, tc.component)
				}, owner)
				return
			}

			before := e.healthSnapshot(t)
			since := time.Now()

			replaced := e.h.RestartComponent(t, tc.component)
			e.markRestarted(owner)
			e.set(t, "replaced", replaced.String())

			probes := e.takeSpare(t, 3)

			recovered := e.h.Within(t, "a new client to connect after the restart", 3*time.Minute,
				func(ctx context.Context) error {
					var wg sync.WaitGroup
					errs := make([]error, len(probes))
					for i, sess := range probes {
						wg.Add(1)
						go func() {
							defer wg.Done()
							c := harness.NewVClient(sess, e.dedicated, e.clientOpts(i))
							if err := c.Connect(ctx); err != nil {
								errs[i] = err
								return
							}
							c.Disconnect(context.Background())
						}()
					}
					wg.Wait()
					for _, err := range errs {
						if err != nil {
							return err
						}
					}
					return nil
				})
			e.set(t, "newClientsRecovered", recovered.String())

			dpRecovered := e.waitSamples(t, "the sample tunnels to work after the restart", 3*time.Minute)
			e.set(t, "dataPlaneRecovered", dpRecovered.String())

			harness.Sleep(t.Context(), 20*time.Second)
			e.assertNoDrops(t, "while the "+tc.component+" was replaced", population, since)

			e.checkInvariants(t, "after the "+tc.component+" was replaced", 2*time.Minute,
				invariantsOpts{connected: population, disconnected: probes})

			e.assertHealthy(t, before, owner)
		})
	}
}
