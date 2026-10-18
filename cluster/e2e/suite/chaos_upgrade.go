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
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testChaosClusterUpgrade(t *testing.T, e *chaosEnv) {
	population := e.ensurePopulation(t)
	h := e.h

	fleet, err := h.NewFleet(t.Context(), harness.FleetOpts{
		Sessions: upgradeFleetSessions,
		Users:    upgradeFleetUsers,
	})
	require.NoError(t, err)
	t.Cleanup(func() { fleet.Close(context.Background()) })

	dialer, err := h.IngressDialer(h.APIServerName())
	require.NoError(t, err)

	conn, err := dialer.GRPCConn()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	before := e.healthSnapshot(t)
	since := time.Now()

	probe := startSessionProbe(conn, e.dedicated, fleet.Sessions, fleet.Sessions[:upgradeChurnClients])
	defer probe.stop()

	upgraded := h.UpgradeCluster(t)
	e.set(t, "upgraded", upgraded.String())

	budget := scaled(5*time.Minute, 50*time.Millisecond, len(population))
	recovered := e.waitConnected(t, "the population to reconnect after the Cluster upgrade", population, budget)

	lat, dropped := reconnectLatencies(population, since)
	e.set(t, "recovered", recovered.String())
	e.set(t, "dropped", dropped)
	e.set(t, "reconnectLatency", lat.Summary())

	rejected := e.superErrs.rejectedSince(since)
	e.set(t, "rejectedReconnects", rejected.Classes())
	if rejected.Total() > 0 {
		e.failf(t, "%d reconnect attempts of the population were rejected during the Cluster upgrade, "+
			"a real client exits on such errors: %s", rejected.Total(), rejected)
	}

	e.checkInvariants(t, "after the Cluster upgrade",
		scaled(3*time.Minute, 20*time.Millisecond, len(population)),
		invariantsOpts{connected: population})

	e.rebuildSamples(t)
	recoveredDP := e.waitSamples(t, "the sample tunnels to recover after the Cluster upgrade", 3*time.Minute)
	e.set(t, "dataPlaneRecovered", recoveredDP.String())

	require.NoError(t, harness.Sleep(t.Context(), upgradeSettle))
	probe.stop()

	e.set(t, "probeRequests", probe.requests.Load())
	e.set(t, "probeConnects", probe.connects.Load())
	e.set(t, "probeErrors", probe.errs.Classes())

	zap.L().Info("Population recovered from the Cluster upgrade",
		zap.Duration("upgraded", upgraded), zap.Duration("recovered", recovered),
		zap.Int("dropped", dropped), zap.String("reconnect", lat.Summary().String()))

	if n := probe.rejected.Total(); n > 0 {
		e.failf(t, "%d of %d API requests and Connect attempts of valid Sessions were rejected "+
			"during the Cluster upgrade: %s", n, probe.requests.Load()+probe.connects.Load(), probe.rejected)
	}

	e.assertHealthy(t, before)
	e.logUsage(t)
}
