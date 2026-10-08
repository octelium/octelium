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
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/metadata"
)

const (
	chaosAPISLO     = 2 * time.Second
	chaosConnectSLO = 15 * time.Second
	chaosStormP95   = 30 * time.Second
)

func testChaosPreflight(t *testing.T, e *chaosEnv) {
	h := e.h

	if !h.Scenario.Caps.Has(capChaos) {
		t.Logf("The scenario %s is not tuned for the chaos suite. Host and container limits "+
			"may be what fails first. Use the %s-chaos scenario to tune them", h.Scenario.ID, h.Scenario.ID)
	}

	cur, err := raiseFDLimit()
	require.NoError(t, err)

	need := e.fdsNeeded()
	soft, hard := fdLimit()
	e.set(t, "scale", e.scale)
	e.set(t, "fdLimit", map[string]uint64{"soft": soft, "hard": hard, "needed": need})
	e.set(t, "ingressAddr", h.IngressAddr())

	if cur < need {
		e.fatalf(t, "The open file limit of the test process is %d but the %s scale needs about %d. "+
			"Raise it with `sudo prlimit --pid $$ --nofile=%d:%d` before running the suite",
			cur, e.scale.Name, need, need*2, need*2)
	}

	if err := h.CanInspectWireGuard(t.Context()); err != nil {
		t.Logf("The Gateway WireGuard peers will not be inspected: %+v", err)
	} else {
		e.wgInspect = true
	}
	e.set(t, "inspectWireGuard", e.wgInspect)

	e.baselineHealth = e.healthSnapshot(t)

	inv, err := h.ConnInventory(t.Context())
	require.NoError(t, err, "the Cluster store must be readable to check the Connection invariants")

	r := harness.CheckConnAddresses(inv)
	e.baselineLeakWG = r.LeakedWG
	e.baselineLeakQUIC = r.LeakedQUIC

	e.set(t, "baseline", r)
	if len(r.LeakedWG)+len(r.LeakedQUIC) > 0 {
		e.report.failure(phaseName(t), fmt.Sprintf(
			"The Cluster already leaks %d WireGuard and %d QUICv0 address indexes before the chaos suite",
			len(r.LeakedWG), len(r.LeakedQUIC)))
		t.Logf("The Cluster already leaks address indexes before the chaos suite starts. "+
			"Only new leaks fail the chaos phases: wg=%v quic=%v",
			firstN(r.LeakedWG, 20), firstN(r.LeakedQUIC, 20))
	}

	for _, v := range r.Violations() {
		if !strings.Contains(v, "(leaked)") {
			e.failf(t, "The Cluster is already inconsistent before the chaos suite: %s", v)
		}
	}

	gws, err := h.ListGateways(t.Context())
	require.NoError(t, err)
	e.set(t, "gateways", len(gws))

	if want := h.Scenario.Topology.Nodes; want > 1 {
		require.Len(t, gws, want, "every data-plane node must run a Gateway")
	}

	zap.L().Info("Chaos preflight",
		zap.String("scale", e.scale.Name), zap.Int("clients", e.scale.Clients),
		zap.Int("spare", e.scale.spare()), zap.Int("gateways", len(gws)),
		zap.Uint64("fdLimit", cur), zap.Uint64("fdNeeded", need),
		zap.String("ingress", h.IngressAddr()), zap.Bool("ipv6", e.ipv6), zap.Bool("quic", e.quic))

	e.logUsage(t)
}

func testChaosFleet(t *testing.T, e *chaosEnv) {
	started := time.Now()
	fleet := e.ensureFleet(t)

	e.set(t, "sessions", len(fleet.Sessions))
	e.set(t, "users", len(fleet.Users))
	e.set(t, "auth", fleet.Auth.String())
	e.set(t, "authLatency", fleet.Auth.Latency.Summary())
	e.set(t, "authRatePerSecond", fleet.Auth.Rate())
	e.set(t, "elapsed", time.Since(started).String())

	t.Run("NoOrphanSessions", func(t *testing.T) {
		inv, err := e.h.ConnInventory(t.Context())
		require.NoError(t, err)

		users := fleet.UserUIDs()

		var got int
		for _, sess := range inv.Sessions {
			if users[sess.GetStatus().GetUserRef().GetUid()] {
				got++
			}
		}

		if got != len(fleet.Sessions) {
			e.failf(t, "The fleet Users own %d Sessions but only %d authentications succeeded. "+
				"A failed or retried authentication left orphan Sessions behind",
				got, len(fleet.Sessions))
		}
	})

	t.Run("CredentialStampede", func(t *testing.T) {
		testChaosCredentialStampede(t, e, fleet)
	})
}

func testChaosCredentialStampede(t *testing.T, e *chaosEnv, fleet *harness.Fleet) {
	h := e.h
	const replicas = 32

	usr := h.CreateUser(t, &corev1.User{
		Spec: &corev1.User_Spec{
			Type:    corev1.User_Spec_WORKLOAD,
			Session: &corev1.User_Spec_Session{MaxPerUser: replicas * 4},
		},
	})

	cred := h.CreateCredential(t, harness.CredentialOpts{
		User:        usr.Metadata.Name,
		Type:        corev1.Credential_Spec_AUTH_TOKEN,
		SessionType: corev1.Session_Status_CLIENT,
	})
	tkn := h.CredentialToken(t, cred).GetAuthenticationToken().GetAuthenticationToken()

	authC := authv1.NewMainServiceClient(fleet.AuthConn())

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := harness.NewErrorCounter()
	var ok atomic.Int32

	for range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()

			if _, err := authC.AuthenticateWithAuthenticationToken(ctx,
				&authv1.AuthenticateWithAuthenticationTokenRequest{AuthenticationToken: tkn}); err != nil {
				errs.Add(err)
				return
			}
			ok.Add(1)
		}()
	}

	close(start)
	wg.Wait()

	sessions := h.UserSessions(t, usr)

	cur, err := h.CoreC().GetCredential(t.Context(), &metav1.GetOptions{Uid: cred.Metadata.Uid})
	require.NoError(t, err)

	e.set(t, "succeeded", ok.Load())
	e.set(t, "errors", errs.Classes())
	e.set(t, "sessions", len(sessions))
	e.set(t, "totalAuthentications", cur.GetStatus().GetTotalAuthentications())

	if int(ok.Load()) != replicas {
		e.failf(t, "Only %d of %d workload replicas sharing one Credential could authenticate at once. %s",
			ok.Load(), replicas, errs)
	}
	if len(sessions) != int(ok.Load()) {
		e.failf(t, "%d Sessions exist for %d successful authentications. "+
			"A failed authentication must not leave its Session behind", len(sessions), ok.Load())
	}
	if int(cur.GetStatus().GetTotalAuthentications()) != len(sessions) {
		e.failf(t, "The Credential counts %d authentications for %d Sessions. "+
			"Concurrent authentications lose updates of the Credential",
			cur.GetStatus().GetTotalAuthentications(), len(sessions))
	}
}

func stateL3Mode(m userv1.ConnectionState_L3Mode) corev1.Session_Status_Connection_L3Mode {
	switch m {
	case userv1.ConnectionState_V4:
		return corev1.Session_Status_Connection_V4
	case userv1.ConnectionState_V6:
		return corev1.Session_Status_Connection_V6
	default:
		return corev1.Session_Status_Connection_BOTH
	}
}

func addrFamilies(addrs []string) (v4, v6 int) {
	for _, s := range addrs {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if addr.Is4() {
			v4++
		} else {
			v6++
		}
	}
	return
}

func dnsMatchesMode(servers []string, mode corev1.Session_Status_Connection_L3Mode) bool {
	v4, v6 := addrFamilies(servers)
	switch mode {
	case corev1.Session_Status_Connection_V4:
		return v6 == 0 && v4 > 0
	case corev1.Session_Status_Connection_V6:
		return v4 == 0 && v6 > 0
	default:
		return v4+v6 > 0
	}
}

func checkClientState(c *harness.VClient, sess *corev1.Session, gwIDs []string) []string {
	var ret []string

	state := c.State()
	conn := sess.GetStatus().GetConnection()
	if state == nil || conn == nil {
		return []string{"connection"}
	}

	want := wantL3Mode(c.Opts().L3Mode)
	if conn.L3Mode != want {
		ret = append(ret, "session-l3mode")
	}
	if stateL3Mode(state.L3Mode) != want {
		ret = append(ret, "state-l3mode")
	}
	if conn.Type != wantTunnel(c.Opts().Tunnel) {
		ret = append(ret, "tunnel")
	}

	if len(state.Addresses) != len(conn.Addresses) {
		ret = append(ret, "addresses")
	} else {
		for i := range state.Addresses {
			if state.Addresses[i].V4 != conn.Addresses[i].V4 || state.Addresses[i].V6 != conn.Addresses[i].V6 {
				ret = append(ret, "addresses")
				break
			}
		}
	}

	if !dnsMatchesMode(state.GetDns().GetServers(), want) {
		ret = append(ret, "dns-family")
	}

	var got []string
	for _, gw := range state.Gateways {
		got = append(got, gw.Id)
	}
	slices.Sort(got)
	if !slices.Equal(got, gwIDs) {
		ret = append(ret, "gateways")
	}

	if state.Mtu <= 0 {
		ret = append(ret, "mtu")
	}

	return ret
}

func (e *chaosEnv) gatewayIDs(t *testing.T) []string {
	t.Helper()

	gws, err := e.h.ListGateways(t.Context())
	require.NoError(t, err)

	var ret []string
	for _, gw := range gws {
		ret = append(ret, gw.GetStatus().GetId())
	}
	slices.Sort(ret)
	return ret
}

func testChaosConnectStorm(t *testing.T, e *chaosEnv) {
	before := e.healthSnapshot(t)

	started := time.Now()
	clients := e.ensurePopulation(t)
	e.set(t, "elapsed", time.Since(started).String())

	t.Run("Latency", func(t *testing.T) {
		var lat harness.Latencies
		for _, c := range clients {
			if at := c.ConnectedAt(); !at.IsZero() {
				lat.Add(at.Sub(started))
			}
		}

		e.set(t, "timeToConnected", lat.Summary())

		e.mu.Lock()
		run := e.popRun
		e.mu.Unlock()

		if run == nil {
			t.Skip("The population was connected by another phase")
		}

		sum := run.Latency.Summary()
		e.set(t, "connectLatency", sum)

		if sum.P95 > chaosStormP95 {
			e.failf(t, "The p95 Connect latency is %s during the storm, the budget is %s (%s)",
				sum.P95, chaosStormP95, sum)
		}
	})

	t.Run("Invariants", func(t *testing.T) {
		e.checkInvariants(t, "after the connect storm",
			scaled(2*time.Minute, 20*time.Millisecond, len(clients)),
			invariantsOpts{connected: clients})
	})

	t.Run("ConnectionState", func(t *testing.T) {
		gwIDs := e.gatewayIDs(t)

		inv, err := e.h.ConnInventory(t.Context())
		require.NoError(t, err)
		byUID := inv.ByUID()

		mismatches := map[string][]string{}
		for _, c := range clients {
			sess := byUID[c.Session.UID]
			if sess == nil {
				mismatches["missing-session"] = append(mismatches["missing-session"], c.Session.UID)
				continue
			}

			for _, kind := range checkClientState(c, sess, gwIDs) {
				mismatches[kind] = append(mismatches[kind], sess.Metadata.Name)
			}
		}

		counts := map[string]int{}
		for kind, names := range mismatches {
			counts[kind] = len(names)
		}
		e.set(t, "mismatches", counts)

		for _, kind := range sortedKeys(mismatches) {
			e.failf(t, "%d clients have a Connection state that does not match their request (%s), e.g. %v",
				len(mismatches[kind]), kind, firstN(mismatches[kind], 5))
		}
	})

	t.Run("Health", func(t *testing.T) {
		e.assertHealthy(t, before)
		e.logUsage(t)
	})
}

type probeStats struct {
	lat  harness.Latencies
	errs *harness.ErrorCounter
}

func newProbeStats() *probeStats { return &probeStats{errs: harness.NewErrorCounter()} }

func (e *chaosEnv) probeAPI(ctx context.Context, every time.Duration, out *probeStats) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		callCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		started := time.Now()
		_, err := e.h.CoreC().ListGateway(callCtx, &corev1.ListGatewayOptions{})
		cancel()

		if ctx.Err() != nil {
			return
		}
		if err != nil {
			out.errs.Add(err)
			continue
		}
		out.lat.Add(time.Since(started))
	}
}

func (e *chaosEnv) probeConnect(ctx context.Context, sessions []*harness.FleetSession,
	every time.Duration, out *probeStats) {
	for i := 0; ctx.Err() == nil; i++ {
		sess := sessions[i%len(sessions)]
		c := harness.NewVClient(sess, e.dedicated, e.clientOpts(i))

		connCtx, cancel := context.WithTimeout(ctx, harness.VClientInitBudget)
		started := time.Now()
		err := c.Connect(connCtx)
		cancel()

		if ctx.Err() != nil {
			c.Drop()
			return
		}

		if err != nil {
			out.errs.Add(err)
		} else {
			out.lat.Add(time.Since(started))
			c.Disconnect(context.Background())
		}

		if harness.Sleep(ctx, every) != nil {
			return
		}
	}
}

func (s *probeStats) assert(t *testing.T, e *chaosEnv, what string, slo time.Duration) {
	t.Helper()

	sum := s.lat.Summary()
	e.set(t, what, sum)
	e.set(t, what+"Errors", s.errs.Classes())

	if s.errs.Total() > 0 {
		e.failf(t, "%d %s probes failed: %s", s.errs.Total(), what, s.errs)
	}
	if sum.Count > 0 && sum.P95 > slo {
		e.failf(t, "The p95 %s latency is %s, the budget is %s (%s)", what, sum.P95, slo, sum)
	}
}

func testChaosSteadyState(t *testing.T, e *chaosEnv) {
	clients := e.ensurePopulation(t)
	probes := e.takeSpare(t, e.scale.Probes)

	before := e.healthSnapshot(t)
	since := time.Now()

	ctx, cancel := context.WithTimeout(t.Context(), e.scale.Hold)
	defer cancel()

	api := newProbeStats()
	conn := newProbeStats()
	dp := newProbeStats()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); e.probeAPI(ctx, 2*time.Second, api) }()
	go func() {
		defer wg.Done()
		e.probeConnect(ctx, probes, max(time.Second, e.scale.Hold/time.Duration(4*len(probes))), conn)
	}()
	go func() { defer wg.Done(); e.probeSamples(ctx, 5*time.Second, dp) }()
	wg.Wait()

	api.assert(t, e, "apiProbe", chaosAPISLO)
	conn.assert(t, e, "connectProbe", chaosConnectSLO)
	dp.assert(t, e, "dataPlaneProbe", chaosAPISLO*5)

	e.assertNoDrops(t, fmt.Sprintf("during the %s steady state", e.scale.Hold), clients, since)

	keepAlives := 0
	if e.scale.KeepAlive > 0 {
		keepAlives = int(float64(len(clients)) * e.scale.Hold.Seconds() / e.scale.KeepAlive.Seconds())
	}
	e.set(t, "keepAlivesSent", keepAlives)

	e.checkInvariants(t, "after the steady state", 2*time.Minute,
		invariantsOpts{connected: clients, disconnected: probes})

	e.assertHealthy(t, before)
	e.logUsage(t)
}

func testChaosChurn(t *testing.T, e *chaosEnv) {
	population := e.ensurePopulation(t)
	sessions := e.takeSpare(t, 2*e.scale.ChurnWorkers)

	before := e.healthSnapshot(t)
	since := time.Now()

	var connects, graceful, drops, takeovers atomic.Int64

	res := harness.RunFor(t.Context(), e.scale.ChurnDuration, e.scale.ChurnWorkers,
		func(ctx context.Context, worker, iteration int) error {
			sess := sessions[2*worker+iteration%2]

			opts := e.clientOpts(worker*7 + iteration)
			opts.KeepAlive = 0

			c := harness.NewVClient(sess, e.dedicated, opts)

			connCtx, cancel := context.WithTimeout(ctx, harness.VClientInitBudget)
			err := c.Connect(connCtx)
			cancel()
			if err != nil {
				return err
			}
			connects.Add(1)

			harness.Sleep(ctx, time.Duration(rand.IntN(1500))*time.Millisecond)

			switch roll := rand.IntN(100); {
			case roll < 50:
				graceful.Add(1)
				if err := c.Disconnect(context.Background()); err != nil {
					return errors.Wrap(err, "graceful disconnect")
				}
			case roll < 80:
				drops.Add(1)
				c.Drop()
			default:
				takeovers.Add(1)
				next := harness.NewVClient(sess, e.dedicated, opts)

				connCtx, cancel := context.WithTimeout(context.Background(), harness.VClientInitBudget)
				err := next.Connect(connCtx)
				cancel()

				waitCtx, waitCancel := context.WithTimeout(context.Background(), 15*time.Second)
				c.WaitDone(waitCtx)
				waitCancel()
				c.Drop()

				if err != nil {
					return errors.Wrap(err, "takeover connect")
				}
				next.Disconnect(context.Background())
				return nil
			}

			waitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return c.WaitDone(waitCtx)
		})

	harness.LogPool("Churn", res)

	e.set(t, "operations", res.String())
	e.set(t, "connects", connects.Load())
	e.set(t, "gracefulDisconnects", graceful.Load())
	e.set(t, "drops", drops.Load())
	e.set(t, "takeovers", takeovers.Load())
	e.set(t, "connectsPerSecond", float64(connects.Load())/res.Elapsed.Seconds())
	e.set(t, "errors", res.Errors.Classes())

	if res.Total == 0 {
		e.fatalf(t, "No churn operation completed: %s", res.Errors)
	}

	if failed := res.Failed(); failed*100 > res.Total {
		e.failf(t, "%d of %d churn operations failed: %s", failed, res.Total, res.Errors)
	}

	e.assertNoDrops(t, "while other clients churned", population, since)

	e.checkInvariants(t, "after the churn settled", 3*time.Minute,
		invariantsOpts{connected: population, disconnected: sessions})

	e.assertHealthy(t, before)
	e.logUsage(t)
}

func testChaosTakeoverRace(t *testing.T, e *chaosEnv) {
	population := e.ensurePopulation(t)
	sessions := e.takeSpare(t, e.scale.Takeover)
	racers := e.scale.TakeoverRacers

	before := e.healthSnapshot(t)

	groups := make([][]*harness.VClient, len(sessions))
	for i, sess := range sessions {
		for j := range racers {
			opts := e.clientOpts(i*racers + j)
			opts.KeepAlive = 0
			groups[i] = append(groups[i], harness.NewVClient(sess, e.dedicated, opts))
		}
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := harness.NewErrorCounter()
	var won atomic.Int64

	for _, group := range groups {
		for _, c := range group {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start

				ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
				defer cancel()

				if err := c.Connect(ctx); err != nil {
					errs.Add(err)
					return
				}
				won.Add(1)
			}()
		}
	}

	close(start)
	wg.Wait()

	e.set(t, "connectsSucceeded", won.Load())
	e.set(t, "connectErrors", errs.Classes())

	var winners []*harness.VClient
	for _, group := range groups {
		e.track(group...)
	}

	h := e.h
	h.Eventually(t, "every raced Session to settle on a single live stream", 2*time.Minute,
		func(ctx context.Context) error {
			winners = winners[:0]
			var multi, none int
			for _, group := range groups {
				var live []*harness.VClient
				for _, c := range group {
					if c.IsConnected() {
						live = append(live, c)
					}
				}
				switch len(live) {
				case 0:
					none++
				case 1:
					winners = append(winners, live[0])
				default:
					multi++
				}
			}
			if multi > 0 {
				return errors.Errorf("%d Sessions still have more than one live stream", multi)
			}
			if none > 0 {
				return errors.Errorf("%d Sessions lost every racing stream", none)
			}
			return nil
		})

	e.checkInvariants(t, "after the takeover race", 2*time.Minute,
		invariantsOpts{connected: append(slices.Clone(population), winners...)})

	res := harness.ForEach(t.Context(), len(winners), 32, func(ctx context.Context, i int) error {
		return winners[i].Disconnect(ctx)
	})
	harness.LogPool("Disconnected the takeover winners", res)

	e.checkInvariants(t, "after the takeover winners disconnected", 2*time.Minute,
		invariantsOpts{connected: population, disconnected: sessions})

	e.assertHealthy(t, before)
}

func testChaosAbruptCancel(t *testing.T, e *chaosEnv) {
	population := e.ensurePopulation(t)
	sessions := e.takeSpare(t, e.scale.Abrupt)

	before := e.healthSnapshot(t)

	const rounds = 3
	var completed, canceled atomic.Int64

	for round := range rounds {
		res := harness.ForEach(t.Context(), len(sessions), 32, func(ctx context.Context, i int) error {
			opts := e.clientOpts(round*len(sessions) + i)
			opts.KeepAlive = 0

			c := harness.NewVClient(sessions[i], e.dedicated, opts)

			connCtx, cancel := context.WithTimeout(ctx, time.Duration(rand.IntN(400))*time.Millisecond)
			err := c.Connect(connCtx)
			cancel()

			if err == nil {
				completed.Add(1)
				c.Drop()
			} else {
				canceled.Add(1)
			}

			return nil
		})
		harness.LogPool(fmt.Sprintf("Abrupt cancel round %d", round), res)
	}

	e.set(t, "completedThenDropped", completed.Load())
	e.set(t, "canceledDuringInit", canceled.Load())

	e.checkInvariants(t, "after the abruptly canceled Connects", 3*time.Minute,
		invariantsOpts{connected: population, disconnected: sessions})

	e.assertHealthy(t, before)
}

func testChaosFrozenClients(t *testing.T, e *chaosEnv) {
	population := e.ensurePopulation(t)
	sessions := e.takeSpare(t, e.scale.Frozen)

	frozen := make([]*harness.VClient, len(sessions))
	for i, sess := range sessions {
		opts := e.clientOpts(i)
		opts.KeepAlive = 0
		frozen[i] = harness.NewVClient(sess, e.dedicated, opts)
	}
	e.track(frozen...)

	run := e.connectAll(t.Context(), frozen, 32)
	require.Equal(t, len(frozen), run.Succeeded, "the clients to freeze could not connect: %s", run.PoolResult)

	before := e.healthSnapshot(t)
	since := time.Now()

	for _, c := range frozen {
		c.Freeze()
	}

	byUID := map[string]bool{}
	for _, sess := range sessions {
		byUID[sess.UID] = true
	}

	detected := map[string]time.Duration{}

	e.h.EventuallyEvery(t, "the Cluster to drop every frozen client", 5*time.Minute, 5*time.Second,
		func(ctx context.Context) error {
			inv, err := e.h.ConnInventory(ctx)
			if err != nil {
				return err
			}

			var still int
			for _, sess := range inv.Sessions {
				if !byUID[sess.Metadata.Uid] {
					continue
				}
				if sess.Status.Connection != nil {
					still++
					continue
				}
				if _, ok := detected[sess.Metadata.Uid]; !ok {
					detected[sess.Metadata.Uid] = time.Since(since)
				}
			}

			if still > 0 {
				return errors.Errorf("%d of %d frozen clients are still connected", still, len(sessions))
			}
			return nil
		})

	var lat harness.Latencies
	for _, d := range detected {
		lat.Add(d)
	}
	e.set(t, "timeToDrop", lat.Summary())

	e.assertNoDrops(t, "while other clients were frozen", population, since)

	e.checkInvariants(t, "after the frozen clients were dropped", 2*time.Minute,
		invariantsOpts{connected: population, disconnected: sessions})

	for _, c := range frozen {
		c.Thaw()
	}

	e.h.Eventually(t, "the thawed clients to notice their dropped streams", 3*time.Minute,
		func(ctx context.Context) error {
			if n := countConnected(frozen); n > 0 {
				return errors.Errorf("%d thawed clients still believe they are connected", n)
			}
			return nil
		})

	e.supervise(frozen...)

	recovered := e.waitConnected(t, "the thawed clients to reconnect", frozen,
		scaled(2*time.Minute, 100*time.Millisecond, len(frozen)))
	e.set(t, "thawedReconnected", recovered.String())

	e.assertHealthy(t, before)
}

func testChaosUninitializedStreams(t *testing.T, e *chaosEnv) {
	population := e.ensurePopulation(t)
	sessions := e.takeSpare(t, e.scale.IdleStreams)
	probes := e.takeSpare(t, 5)

	before := e.healthSnapshot(t)
	since := time.Now()

	type idle struct {
		cancel context.CancelFunc
		closed chan struct{}
		conn   *harness.VConn
	}

	streams := make([]*idle, len(sessions))
	openErrs := harness.NewErrorCounter()

	res := harness.ForEach(t.Context(), len(sessions), 32, func(ctx context.Context, i int) error {
		conn, err := e.dedicated.Acquire()
		if err != nil {
			return err
		}

		streamCtx, cancel := context.WithCancel(context.Background())
		streamCtx = metadata.AppendToOutgoingContext(streamCtx, harness.AuthHeader, sessions[i].AccessToken)

		stream, err := userv1.NewMainServiceClient(conn.CC()).Connect(streamCtx)
		if err != nil {
			cancel()
			conn.Release()
			openErrs.Add(err)
			return err
		}

		cur := &idle{cancel: cancel, closed: make(chan struct{}), conn: conn}
		go func() {
			defer close(cur.closed)
			stream.Recv()
		}()

		streams[i] = cur
		return nil
	})
	harness.LogPool("Opened streams that never initialize", res)

	defer func() {
		for _, s := range streams {
			if s != nil {
				s.cancel()
				s.conn.Release()
			}
		}
	}()

	hold := min(90*time.Second, max(30*time.Second, e.scale.Hold/2))
	ctx, cancel := context.WithTimeout(t.Context(), hold)
	defer cancel()

	api := newProbeStats()
	conn := newProbeStats()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); e.probeAPI(ctx, 2*time.Second, api) }()
	go func() { defer wg.Done(); e.probeConnect(ctx, probes, 3*time.Second, conn) }()
	wg.Wait()

	var closedByServer int
	for _, s := range streams {
		if s == nil {
			continue
		}
		select {
		case <-s.closed:
			closedByServer++
		default:
		}
	}

	e.set(t, "opened", res.Succeeded)
	e.set(t, "openErrors", openErrs.Classes())
	e.set(t, "hold", hold.String())
	e.set(t, "closedByServerWithinHold", closedByServer)

	zap.L().Info("Streams that never sent an Initialize",
		zap.Int("opened", res.Succeeded), zap.Int("closedByServer", closedByServer),
		zap.Duration("hold", hold))

	api.assert(t, e, "apiProbe", chaosAPISLO)
	conn.assert(t, e, "connectProbe", chaosConnectSLO)

	e.assertNoDrops(t, "while uninitialized streams were held", population, since)

	e.checkInvariants(t, "while uninitialized streams are held", time.Minute,
		invariantsOpts{connected: population, disconnected: sessions})

	e.assertHealthy(t, before)
}

func testChaosSessionDeletion(t *testing.T, e *chaosEnv) {
	population := e.ensurePopulation(t)
	sessions := e.takeSpare(t, e.scale.Deleted)
	h := e.h

	clients := make([]*harness.VClient, len(sessions))
	for i, sess := range sessions {
		opts := e.clientOpts(i)
		opts.KeepAlive = 0
		clients[i] = harness.NewVClient(sess, e.dedicated, opts)
	}
	e.track(clients...)

	run := e.connectAll(t.Context(), clients, 32)
	require.Equal(t, len(clients), run.Succeeded, "the clients to delete could not connect: %s", run.PoolResult)

	before := e.healthSnapshot(t)
	since := time.Now()

	victims := clients[:len(clients)/2]
	survivors := clients[len(clients)/2:]

	victimPlanes := e.victimDataPlanes(t, victims)

	res := harness.ForEach(t.Context(), len(victims), 16, func(ctx context.Context, i int) error {
		_, err := h.CoreC().DeleteSession(ctx, &metav1.DeleteOptions{Uid: victims[i].Session.UID})
		return err
	})
	require.Zero(t, res.Failed(), "could not delete the Sessions: %s", res)

	h.Eventually(t, "the clients of the deleted Sessions to be disconnected", 2*time.Minute,
		func(ctx context.Context) error {
			if n := countConnected(victims); n > 0 {
				return errors.Errorf("%d clients of deleted Sessions are still connected", n)
			}
			return nil
		})

	var notified int
	for _, c := range victims {
		if c.DisconnectedByServer() {
			notified++
		}
	}
	e.set(t, "notifiedByDisconnect", notified)
	e.set(t, "deleted", len(victims))

	for _, vp := range victimPlanes {
		e.assertDataPlaneRevoked(t, vp)
	}

	e.assertNoDrops(t, "while other Sessions were deleted", append(slices.Clone(population), survivors...), since)

	e.checkInvariants(t, "after connected Sessions were deleted", 2*time.Minute,
		invariantsOpts{connected: append(slices.Clone(population), survivors...)})

	t.Run("UserDeletion", func(t *testing.T) {
		testChaosUserDeletion(t, e, population)
	})

	e.assertHealthy(t, before)
}

func testChaosUserDeletion(t *testing.T, e *chaosEnv, population []*harness.VClient) {
	h := e.h

	fleet, err := h.NewFleet(t.Context(), harness.FleetOpts{Sessions: 10, Users: 1})
	require.NoError(t, err)
	t.Cleanup(func() { fleet.Close(context.Background()) })

	clients := make([]*harness.VClient, len(fleet.Sessions))
	for i, sess := range fleet.Sessions {
		clients[i] = harness.NewVClient(sess, e.dedicated, e.clientOpts(i))
	}
	e.track(clients...)

	run := e.connectAll(t.Context(), clients, 10)
	require.Equal(t, len(clients), run.Succeeded, "%s", run.PoolResult)

	_, err = h.CoreC().DeleteUser(t.Context(), &metav1.DeleteOptions{Uid: fleet.Users[0].Metadata.Uid})
	require.NoError(t, err)

	h.Eventually(t, "the clients of the deleted User to be disconnected", 3*time.Minute,
		func(ctx context.Context) error {
			if n := countConnected(clients); n > 0 {
				return errors.Errorf("%d clients of the deleted User are still connected", n)
			}
			return nil
		})

	h.Eventually(t, "the Sessions of the deleted User to be removed", 3*time.Minute,
		func(ctx context.Context) error {
			list, err := h.CoreC().ListSession(ctx, &corev1.ListSessionOptions{
				UserRef: umetav1.GetObjectReference(fleet.Users[0]),
			})
			if err != nil {
				return err
			}
			if n := len(list.Items); n > 0 {
				return errors.Errorf("%d Sessions of the deleted User remain", n)
			}
			return nil
		})

	e.checkInvariants(t, "after a User with connected Sessions was deleted", 2*time.Minute,
		invariantsOpts{connected: population})
}

func testChaosFinal(t *testing.T, e *chaosEnv) {
	e.mu.Lock()
	population := e.population
	extra := e.extra
	fleet := e.fleet
	e.mu.Unlock()

	if fleet == nil {
		t.Skip("The chaos fleet was never created")
	}

	e.stopSupervisors()

	all := append(slices.Clone(population), extra...)

	started := time.Now()
	res := harness.ForEach(t.Context(), len(all), 64, func(ctx context.Context, i int) error {
		return all[i].Disconnect(ctx)
	})
	harness.LogPool("Disconnected every chaos client", res)

	e.set(t, "disconnect", res.String())
	e.set(t, "disconnectLatency", res.Latency.Summary())
	e.set(t, "disconnectElapsed", time.Since(started).String())

	if res.Failed() > 0 {
		e.failf(t, "%d graceful Disconnects failed: %s", res.Failed(), res.Errors)
	}

	e.checkInvariants(t, "after every chaos client disconnected",
		scaled(2*time.Minute, 10*time.Millisecond, len(all)),
		invariantsOpts{disconnected: fleet.Sessions})

	if e.baselineHealth != nil {
		e.mu.Lock()
		restarted := slices.Clone(e.restarted)
		e.mu.Unlock()
		e.assertHealthy(t, e.baselineHealth, restarted...)
	}

	e.logUsage(t)
}

func (e *chaosEnv) markRestarted(owners ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, owner := range owners {
		if !slices.Contains(e.restarted, owner) {
			e.restarted = append(e.restarted, owner)
		}
	}
}
