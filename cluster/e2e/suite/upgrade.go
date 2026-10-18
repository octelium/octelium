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
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	upgradeFleetSessions    = 32
	upgradeFleetUsers       = 4
	upgradeClients          = 8
	upgradeChurnClients     = 2
	upgradeAbandonedClients = 4

	upgradeProbeWorkers  = 8
	upgradeProbeInterval = 50 * time.Millisecond
	upgradeProbeTimeout  = 10 * time.Second
	upgradeChurnInterval = 500 * time.Millisecond

	upgradeRecoverBudget = 3 * time.Minute
	upgradeSettle        = 15 * time.Second

	octovigilDeployment = "octelium-octovigil"
	apiService          = "default.octelium-api"
)

var controlPlaneDeployments = []string{
	"octelium-rscserver",
	"octelium-octovigil",
	"octelium-nocturne",
	"octelium-ingress",
	"octelium-ingress-dataplane",
}

func rejectsValidSession(err error) bool {
	switch status.Code(err) {
	case codes.NotFound, codes.PermissionDenied, codes.InvalidArgument, codes.Unauthenticated:
		return true
	default:
		return false
	}
}

type timedErr struct {
	at  time.Time
	err error
}

type errorLog struct {
	mu   sync.Mutex
	errs []timedErr
}

func (l *errorLog) add(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errs = append(l.errs, timedErr{at: time.Now(), err: err})
}

func (l *errorLog) rejectedSince(since time.Time) *harness.ErrorCounter {
	l.mu.Lock()
	defer l.mu.Unlock()

	ret := harness.NewErrorCounter()
	for _, e := range l.errs {
		if !e.at.Before(since) && rejectsValidSession(e.err) {
			ret.Add(e.err)
		}
	}
	return ret
}

type sessionProbe struct {
	requests atomic.Int64
	connects atomic.Int64
	errs     *harness.ErrorCounter
	rejected *harness.ErrorCounter

	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

func startSessionProbe(conn *grpc.ClientConn, pool *harness.VConnPool,
	sessions, churn []*harness.FleetSession) *sessionProbe {
	ctx, cancel := context.WithCancel(context.Background())

	ret := &sessionProbe{
		errs:     harness.NewErrorCounter(),
		rejected: harness.NewErrorCounter(),
		cancel:   cancel,
	}

	c := userv1.NewMainServiceClient(conn)

	for w := range upgradeProbeWorkers {
		ret.wg.Add(1)
		go func() {
			defer ret.wg.Done()

			for i := w; ctx.Err() == nil; i += upgradeProbeWorkers {
				sess := sessions[i%len(sessions)]

				reqCtx, cancelReq := context.WithTimeout(ctx, upgradeProbeTimeout)
				_, err := c.GetStatus(metadata.AppendToOutgoingContext(reqCtx,
					harness.AuthHeader, sess.AccessToken), &userv1.GetStatusRequest{})
				cancelReq()

				ret.requests.Add(1)
				ret.record(ctx, err)

				harness.Sleep(ctx, upgradeProbeInterval)
			}
		}()
	}

	for _, sess := range churn {
		ret.wg.Add(1)
		go func() {
			defer ret.wg.Done()

			for ctx.Err() == nil {
				vc := harness.NewVClient(sess, pool, harness.VClientOpts{
					L3Mode: userv1.ConnectRequest_Initialize_V4,
				})

				err := vc.Connect(ctx)
				ret.connects.Add(1)
				ret.record(ctx, err)
				if err == nil {
					ret.record(ctx, vc.Disconnect(ctx))
				}

				harness.Sleep(ctx, upgradeChurnInterval)
			}
		}()
	}

	return ret
}

func (p *sessionProbe) record(ctx context.Context, err error) {
	if err == nil || ctx.Err() != nil {
		return
	}

	p.errs.Add(err)
	if rejectsValidSession(err) {
		p.rejected.Add(err)
	}
}

func (p *sessionProbe) stop() {
	p.once.Do(func() {
		p.cancel()
		p.wg.Wait()
	})
}

type upgradeEnv struct {
	h *harness.H

	conn      *grpc.ClientConn
	pool      *harness.VConnPool
	fleet     *harness.Fleet
	clients   []*harness.VClient
	churn     []*harness.FleetSession
	abandoned []*harness.FleetSession

	connectErrs *errorLog
}

func upgradeClientOpts(h *harness.H, i int) harness.VClientOpts {
	tunnels := []userv1.ConnectRequest_Initialize_ConnectionType{userv1.ConnectRequest_Initialize_WIREGUARD}
	if h.Scenario.Caps.Has(capQUICv0) {
		tunnels = append(tunnels, userv1.ConnectRequest_Initialize_QUICV0)
	}

	modes := []userv1.ConnectRequest_Initialize_L3Mode{userv1.ConnectRequest_Initialize_V4}
	if h.Scenario.Caps.Has(capIPv6) {
		modes = append(modes, userv1.ConnectRequest_Initialize_V6, userv1.ConnectRequest_Initialize_BOTH)
	}

	return harness.VClientOpts{
		Tunnel: tunnels[i%len(tunnels)],
		L3Mode: modes[(i/len(tunnels))%len(modes)],
	}
}

func newUpgradeEnv(t *testing.T, h *harness.H) *upgradeEnv {
	t.Helper()

	dialer, err := h.IngressDialer(h.APIServerName())
	require.NoError(t, err)

	conn, err := dialer.GRPCConn()
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	pool := harness.NewVConnPool(dialer, 1)
	t.Cleanup(pool.Close)

	fleet, err := h.NewFleet(t.Context(), harness.FleetOpts{
		Sessions: upgradeFleetSessions,
		Users:    upgradeFleetUsers,
	})
	require.NoError(t, err)
	t.Cleanup(func() { fleet.Close(context.Background()) })

	abandonedFrom := upgradeClients + upgradeChurnClients

	ret := &upgradeEnv{
		h:           h,
		conn:        conn,
		pool:        pool,
		fleet:       fleet,
		churn:       fleet.Sessions[upgradeClients : upgradeClients+upgradeChurnClients],
		abandoned:   fleet.Sessions[abandonedFrom : abandonedFrom+upgradeAbandonedClients],
		connectErrs: &errorLog{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()

		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, c := range ret.clients {
			c.Disconnect(ctx)
		}
	})

	for i, sess := range fleet.Sessions[:upgradeClients] {
		c := harness.NewVClient(sess, pool, upgradeClientOpts(h, i))

		connectCtx, cancelConnect := context.WithTimeout(t.Context(), 2*harness.VClientInitBudget)
		_, err := connectWithRetry(connectCtx, c, 5)
		cancelConnect()
		require.NoError(t, err)

		ret.clients = append(ret.clients, c)

		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Supervise(ctx, harness.SuperviseOpts{
				BackoffMin: time.Second,
				BackoffMax: 10 * time.Second,
				OnConnectError: func(err error) bool {
					ret.connectErrs.add(err)
					return isRetryableConnectErr(err)
				},
			})
		}()
	}

	return ret
}

func (e *upgradeEnv) connectAbandoned(t *testing.T) []*harness.VClient {
	t.Helper()

	var ret []*harness.VClient
	for i, sess := range e.abandoned {
		c := harness.NewVClient(sess, e.pool, upgradeClientOpts(e.h, i))

		ctx, cancel := context.WithTimeout(t.Context(), 2*harness.VClientInitBudget)
		_, err := connectWithRetry(ctx, c, 5)
		cancel()
		require.NoError(t, err)

		t.Cleanup(func() { c.Disconnect(context.Background()) })

		ret = append(ret, c)
	}

	return ret
}

func connectedSessionNames(sessions []*corev1.Session) []string {
	var ret []string
	for _, sess := range sessions {
		if sess.Status != nil && (sess.Status.IsConnected || sess.Status.Connection != nil) {
			ret = append(ret, sess.Metadata.Name)
		}
	}

	return ret
}

func (e *upgradeEnv) waitAbandonedDisconnected(t *testing.T,
	clients []*harness.VClient, what string) time.Duration {
	t.Helper()

	return e.h.Within(t, "the Sessions of the clients that never reconnected after "+what+
		" to be disconnected", upgradeRecoverBudget, func(ctx context.Context) error {
		var sessions []*corev1.Session
		for _, c := range clients {
			if c.IsConnected() {
				return errors.Errorf("the client of the Session %s still has its API stream", c.Session.UID)
			}

			sess, err := e.h.CoreC().GetSession(ctx, &metav1.GetOptions{Uid: c.Session.UID})
			if err != nil {
				return err
			}
			sessions = append(sessions, sess)
		}

		if connected := connectedSessionNames(sessions); len(connected) > 0 {
			return errors.Errorf("%d of %d Sessions are still connected although their client is gone: %v",
				len(connected), len(sessions), connected)
		}

		return nil
	})
}

type upgradeDisruption struct {
	name  string
	drops bool
	run   func(t *testing.T, e *upgradeEnv) time.Duration
}

func rolloutDeployments(t *testing.T, h *harness.H, deployments ...string) time.Duration {
	t.Helper()

	started := time.Now()

	for _, dep := range deployments {
		require.NoError(t, h.RolloutRestart(t.Context(), dep), "Could not restart the Deployment %s", dep)
	}

	for _, dep := range deployments {
		require.NoError(t, h.WaitRollout(t.Context(), dep))
	}

	return time.Since(started)
}

func (e *upgradeEnv) runDisruption(t *testing.T, d upgradeDisruption) {
	h := e.h

	port := h.Port()
	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{"demo-nginx": port},
	})
	h.WaitGetStatus(t, h.HTTP(), conn.URL("demo-nginx"), http.StatusOK)

	sessName := h.Status(t).Session.Metadata.Name
	totalConnections := h.GetSession(t, sessName).Status.TotalConnections

	h.Within(t, "every virtual client to be connected before the disruption", upgradeRecoverBudget,
		func(ctx context.Context) error {
			if n := countConnected(e.clients); n < len(e.clients) {
				return errors.Errorf("%d of %d virtual clients are connected", n, len(e.clients))
			}
			return nil
		})

	abandoned := e.connectAbandoned(t)

	since := time.Now()

	probe := startSessionProbe(e.conn, e.pool, e.fleet.Sessions, e.churn)
	defer probe.stop()

	disrupted := d.run(t, e)

	var gaveUp string
	recovered := h.Within(t, "every client to reconnect after "+d.name, upgradeRecoverBudget,
		func(ctx context.Context) error {
			if !conn.IsRunning() {
				gaveUp = "octelium connect exited"
				return nil
			}
			if rejected := e.connectErrs.rejectedSince(since); rejected.Total() > 0 {
				gaveUp = "virtual clients gave up reconnecting: " + rejected.String()
				return nil
			}

			sess, err := h.CoreC().GetSession(ctx, &metav1.GetOptions{Name: sessName})
			if err != nil {
				return err
			}
			if sess.Status == nil || !sess.Status.IsConnected {
				return errors.Errorf("the Session of octelium connect is not connected")
			}
			if d.drops && sess.Status.TotalConnections <= totalConnections {
				return errors.Errorf("octelium connect has not opened a new API stream yet")
			}

			if n := countConnected(e.clients); n < len(e.clients) {
				return errors.Errorf("%d of %d virtual clients are connected", n, len(e.clients))
			}

			return nil
		})

	if gaveUp != "" {
		probe.stop()
		t.Fatalf("Clients did not reconnect after %s, %s. The API requests rejected meanwhile: %s",
			d.name, gaveUp, probe.rejected)
	}

	h.WaitConnected(t)
	h.WaitGetStatus(t, h.HTTP(), conn.URL("demo-nginx"), http.StatusOK)

	var abandonedDisconnected time.Duration
	if d.drops {
		abandonedDisconnected = e.waitAbandonedDisconnected(t, abandoned, d.name)
	}

	require.NoError(t, harness.Sleep(t.Context(), upgradeSettle))
	probe.stop()

	zap.L().Info("Clients recovered from an upgrade-like disruption",
		zap.String("disruption", d.name),
		zap.Duration("disrupted", disrupted),
		zap.Duration("recovered", recovered),
		zap.Duration("abandonedDisconnected", abandonedDisconnected),
		zap.Int64("requests", probe.requests.Load()),
		zap.Int64("connects", probe.connects.Load()),
		zap.Any("errors", probe.errs.Classes()))

	require.True(t, conn.IsRunning(), "octelium connect exited after %s", d.name)
	require.Positive(t, probe.requests.Load(), "the probe sent no request")

	if n := probe.rejected.Total(); n > 0 {
		t.Errorf("%d of %d API requests and Connect attempts of valid Sessions were rejected after %s. "+
			"A real client gives up on such errors: %s",
			n, probe.requests.Load()+probe.connects.Load(), d.name, probe.rejected)
	}

	if rejected := e.connectErrs.rejectedSince(since); rejected.Total() > 0 {
		t.Errorf("%d reconnect attempts of the virtual clients were rejected after %s, "+
			"the real client would have exited: %s", rejected.Total(), d.name, rejected)
	}

	if !d.drops {
		if dropped := dropsSince(e.clients, since); len(dropped) > 0 {
			t.Errorf("%d of %d virtual clients lost their stream after %s",
				len(dropped), len(e.clients), d.name)
		}
	}
}

func upgradeDisruptions() []upgradeDisruption {
	return []upgradeDisruption{
		{
			name: "OctovigilRollout",
			run: func(t *testing.T, e *upgradeEnv) time.Duration {
				return rolloutDeployments(t, e.h, octovigilDeployment)
			},
		},
		{
			name:  "OctovigilAndAPIServerRollout",
			drops: true,
			run: func(t *testing.T, e *upgradeEnv) time.Duration {
				return rolloutDeployments(t, e.h, octovigilDeployment, e.h.ServiceDeployment(apiService))
			},
		},
		{
			name:  "OctovigilAndAPIServerReplace",
			drops: true,
			run: func(t *testing.T, e *upgradeEnv) time.Duration {
				return e.h.RestartWorkloads(t, []string{"octovigil"}, []string{apiService})
			},
		},
		{
			name:  "ControlPlaneRollout",
			drops: true,
			run: func(t *testing.T, e *upgradeEnv) time.Duration {
				return rolloutDeployments(t, e.h,
					append(slices.Clone(controlPlaneDeployments), e.h.ServiceDeployment(apiService))...)
			},
		},
		{
			name:  "GenesisUpgrade",
			drops: true,
			run: func(t *testing.T, e *upgradeEnv) time.Duration {
				return e.h.UpgradeCluster(t)
			},
		},
	}
}

func testClusterUpgrade(t *testing.T, h *harness.H) {
	e := newUpgradeEnv(t, h)

	for _, d := range upgradeDisruptions() {
		t.Run(d.name, func(t *testing.T) {
			e.runDisruption(t, d)
		})
	}
}
