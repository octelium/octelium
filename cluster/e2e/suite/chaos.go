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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type chaosScale struct {
	Name string `json:"name"`

	Clients        int `json:"clients"`
	Users          int `json:"users"`
	ConnectWorkers int `json:"connectWorkers"`
	StreamsPerConn int `json:"streamsPerConn"`
	AuthWorkers    int `json:"authWorkers"`

	KeepAlive time.Duration `json:"keepAlive"`
	Hold      time.Duration `json:"hold"`

	ChurnWorkers  int           `json:"churnWorkers"`
	ChurnDuration time.Duration `json:"churnDuration"`

	DataPlane int `json:"dataPlane"`

	HTTPWorkers  int           `json:"httpWorkers"`
	HTTPDuration time.Duration `json:"httpDuration"`
	LongLived    int           `json:"longLived"`

	IdleStreams    int `json:"idleStreams"`
	Frozen         int `json:"frozen"`
	Takeover       int `json:"takeover"`
	TakeoverRacers int `json:"takeoverRacers"`
	Abrupt         int `json:"abrupt"`
	Deleted        int `json:"deleted"`
	Probes         int `json:"probes"`
}

const chaosSpareExtra = 32

func (s chaosScale) spare() int {
	return s.Takeover + s.Abrupt + s.Frozen + s.IdleStreams + s.Deleted +
		2*s.ChurnWorkers + s.Probes + chaosSpareExtra
}

var chaosScales = map[string]chaosScale{
	"small": {
		Clients: 200, Users: 4, ConnectWorkers: 16, StreamsPerConn: 1, AuthWorkers: 16,
		KeepAlive: 30 * time.Second, Hold: time.Minute,
		ChurnWorkers: 8, ChurnDuration: time.Minute,
		DataPlane:   12,
		HTTPWorkers: 32, HTTPDuration: 30 * time.Second, LongLived: 200,
		IdleStreams: 100, Frozen: 20, Takeover: 10, TakeoverRacers: 4, Abrupt: 20, Deleted: 20, Probes: 20,
	},
	"medium": {
		Clients: 1000, Users: 8, ConnectWorkers: 32, StreamsPerConn: 1, AuthWorkers: 32,
		KeepAlive: 30 * time.Second, Hold: 2 * time.Minute,
		ChurnWorkers: 16, ChurnDuration: 2 * time.Minute,
		DataPlane:   24,
		HTTPWorkers: 64, HTTPDuration: time.Minute, LongLived: 1000,
		IdleStreams: 250, Frozen: 50, Takeover: 25, TakeoverRacers: 4, Abrupt: 50, Deleted: 50, Probes: 30,
	},
	"large": {
		Clients: 2500, Users: 16, ConnectWorkers: 48, StreamsPerConn: 2, AuthWorkers: 48,
		KeepAlive: time.Minute, Hold: 3 * time.Minute,
		ChurnWorkers: 32, ChurnDuration: 3 * time.Minute,
		DataPlane:   32,
		HTTPWorkers: 128, HTTPDuration: 90 * time.Second, LongLived: 2500,
		IdleStreams: 400, Frozen: 100, Takeover: 50, TakeoverRacers: 4, Abrupt: 100, Deleted: 100, Probes: 40,
	},
	"xlarge": {
		Clients: 10000, Users: 32, ConnectWorkers: 64, StreamsPerConn: 8, AuthWorkers: 64,
		KeepAlive: 2 * time.Minute, Hold: 3 * time.Minute,
		ChurnWorkers: 48, ChurnDuration: 4 * time.Minute,
		DataPlane:   48,
		HTTPWorkers: 256, HTTPDuration: 2 * time.Minute, LongLived: 4000,
		IdleStreams: 500, Frozen: 200, Takeover: 100, TakeoverRacers: 4, Abrupt: 200, Deleted: 200, Probes: 50,
	},
}

func chaosScaleFor(name string) (chaosScale, error) {
	ret, ok := chaosScales[name]
	if !ok {
		return ret, errors.Errorf("Unknown chaos scale %q. One of: %s",
			name, strings.Join(harness.ChaosScales, ", "))
	}
	ret.Name = name

	if val := strings.TrimSpace(os.Getenv(harness.ChaosClientsEnv)); val != "" {
		n, err := strconv.Atoi(val)
		if err != nil || n < 10 || n > 50000 {
			return ret, errors.Errorf("Invalid %s %q. It must be between 10 and 50000",
				harness.ChaosClientsEnv, val)
		}
		ret.Clients = n
		ret.Users = max(ret.Users, (n+999)/1000*2)
		ret.LongLived = min(n, 4000)
		ret.Name = fmt.Sprintf("%s-%d", name, n)
	}

	return ret, nil
}

func scaled(base, perClient time.Duration, n int) time.Duration {
	return base + time.Duration(n)*perClient
}

type chaosReport struct {
	mu sync.Mutex

	Scenario  string                    `json:"scenario"`
	Scale     chaosScale                `json:"scale"`
	StartedAt time.Time                 `json:"startedAt"`
	EndedAt   time.Time                 `json:"endedAt,omitzero"`
	Phases    map[string]map[string]any `json:"phases"`
	Failures  map[string][]string       `json:"failures,omitempty"`
}

func (r *chaosReport) set(phase, key string, val any) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.Phases[phase] == nil {
		r.Phases[phase] = map[string]any{}
	}
	r.Phases[phase][key] = val
}

func (r *chaosReport) failure(phase, msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.Failures == nil {
		r.Failures = map[string][]string{}
	}
	r.Failures[phase] = append(r.Failures[phase], msg)
}

func (r *chaosReport) write(dir string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.EndedAt = time.Now()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, fmt.Sprintf("chaos-report-%s.json", r.Scenario))
	return path, os.WriteFile(path, b, 0o644)
}

type chaosEnv struct {
	h     *harness.H
	scale chaosScale

	ctx    context.Context
	cancel context.CancelFunc

	report *chaosReport

	ipv6      bool
	quic      bool
	multiNode bool
	wgInspect bool

	mu         sync.Mutex
	fleet      *harness.Fleet
	fleetErr   error
	spare      []*harness.FleetSession
	pool       *harness.VConnPool
	dedicated  *harness.VConnPool
	population []*harness.VClient
	popErr     error
	popTarget  int
	popRun     *connectRun
	supervised map[*harness.VClient]bool
	superWG    sync.WaitGroup
	extra      []*harness.VClient
	samples    []*chaosSample
	target     *chaosTarget

	closers []func()

	baselineHealth   harness.HealthSnapshot
	baselineLeakWG   []uint32
	baselineLeakQUIC []uint32
	baselineStale    map[string][]string
	restarted        []string
}

func newChaosEnv(t *testing.T, h *harness.H) (*chaosEnv, error) {
	scale, err := chaosScaleFor(harness.ChaosScale())
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	ret := &chaosEnv{
		h:          h,
		scale:      scale,
		ctx:        ctx,
		cancel:     cancel,
		ipv6:       h.Scenario.Caps.Has(capIPv6),
		quic:       h.Scenario.Caps.Has(capQUICv0),
		multiNode:  h.Scenario.Caps.Has(capMultiNode),
		supervised: map[*harness.VClient]bool{},
		report: &chaosReport{
			Scenario:  h.Scenario.ID,
			Scale:     scale,
			StartedAt: time.Now(),
			Phases:    map[string]map[string]any{},
		},
	}

	dialer, err := h.IngressDialer(h.APIServerName())
	if err != nil {
		cancel()
		return nil, err
	}

	ret.pool = harness.NewVConnPool(dialer, scale.StreamsPerConn)
	ret.dedicated = harness.NewVConnPool(dialer, 1)

	t.Cleanup(ret.close)

	return ret, nil
}

func (e *chaosEnv) onClose(fn func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closers = append(e.closers, fn)
}

func (e *chaosEnv) close() {
	e.stopSupervisors()

	e.mu.Lock()
	clients := append(append([]*harness.VClient{}, e.population...), e.extra...)
	samples := e.samples
	fleet := e.fleet
	closers := e.closers
	e.mu.Unlock()

	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}()

	for _, s := range samples {
		s.dp.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	res := harness.ForEach(ctx, len(clients), 64, func(ctx context.Context, i int) error {
		return clients[i].Disconnect(ctx)
	})
	harness.LogPool("Disconnected the chaos clients", res)

	if fleet != nil {
		fleet.Close(ctx)
	}

	e.pool.Close()
	e.dedicated.Close()
	e.cancel()

	if path, err := e.report.write(e.h.ArtifactDir()); err != nil {
		zap.L().Warn("Could not write the chaos report", zap.Error(err))
	} else {
		zap.L().Info("Wrote the chaos report", zap.String("path", path))
	}
}

func (e *chaosEnv) set(t *testing.T, key string, val any) {
	e.report.set(phaseName(t), key, val)
}

func phaseName(t *testing.T) string {
	parts := strings.Split(t.Name(), "/")
	if len(parts) > 1 {
		return strings.Join(parts[1:], "/")
	}
	return t.Name()
}

func (e *chaosEnv) failf(t *testing.T, format string, args ...any) {
	t.Helper()

	msg := fmt.Sprintf(format, args...)
	e.report.failure(phaseName(t), msg)
	t.Error(msg)
}

func (e *chaosEnv) fatalf(t *testing.T, format string, args ...any) {
	t.Helper()

	msg := fmt.Sprintf(format, args...)
	e.report.failure(phaseName(t), msg)
	t.Fatal(msg)
}

func (e *chaosEnv) l3Modes() []userv1.ConnectRequest_Initialize_L3Mode {
	if !e.ipv6 {
		return []userv1.ConnectRequest_Initialize_L3Mode{userv1.ConnectRequest_Initialize_V4}
	}

	return []userv1.ConnectRequest_Initialize_L3Mode{
		userv1.ConnectRequest_Initialize_V4,
		userv1.ConnectRequest_Initialize_V6,
		userv1.ConnectRequest_Initialize_BOTH,
	}
}

func (e *chaosEnv) tunnels() []userv1.ConnectRequest_Initialize_ConnectionType {
	if !e.quic {
		return []userv1.ConnectRequest_Initialize_ConnectionType{userv1.ConnectRequest_Initialize_WIREGUARD}
	}

	return []userv1.ConnectRequest_Initialize_ConnectionType{
		userv1.ConnectRequest_Initialize_WIREGUARD,
		userv1.ConnectRequest_Initialize_WIREGUARD,
		userv1.ConnectRequest_Initialize_QUICV0,
	}
}

func (e *chaosEnv) clientOpts(i int) harness.VClientOpts {
	tunnels := e.tunnels()
	modes := e.l3Modes()

	return harness.VClientOpts{
		Tunnel:    tunnels[i%len(tunnels)],
		L3Mode:    modes[(i/len(tunnels))%len(modes)],
		KeepAlive: e.scale.KeepAlive,
	}
}

func wantL3Mode(m userv1.ConnectRequest_Initialize_L3Mode) corev1.Session_Status_Connection_L3Mode {
	switch m {
	case userv1.ConnectRequest_Initialize_V4:
		return corev1.Session_Status_Connection_V4
	case userv1.ConnectRequest_Initialize_V6:
		return corev1.Session_Status_Connection_V6
	default:
		return corev1.Session_Status_Connection_BOTH
	}
}

func wantTunnel(m userv1.ConnectRequest_Initialize_ConnectionType) corev1.Session_Status_Connection_Type {
	if m == userv1.ConnectRequest_Initialize_QUICV0 {
		return corev1.Session_Status_Connection_QUICV0
	}
	return corev1.Session_Status_Connection_WIREGUARD
}

func (e *chaosEnv) ensureFleet(t *testing.T) *harness.Fleet {
	t.Helper()

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.fleet != nil {
		return e.fleet
	}
	if e.fleetErr != nil {
		t.Skipf("The chaos fleet could not be created: %+v", e.fleetErr)
	}

	total := e.scale.Clients + e.scale.spare()

	ctx, cancel := context.WithTimeout(t.Context(), scaled(3*time.Minute, 40*time.Millisecond, total))
	defer cancel()

	fleet, err := e.h.NewFleet(ctx, harness.FleetOpts{
		Sessions:    total,
		Users:       e.scale.Users,
		Concurrency: e.scale.AuthWorkers,
	})
	switch {
	case err == nil:
	case fleet != nil && len(fleet.Sessions) >= e.scale.spare()+10:
		e.failf(t, "Only %d of %d chaos Sessions could be created, the next phases run with %d clients: %+v",
			len(fleet.Sessions), total, len(fleet.Sessions)-e.scale.spare(), err)
		e.scale.Clients = len(fleet.Sessions) - e.scale.spare()
	default:
		if fleet != nil {
			fleet.Close(context.Background())
		}
		e.fleetErr = err
		e.fatalf(t, "Could not create the chaos fleet of %d Sessions: %+v", total, err)
	}

	e.fleet = fleet
	e.spare = fleet.Sessions[e.scale.Clients:]

	return fleet
}

func (e *chaosEnv) takeSpare(t *testing.T, n int) []*harness.FleetSession {
	t.Helper()

	e.ensureFleet(t)

	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.spare) < n {
		e.fatalf(t, "The fleet has %d spare Sessions left, %d are needed", len(e.spare), n)
	}

	ret := e.spare[:n]
	e.spare = e.spare[n:]
	return ret
}

func isRetryableConnectErr(err error) bool {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.PermissionDenied, codes.NotFound:
		return false
	default:
		return true
	}
}

type connectOutcome struct {
	attempts int
	errs     []error
}

func connectWithRetry(ctx context.Context, c *harness.VClient, attempts int) (*connectOutcome, error) {
	ret := &connectOutcome{}

	for attempt := 1; attempt <= attempts; attempt++ {
		ret.attempts = attempt

		err := c.Connect(ctx)
		if err == nil {
			return ret, nil
		}

		ret.errs = append(ret.errs, err)
		if !isRetryableConnectErr(err) || ctx.Err() != nil || attempt == attempts {
			return ret, err
		}

		if err := harness.Sleep(ctx, harness.ReconnectBackoff(attempt, time.Second, 5*time.Second)); err != nil {
			return ret, err
		}
	}

	return ret, errors.Errorf("unreachable")
}

type connectRun struct {
	*harness.PoolResult
	Retried     int
	FirstErrors *harness.ErrorCounter
}

func (e *chaosEnv) connectAll(ctx context.Context, clients []*harness.VClient, workers int) *connectRun {
	var mu sync.Mutex
	ret := &connectRun{FirstErrors: harness.NewErrorCounter()}

	ret.PoolResult = harness.ForEach(ctx, len(clients), workers, func(ctx context.Context, i int) error {
		outcome, err := connectWithRetry(ctx, clients[i], 5)

		mu.Lock()
		if outcome.attempts > 1 {
			ret.Retried++
		}
		mu.Unlock()

		for _, attemptErr := range outcome.errs {
			ret.FirstErrors.Add(attemptErr)
		}

		return err
	})

	return ret
}

func (e *chaosEnv) supervise(clients ...*harness.VClient) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, c := range clients {
		if e.supervised[c] {
			continue
		}
		e.supervised[c] = true

		e.superWG.Add(1)
		go func() {
			defer e.superWG.Done()
			c.Supervise(e.ctx, harness.SuperviseOpts{})
		}()
	}
}

func (e *chaosEnv) stopSupervisors() {
	e.cancel()
	e.superWG.Wait()
}

func (e *chaosEnv) ensurePopulation(t *testing.T) []*harness.VClient {
	t.Helper()

	e.mu.Lock()
	if e.population != nil {
		ret := e.population
		e.mu.Unlock()
		return ret
	}
	if e.popErr != nil {
		e.mu.Unlock()
		t.Skipf("The connected population could not be established: %+v", e.popErr)
	}
	e.mu.Unlock()

	fleet := e.ensureFleet(t)

	clients := make([]*harness.VClient, e.scale.Clients)
	for i := range clients {
		clients[i] = harness.NewVClient(fleet.Sessions[i], e.pool, e.clientOpts(i))
	}

	ctx, cancel := context.WithTimeout(t.Context(), scaled(4*time.Minute, 60*time.Millisecond, len(clients)))
	defer cancel()

	run := e.connectAll(ctx, clients, e.scale.ConnectWorkers)
	harness.LogPool("Connected the chaos population", run.PoolResult)

	var connected []*harness.VClient
	for _, c := range clients {
		if c.IsConnected() {
			connected = append(connected, c)
		}
	}

	e.set(t, "connect", run.PoolResult.String())
	e.set(t, "connectLatency", run.Latency.Summary())
	e.set(t, "connectRatePerSecond", run.Rate())
	e.set(t, "connectRetried", run.Retried)
	e.set(t, "connectAttemptErrors", run.FirstErrors.Classes())
	e.set(t, "connected", len(connected))
	e.set(t, "tcpConnections", e.pool.Len())

	e.mu.Lock()
	e.population = connected
	e.popTarget = len(clients)
	e.popRun = run
	if len(connected) == 0 {
		e.popErr = errors.Errorf("no client connected: %s", run.Errors)
	}
	e.mu.Unlock()

	e.supervise(connected...)

	if len(connected) < len(clients) {
		e.failf(t, "Only %d of %d clients connected. %s\nThe failures by attempt: %s",
			len(connected), len(clients), run.PoolResult, run.FirstErrors)
	}

	if len(connected) == 0 {
		t.FailNow()
	}

	return connected
}

func (e *chaosEnv) track(clients ...*harness.VClient) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.extra = append(e.extra, clients...)
}

func countConnected(clients []*harness.VClient) int {
	var ret int
	for _, c := range clients {
		if c.IsConnected() {
			ret++
		}
	}
	return ret
}

func (e *chaosEnv) waitConnected(t *testing.T, what string, clients []*harness.VClient,
	budget time.Duration) time.Duration {
	t.Helper()

	started := time.Now()
	lastLog := time.Now()

	for {
		n := countConnected(clients)
		if n == len(clients) {
			return time.Since(started)
		}

		if time.Since(lastLog) > 15*time.Second {
			lastLog = time.Now()
			zap.L().Info("Waiting for clients to connect",
				zap.String("what", what), zap.Int("connected", n), zap.Int("total", len(clients)),
				zap.Duration("elapsed", time.Since(started).Truncate(time.Second)))
		}

		if time.Since(started) > budget {
			errs := harness.NewErrorCounter()
			for _, c := range clients {
				if !c.IsConnected() {
					if err := c.StreamErr(); err != nil {
						errs.Add(err)
					} else {
						errs.Add(errors.New("never connected"))
					}
				}
			}
			e.fatalf(t, "Only %d of %d clients are connected after %s (%s). The last stream errors: %s",
				n, len(clients), budget, what, errs)
		}

		if err := harness.Sleep(t.Context(), time.Second); err != nil {
			t.FailNow()
		}
	}
}

func dropsSince(clients []*harness.VClient, since time.Time) []*harness.VClient {
	var ret []*harness.VClient
	for _, c := range clients {
		if c.DroppedAt().After(since) || !c.IsConnected() {
			ret = append(ret, c)
		}
	}
	return ret
}

func (e *chaosEnv) assertNoDrops(t *testing.T, what string, clients []*harness.VClient, since time.Time) {
	t.Helper()

	dropped := dropsSince(clients, since)
	if len(dropped) == 0 {
		return
	}

	errs := harness.NewErrorCounter()
	for _, c := range dropped {
		if err := c.StreamErr(); err != nil {
			errs.Add(err)
		}
	}

	e.failf(t, "%d of %d connected clients lost their stream %s. %s",
		len(dropped), len(clients), what, errs)
}

type invariantsOpts struct {
	connected    []*harness.VClient
	disconnected []*harness.FleetSession
	skipPeers    bool
}

func (e *chaosEnv) baselineLeaks(r *harness.AddressReport) (wg, quic []uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()

	return harness.NewLeaks(e.baselineLeakWG, r.LeakedWG), harness.NewLeaks(e.baselineLeakQUIC, r.LeakedQUIC)
}

func (e *chaosEnv) setBaselineLeaks(r *harness.AddressReport) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.baselineLeakWG = r.LeakedWG
	e.baselineLeakQUIC = r.LeakedQUIC
}

func (e *chaosEnv) newStalePeers(gateway string, stale []string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	prev := map[string]bool{}
	for _, key := range e.baselineStale[gateway] {
		prev[key] = true
	}

	var ret []string
	for _, key := range stale {
		if !prev[key] {
			ret = append(ret, key)
		}
	}
	return ret
}

func (e *chaosEnv) setBaselineStale(stale map[string][]string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.baselineStale == nil {
		e.baselineStale = map[string][]string{}
	}
	for gateway, keys := range stale {
		e.baselineStale[gateway] = keys
	}
}

func (e *chaosEnv) evalInvariants(ctx context.Context, o invariantsOpts) (*harness.AddressReport,
	map[string][]string, []string, error) {
	inv, err := e.h.ConnInventory(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	r := harness.CheckConnAddresses(inv)

	var violations []string

	leakWG, leakQUIC := e.baselineLeaks(r)
	if len(leakWG) > 0 {
		violations = append(violations, fmt.Sprintf(
			"%d WireGuard address indexes leaked during this phase, e.g. %v", len(leakWG), firstN(leakWG, 10)))
	}
	if len(leakQUIC) > 0 {
		violations = append(violations, fmt.Sprintf(
			"%d QUICv0 address indexes leaked during this phase, e.g. %v", len(leakQUIC), firstN(leakQUIC, 10)))
	}

	for _, v := range r.Violations() {
		if strings.Contains(v, "(leaked)") {
			continue
		}
		violations = append(violations, v)
	}

	byUID := inv.ByUID()

	var mismatched []string
	for _, c := range o.connected {
		sess := byUID[c.Session.UID]
		switch {
		case sess == nil:
			mismatched = append(mismatched, c.Session.UID+": the Session is gone")
		case sess.Status.Connection == nil:
			mismatched = append(mismatched, sess.Metadata.Name+": the client is connected but the Session is not")
		default:
			pub, err := c.X25519PublicKey()
			if err != nil || string(pub) != string(sess.Status.Connection.X25519PublicKey) {
				mismatched = append(mismatched, sess.Metadata.Name+": the Session uses another Connection than the client")
			}
		}
	}
	if len(mismatched) > 0 {
		violations = append(violations, fmt.Sprintf("%d connected clients do not match their Session, e.g. %v",
			len(mismatched), firstN(mismatched, 5)))
	}

	var zombies []string
	for _, fs := range o.disconnected {
		if sess := byUID[fs.UID]; sess != nil && sess.Status.Connection != nil {
			zombies = append(zombies, sess.Metadata.Name)
		}
	}
	if len(zombies) > 0 {
		violations = append(violations, fmt.Sprintf(
			"%d Sessions are still connected although their client is gone, e.g. %v",
			len(zombies), firstN(zombies, 5)))
	}

	stale := map[string][]string{}

	if !o.skipPeers && e.wgInspect {
		gws, err := e.h.ListGateways(ctx)
		if err != nil {
			return r, nil, violations, err
		}

		for _, gw := range gws {
			peers, err := e.h.GatewayWGPeers(ctx, gw)
			if err != nil {
				violations = append(violations, err.Error())
				continue
			}

			report := harness.CheckGatewayPeers(gw.Metadata.Name, peers, inv.Connected())
			stale[gw.Metadata.Name] = report.Stale
			report.Stale = e.newStalePeers(gw.Metadata.Name, report.Stale)

			if err := report.Err(); err != nil {
				violations = append(violations, err.Error())
			}
		}
	}

	return r, stale, violations, nil
}

func firstN[T any](vals []T, n int) []T {
	if len(vals) <= n {
		return vals
	}
	return vals[:n]
}

func (e *chaosEnv) checkInvariants(t *testing.T, what string, budget time.Duration,
	o invariantsOpts) *harness.AddressReport {
	t.Helper()

	started := time.Now()

	var last *harness.AddressReport
	var lastStale map[string][]string
	var lastViolations []string
	var lastErr error

	for {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		r, stale, violations, err := e.evalInvariants(ctx, o)
		cancel()

		if r != nil {
			last = r
		}
		if stale != nil {
			lastStale = stale
		}
		lastViolations, lastErr = violations, err

		if err == nil && len(violations) == 0 {
			zap.L().Info("The Connection invariants hold",
				zap.String("what", what), zap.String("report", r.String()),
				zap.Duration("settled", time.Since(started)))
			e.set(t, "invariants", r)
			e.set(t, "invariantsSettled", time.Since(started).String())
			e.setBaselineLeaks(r)
			e.setBaselineStale(stale)
			return r
		}

		if time.Since(started) > budget || t.Context().Err() != nil {
			break
		}

		if harness.Sleep(t.Context(), 5*time.Second) != nil {
			break
		}
	}

	if lastErr != nil {
		e.failf(t, "Could not evaluate the Connection invariants (%s): %+v", what, lastErr)
		return last
	}

	if last != nil {
		e.set(t, "invariants", last)
		e.setBaselineLeaks(last)
	}
	e.setBaselineStale(lastStale)

	e.failf(t, "The Connection invariants do not hold %s after %s (%v):\n  - %s",
		what, budget, last, strings.Join(lastViolations, "\n  - "))

	return last
}

func (e *chaosEnv) healthSnapshot(t *testing.T) harness.HealthSnapshot {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	ret, err := e.h.Health(ctx)
	if err != nil {
		t.Fatalf("Could not read the component health: %+v", err)
	}
	return ret
}

func (e *chaosEnv) assertHealthy(t *testing.T, before harness.HealthSnapshot, ignore ...string) {
	t.Helper()

	after := e.healthSnapshot(t)

	deltas := harness.RestartsSince(before, after, ignore...)
	if len(deltas) == 0 {
		return
	}

	var msgs []string
	for _, d := range deltas {
		msgs = append(msgs, d.String())
	}

	e.set(t, "restarts", deltas)
	e.failf(t, "Containers restarted during the phase:\n  - %s", strings.Join(msgs, "\n  - "))
}

func (e *chaosEnv) logUsage(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	usage, err := e.h.TopContainers(ctx)
	if err != nil {
		zap.L().Debug("Could not read the container usage", zap.Error(err))
		return
	}

	top := firstN(usage, 12)
	e.set(t, "topContainers", top)

	for _, u := range top {
		zap.L().Info("Container usage",
			zap.String("phase", phaseName(t)), zap.String("pod", u.Pod),
			zap.String("container", u.Container),
			zap.Int64("milliCPU", u.MilliCPU), zap.Int64("memoryMiB", u.MemoryMiB))
	}
}

func fdLimit() (uint64, uint64) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0, 0
	}
	return lim.Cur, lim.Max
}

func raiseFDLimit() (uint64, error) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0, err
	}
	if lim.Cur < lim.Max {
		lim.Cur = lim.Max
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
			return 0, err
		}
	}
	return lim.Cur, nil
}

func (e *chaosEnv) fdsNeeded() uint64 {
	s := e.scale
	conns := (s.Clients+s.StreamsPerConn-1)/s.StreamsPerConn + s.spare()
	return uint64(conns + s.LongLived + s.HTTPWorkers + s.IdleStreams + 8*s.DataPlane + 4096)
}

func sortedKeys[V any](m map[string]V) []string {
	ret := make([]string, 0, len(m))
	for k := range m {
		ret = append(ret, k)
	}
	sort.Strings(ret)
	return ret
}

func ChaosPhases(e *chaosEnv) []Phase {
	bind := func(fn func(t *testing.T, e *chaosEnv)) func(t *testing.T, h *harness.H) {
		return func(t *testing.T, h *harness.H) { fn(t, e) }
	}

	return []Phase{
		{"ChaosPreflight", bind(testChaosPreflight)},
		{"ChaosFleet", bind(testChaosFleet)},
		{"ChaosConnectStorm", bind(testChaosConnectStorm)},
		{"ChaosDataPlane", bind(testChaosDataPlane)},
		{"ChaosSteadyState", bind(testChaosSteadyState)},
		{"ChaosDNSBroadcast", bind(testChaosDNSBroadcast)},
		{"ChaosGatewayAgentRestart", bind(testChaosGatewayAgentRestart)},
		{"ChaosAPIServerRestart", bind(testChaosAPIServerRestart)},
		{"ChaosComponentRestarts", bind(testChaosComponentRestarts)},
		{"ChaosChurn", bind(testChaosChurn)},
		{"ChaosTakeoverRace", bind(testChaosTakeoverRace)},
		{"ChaosAbruptCancel", bind(testChaosAbruptCancel)},
		{"ChaosFrozenClients", bind(testChaosFrozenClients)},
		{"ChaosUninitializedStreams", bind(testChaosUninitializedStreams)},
		{"ChaosSessionDeletion", bind(testChaosSessionDeletion)},
		{"ChaosClientless", bind(testChaosClientless)},
		{"ChaosIngressAbuse", bind(testChaosIngressAbuse)},
		{"ChaosMultiNode", bind(testChaosMultiNode)},
		{"ChaosFinal", bind(testChaosFinal)},
	}
}

func RunChaos(t *testing.T) {
	if !harness.SuiteSelected(harness.SuiteChaos) {
		t.Skipf("The chaos suite is not selected. Run with %s=%s or `octelium-e2e test --suite=chaos`",
			harness.SuiteEnv, harness.SuiteChaos)
	}

	if initErr != nil {
		t.Fatalf("Could not initialize the e2e harness: %+v", initErr)
	}

	env, err := newChaosEnv(t, h)
	if err != nil {
		t.Fatalf("Could not initialize the chaos suite: %+v", err)
	}

	runPhases(t, ChaosPhases(env))
}
