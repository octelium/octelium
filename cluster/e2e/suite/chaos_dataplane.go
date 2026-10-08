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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	chaosUpstreamBody   = 16 * 1024
	dataPlaneGetTimeout = 10 * time.Second
	dataPlaneReady      = 90 * time.Second
	revokeBudget        = time.Minute
)

type targetAddr struct {
	addr    netip.Addr
	node    string
	gateway string
	pod     string
}

type chaosTarget struct {
	svc      *corev1.Service
	upstream *harness.CountingUpstream
	port     int
	addrs    []targetAddr
}

func (t *chaosTarget) url(addr netip.Addr, id string) string {
	return fmt.Sprintf("http://%s/?id=%s", net.JoinHostPort(addr.String(), strconv.Itoa(t.port)), id)
}

func (t *chaosTarget) family(v6 bool) []targetAddr {
	var ret []targetAddr
	for _, a := range t.addrs {
		if a.addr.Is6() == v6 {
			ret = append(ret, a)
		}
	}
	return ret
}

const sampleTargets = 4

func (t *chaosTarget) subset(v6 bool, idx int) []targetAddr {
	all := t.family(v6)
	if len(all) <= sampleTargets {
		return all
	}

	ret := make([]targetAddr, 0, sampleTargets)
	for j := range sampleTargets {
		ret = append(ret, all[(idx*sampleTargets+j)%len(all)])
	}
	return ret
}

func (t *chaosTarget) gateways() []string {
	seen := map[string]bool{}
	var ret []string
	for _, a := range t.addrs {
		if !seen[a.gateway] {
			seen[a.gateway] = true
			ret = append(ret, a.gateway)
		}
	}
	return ret
}

type chaosSample struct {
	idx int
	vc  *harness.VClient
	dp  *harness.DataPlane
}

func (s *chaosSample) name() string {
	opts := s.vc.Opts()
	return fmt.Sprintf("%s/%s", wantTunnel(opts.Tunnel), wantL3Mode(opts.L3Mode))
}

func modeFamilies(m userv1.ConnectRequest_Initialize_L3Mode) []bool {
	switch m {
	case userv1.ConnectRequest_Initialize_V4:
		return []bool{false}
	case userv1.ConnectRequest_Initialize_V6:
		return []bool{true}
	default:
		return []bool{false, true}
	}
}

func (e *chaosEnv) dataPlaneTLS() (*tls.Config, error) {
	roots, err := e.h.TLSRoots()
	if err != nil {
		return nil, err
	}
	return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, nil
}

func (e *chaosEnv) gatewayByNode(ctx context.Context) (map[string]*corev1.Gateway, error) {
	gws, err := e.h.ListGateways(ctx)
	if err != nil {
		return nil, err
	}

	ret := map[string]*corev1.Gateway{}
	for _, gw := range gws {
		ret[gw.GetStatus().GetNodeRef().GetName()] = gw
	}
	return ret, nil
}

func (e *chaosEnv) resolveTargetAddrs(ctx context.Context, svc *corev1.Service) ([]targetAddr, error) {
	byNode, err := e.gatewayByNode(ctx)
	if err != nil {
		return nil, err
	}

	var ret []targetAddr
	for _, addr := range svc.GetStatus().GetAddresses() {
		podName := addr.GetPodRef().GetName()
		if podName == "" {
			return nil, errors.Errorf("The Service address %v has no pod", addr.DualStackIP)
		}

		pod, err := e.h.K8sC().CoreV1().Pods(vutils.K8sNS).Get(ctx, podName, k8smetav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		gw := byNode[pod.Spec.NodeName]
		if gw == nil {
			return nil, errors.Errorf("The node %s of the pod %s runs no Gateway", pod.Spec.NodeName, podName)
		}

		for _, s := range []string{addr.GetDualStackIP().GetIpv4(), addr.GetDualStackIP().GetIpv6()} {
			if s == "" {
				continue
			}
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return nil, err
			}
			ret = append(ret, targetAddr{
				addr:    ip,
				node:    pod.Spec.NodeName,
				gateway: gw.GetStatus().GetId(),
				pod:     podName,
			})
		}
	}

	return ret, nil
}

func (e *chaosEnv) ensureTarget(t *testing.T) *chaosTarget {
	t.Helper()

	e.mu.Lock()
	target := e.target
	e.mu.Unlock()
	if target != nil {
		return target
	}

	h := e.h

	host := h.ExternalIP
	if host == "" {
		host = "127.0.0.1"
	}

	upstream, err := harness.NewCountingUpstream(net.JoinHostPort(host, "0"), chaosUpstreamBody)
	require.NoError(t, err)

	replicas := max(1, h.Scenario.Topology.Nodes)

	svc, err := h.CoreC().CreateService(t.Context(), &corev1.Service{
		Metadata: &metav1.Metadata{Name: fmt.Sprintf("chaos-%s", utilrand.GetRandomStringCanonical(6))},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{Url: upstream.URL()},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: harness.InlineAllowAny("allow-chaos"),
			},
			Deployment: &corev1.Service_Spec_Deployment{Replicas: uint32(replicas)},
		},
	})
	if err != nil {
		upstream.Close()
		t.Fatalf("Could not create the chaos target Service: %+v", err)
	}

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, err := h.CoreC().DeleteService(ctx, &metav1.DeleteOptions{Uid: svc.Metadata.Uid}); err != nil &&
			!grpcerr.IsNotFound(err) {
			zap.L().Warn("Could not delete the chaos target Service", zap.Error(err))
		}
		upstream.Close()
	}

	ret := &chaosTarget{svc: svc, upstream: upstream}

	e.mu.Lock()
	e.target = ret
	e.mu.Unlock()

	e.onClose(cleanup)

	h.MustWaitService(t, svc.Metadata.Name)

	h.Eventually(t, "the chaos target Service to publish an address per replica", 3*time.Minute,
		func(ctx context.Context) error {
			cur, err := h.CoreC().GetService(ctx, &metav1.GetOptions{Uid: svc.Metadata.Uid})
			if err != nil {
				return err
			}
			if got := len(cur.GetStatus().GetAddresses()); got < replicas {
				return errors.Errorf("the Service has %d addresses, want %d", got, replicas)
			}
			for _, addr := range cur.Status.Addresses {
				if addr.GetDualStackIP().GetIpv4() == "" || (e.ipv6 && addr.GetDualStackIP().GetIpv6() == "") {
					return errors.Errorf("the Service address %v is incomplete", addr.DualStackIP)
				}
			}
			if cur.Status.Port == 0 {
				return errors.Errorf("the Service has no port yet")
			}

			addrs, err := e.resolveTargetAddrs(ctx, cur)
			if err != nil {
				return err
			}

			ret.svc = cur
			ret.port = int(cur.Status.Port)
			ret.addrs = addrs
			return nil
		})

	var desc []string
	for _, a := range ret.addrs {
		desc = append(desc, fmt.Sprintf("%s@%s/%s", a.addr, a.node, a.gateway))
	}
	e.set(t, "target", map[string]any{
		"service":  svc.Metadata.Name,
		"port":     ret.port,
		"addrs":    desc,
		"gateways": len(ret.gateways()),
	})

	return ret
}

func (e *chaosEnv) newSample(t *testing.T, c *harness.VClient, o harness.DataPlaneOpts) (*chaosSample, error) {
	tlsCfg, err := e.dataPlaneTLS()
	if err != nil {
		return nil, err
	}
	o.TLSConfig = tlsCfg

	dp, err := c.DataPlane(o)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(t.Context(), dataPlaneReady)
	defer cancel()

	if err := dp.WaitReady(ctx); err != nil {
		dp.Close()
		return nil, err
	}

	return &chaosSample{vc: c, dp: dp}, nil
}

var requestSeq atomic.Int64

func nextRequestID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, requestSeq.Add(1))
}

func (e *chaosEnv) sampleGet(ctx context.Context, target *chaosTarget, s *chaosSample,
	a targetAddr, id string) error {
	code, body, err := s.dp.Get(ctx, target.url(a.addr, id), dataPlaneGetTimeout)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return errUnexpectedStatus(code, http.StatusOK)
	}
	if len(body) != chaosUpstreamBody {
		return errors.Errorf("the upstream answered %d bytes, want %d", len(body), chaosUpstreamBody)
	}
	return nil
}

func (e *chaosEnv) sampleReachesAll(ctx context.Context, target *chaosTarget, s *chaosSample) error {
	for _, v6 := range modeFamilies(s.vc.Opts().L3Mode) {
		for _, a := range target.subset(v6, s.idx) {
			if err := e.sampleGet(ctx, target, s, a, nextRequestID("probe")); err != nil {
				return errors.Wrapf(err, "%s to %s", s.name(), a.addr)
			}
		}
	}
	return nil
}

func (e *chaosEnv) probeSamples(ctx context.Context, every time.Duration, out *probeStats) {
	e.mu.Lock()
	samples := e.samples
	target := e.target
	e.mu.Unlock()

	if len(samples) == 0 || target == nil {
		return
	}

	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var wg sync.WaitGroup
		for _, s := range samples {
			wg.Add(1)
			go func() {
				defer wg.Done()
				started := time.Now()
				err := e.sampleReachesAll(ctx, target, s)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					out.errs.Add(err)
					return
				}
				out.lat.Add(time.Since(started))
			}()
		}
		wg.Wait()
	}
}

func (e *chaosEnv) waitSamples(t *testing.T, what string, budget time.Duration) time.Duration {
	t.Helper()

	e.mu.Lock()
	samples := e.samples
	target := e.target
	e.mu.Unlock()

	if len(samples) == 0 {
		return 0
	}

	return e.h.Within(t, what, budget, func(ctx context.Context) error {
		errs := harness.NewErrorCounter()
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, s := range samples {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := e.sampleReachesAll(ctx, target, s); err != nil {
					mu.Lock()
					errs.Add(err)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		if errs.Total() > 0 {
			return errors.Errorf("%d of %d sample clients cannot reach the Service: %s",
				errs.Total(), len(samples), errs)
		}
		return nil
	})
}

func (e *chaosEnv) rebuildSamples(t *testing.T) {
	t.Helper()

	e.mu.Lock()
	samples := e.samples
	e.mu.Unlock()

	var rebuilt int
	for _, s := range samples {
		if s.dp.Matches(s.vc.State()) {
			continue
		}

		s.dp.Close()

		next, err := e.newSample(t, s.vc, harness.DataPlaneOpts{})
		if err != nil {
			e.fatalf(t, "Could not rebuild the data plane of %s after it reconnected: %+v", s.name(), err)
		}

		e.mu.Lock()
		s.dp = next.dp
		e.mu.Unlock()
		rebuilt++
	}

	e.set(t, "samplesRebuilt", rebuilt)
}

func (e *chaosEnv) pickSamples(population []*harness.VClient, n int) []*harness.VClient {
	type combo struct {
		tunnel userv1.ConnectRequest_Initialize_ConnectionType
		mode   userv1.ConnectRequest_Initialize_L3Mode
	}

	byCombo := map[combo][]*harness.VClient{}
	var order []combo
	for _, c := range population {
		k := combo{c.Opts().Tunnel, c.Opts().L3Mode}
		if _, ok := byCombo[k]; !ok {
			order = append(order, k)
		}
		byCombo[k] = append(byCombo[k], c)
	}

	var ret []*harness.VClient
	for round := 0; len(ret) < n; round++ {
		added := false
		for _, k := range order {
			if round < len(byCombo[k]) && len(ret) < n {
				ret = append(ret, byCombo[k][round])
				added = true
			}
		}
		if !added {
			break
		}
	}

	return ret
}

func testChaosDataPlane(t *testing.T, e *chaosEnv) {
	population := e.ensurePopulation(t)
	target := e.ensureTarget(t)

	before := e.healthSnapshot(t)

	picked := e.pickSamples(population, e.scale.DataPlane)

	var mu sync.Mutex
	var samples []*chaosSample
	firstOK := &harness.Latencies{}

	res := harness.ForEach(t.Context(), len(picked), 8, func(ctx context.Context, i int) error {
		started := time.Now()

		s, err := e.newSample(t, picked[i], harness.DataPlaneOpts{})
		if err != nil {
			return errors.Wrapf(err, "the data plane of %s", picked[i].Opts().Tunnel)
		}
		s.idx = i

		mu.Lock()
		samples = append(samples, s)
		mu.Unlock()

		err = e.h.EventuallyErr(ctx, "the first request through the tunnel", harness.DecisionBudget,
			func(ctx context.Context) error { return e.sampleReachesAll(ctx, target, s) })
		if err != nil {
			return err
		}

		firstOK.Add(time.Since(started))
		return nil
	})

	e.mu.Lock()
	e.samples = samples
	e.mu.Unlock()

	e.set(t, "samples", len(samples))
	e.set(t, "timeToFirstResponse", firstOK.Summary())

	if res.Failed() > 0 {
		e.failf(t, "%d of %d sample clients could not use their tunnel: %s", res.Failed(), res.Total, res.Errors)
	}

	t.Run("Steady", func(t *testing.T) {
		const perSample = 10

		var ids []string
		var idsMu sync.Mutex

		res := harness.ForEach(t.Context(), len(samples)*perSample, 16, func(ctx context.Context, i int) error {
			s := samples[i%len(samples)]
			for _, v6 := range modeFamilies(s.vc.Opts().L3Mode) {
				for _, a := range target.subset(v6, s.idx) {
					id := nextRequestID("steady")
					idsMu.Lock()
					ids = append(ids, id)
					idsMu.Unlock()
					if err := e.sampleGet(ctx, target, s, a, id); err != nil {
						return err
					}
				}
			}
			return nil
		})

		e.set(t, "requests", res.String())
		if res.Failed() > 0 {
			e.failf(t, "%d tunneled requests failed: %s", res.Failed(), res.Errors)
		}

		var lost, duplicated int
		for _, id := range ids {
			switch n := target.upstream.Seen(id); {
			case n == 0:
				lost++
			case n > 1:
				duplicated++
			}
		}
		if lost > 0 || duplicated > 0 {
			e.failf(t, "Of %d tunneled requests the upstream never saw %d and saw %d more than once",
				len(ids), lost, duplicated)
		}
	})

	t.Run("Routing", func(t *testing.T) {
		var wrong []string
		var checked, failed int

		checkRoute := func(s *chaosSample, a targetAddr) []string {
			gw := s.dp.GatewayFor(a.addr)
			if gw == nil {
				return []string{fmt.Sprintf("%s: no Gateway routes %s", s.name(), a.addr)}
			}
			if gw.Id != a.gateway {
				return []string{fmt.Sprintf("%s: %s is routed to %s, it lives behind %s",
					s.name(), a.addr, gw.Id, a.gateway)}
			}

			var ret []string

			beforeStats, err := s.dp.Stats()
			require.NoError(t, err)

			for range 3 {
				if err := e.sampleGet(t.Context(), target, s, a, nextRequestID("route")); err != nil {
					ret = append(ret, fmt.Sprintf("%s: %+v", s.name(), err))
				}
			}

			afterStats, err := s.dp.Stats()
			require.NoError(t, err)

			if got := harness.DominantGateway(harness.StatsDelta(beforeStats, afterStats)); got != a.gateway {
				ret = append(ret, fmt.Sprintf("%s: the traffic to %s went through %q, want %q",
					s.name(), a.addr, got, a.gateway))
			}

			return ret
		}

		for _, s := range samples {
			for _, v6 := range modeFamilies(s.vc.Opts().L3Mode) {
				for _, a := range target.subset(v6, s.idx) {
					checked++
					if problems := checkRoute(s, a); len(problems) > 0 {
						failed++
						wrong = append(wrong, problems...)
					}
				}
			}
		}

		e.set(t, "routesChecked", checked)
		e.set(t, "routesWrong", failed)
		if failed > 0 {
			e.failf(t, "%d of %d routes are wrong:\n  - %s", failed, checked, joinLines(wrong))
		}
	})

	t.Run("L3ModeEnforcement", func(t *testing.T) {
		if !e.ipv6 {
			t.Skip("The Cluster is not dual-stack")
		}
		testChaosL3Enforcement(t, e, target)
	})

	t.Run("SourceSpoofing", func(t *testing.T) {
		testChaosSourceSpoofing(t, e, target, population)
	})

	e.assertHealthy(t, before)
	e.logUsage(t)
}

func joinLines(vals []string) string {
	ret := ""
	for i, v := range firstN(vals, 20) {
		if i > 0 {
			ret += "\n  - "
		}
		ret += v
	}
	if len(vals) > 20 {
		ret += fmt.Sprintf("\n  ... and %d more", len(vals)-20)
	}
	return ret
}

func (e *chaosEnv) freshClient(t *testing.T, tunnel userv1.ConnectRequest_Initialize_ConnectionType,
	mode userv1.ConnectRequest_Initialize_L3Mode) *harness.VClient {
	t.Helper()

	sess := e.takeSpare(t, 1)[0]
	c := harness.NewVClient(sess, e.dedicated, harness.VClientOpts{Tunnel: tunnel, L3Mode: mode})
	e.track(c)

	ctx, cancel := context.WithTimeout(t.Context(), 2*harness.VClientInitBudget)
	defer cancel()

	if _, err := connectWithRetry(ctx, c, 5); err != nil {
		t.Fatalf("Could not connect a fresh client: %+v", err)
	}

	return c
}

func (e *chaosEnv) assertUnreachable(t *testing.T, what string, s *chaosSample, target *chaosTarget, a targetAddr) {
	t.Helper()

	id := nextRequestID("spoof")
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	if err := e.sampleGet(ctx, target, s, a, id); err == nil {
		e.failf(t, "%s: a request from %v reached %s", what, s.dp.Addrs(), a.addr)
	}

	if n := target.upstream.Seen(id); n > 0 {
		e.failf(t, "%s: the upstream received the request %d time(s)", what, n)
	}
}

func testChaosL3Enforcement(t *testing.T, e *chaosEnv, target *chaosTarget) {
	tunnels := []userv1.ConnectRequest_Initialize_ConnectionType{userv1.ConnectRequest_Initialize_WIREGUARD}
	if e.quic {
		tunnels = append(tunnels, userv1.ConnectRequest_Initialize_QUICV0)
	}

	v6 := target.family(true)
	require.NotEmpty(t, v6)

	for _, tunnel := range tunnels {
		t.Run(wantTunnel(tunnel).String(), func(t *testing.T) {
			c := e.freshClient(t, tunnel, userv1.ConnectRequest_Initialize_V4)

			state := c.State()
			require.NotNil(t, state)

			var ownV6 netip.Addr
			for _, addr := range state.Addresses {
				if pfx, err := netip.ParsePrefix(addr.V6); err == nil {
					ownV6 = pfx.Addr()
				}
			}
			if !ownV6.IsValid() {
				t.Skip("The IPv4-only Connection has no IPv6 address to abuse")
			}

			s, err := e.newSample(t, c, harness.DataPlaneOpts{
				Addresses: append([]netip.Addr{}, ownV6),
			})
			if err != nil {
				t.Fatalf("Could not build the abusive data plane: %+v", err)
			}
			defer s.dp.Close()

			e.assertUnreachable(t, "an IPv4-only Connection sending IPv6", s, target, v6[0])
		})
	}
}

func testChaosSourceSpoofing(t *testing.T, e *chaosEnv, target *chaosTarget, population []*harness.VClient) {
	tunnels := []userv1.ConnectRequest_Initialize_ConnectionType{userv1.ConnectRequest_Initialize_WIREGUARD}
	if e.quic {
		tunnels = append(tunnels, userv1.ConnectRequest_Initialize_QUICV0)
	}

	v4 := target.family(false)
	require.NotEmpty(t, v4)

	var victim netip.Addr
	for _, c := range population {
		if state := c.State(); state != nil && len(state.Addresses) > 0 {
			if pfx, err := netip.ParsePrefix(state.Addresses[0].V4); err == nil {
				victim = pfx.Addr()
				break
			}
		}
	}
	require.True(t, victim.IsValid(), "no connected client has an IPv4 address to impersonate")

	for _, tunnel := range tunnels {
		t.Run(wantTunnel(tunnel).String(), func(t *testing.T) {
			c := e.freshClient(t, tunnel, userv1.ConnectRequest_Initialize_BOTH)

			s, err := e.newSample(t, c, harness.DataPlaneOpts{Addresses: []netip.Addr{victim}})
			if err != nil {
				t.Fatalf("Could not build the spoofing data plane: %+v", err)
			}
			defer s.dp.Close()

			e.assertUnreachable(t, "a Connection impersonating "+victim.String(), s, target, v4[0])
		})
	}
}

func (e *chaosEnv) victimDataPlanes(t *testing.T, victims []*harness.VClient) []*chaosSample {
	t.Helper()

	target := e.ensureTarget(t)

	var ret []*chaosSample
	for _, c := range victims {
		if len(ret) >= 4 {
			break
		}

		s, err := e.newSample(t, c, harness.DataPlaneOpts{})
		if err != nil {
			t.Fatalf("Could not build the data plane of a client to delete: %+v", err)
		}
		t.Cleanup(s.dp.Close)

		e.h.Eventually(t, "the client to delete to reach the Service", harness.DecisionBudget,
			func(ctx context.Context) error { return e.sampleReachesAll(ctx, target, s) })

		ret = append(ret, s)
	}

	return ret
}

func (e *chaosEnv) assertDataPlaneRevoked(t *testing.T, s *chaosSample) {
	t.Helper()

	target := e.ensureTarget(t)

	revoked := e.h.Within(t, fmt.Sprintf("the deleted Session of %s to lose its tunnel", s.name()),
		revokeBudget, func(ctx context.Context) error {
			if err := e.sampleReachesAll(ctx, target, s); err == nil {
				return errors.Errorf("the deleted Session can still reach the Service")
			}
			return nil
		})

	e.set(t, "timeToRevoke/"+s.name(), revoked.String())

	e.h.Consistently(t, "the deleted Session to stay locked out", 10*time.Second,
		func(ctx context.Context) error {
			if err := e.sampleReachesAll(ctx, target, s); err == nil {
				return errors.Errorf("the deleted Session reached the Service again")
			}
			return nil
		})
}
