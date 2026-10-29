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

package udp

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	v1 "github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

const udpBufSize = 1500

func setTestMeterProvider(t *testing.T) *sdkmetric.ManualReader {
	prevProvider := otel.GetMeterProvider()
	t.Cleanup(func() {
		otel.SetMeterProvider(prevProvider)
	})

	reader := sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))

	return reader
}

func TestUDPDatagramBoundaries(t *testing.T) {
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.Nil(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, addr, err := upstream.ReadFromUDP(buf)
			if err != nil {
				return
			}
			body := buf[:n]
			if string(body) == "large-reply" {
				body = bytes.Repeat([]byte("r"), udpBufSize+1)
			} else if string(body) == "empty-reply" {
				body = nil
			}
			_, _ = upstream.WriteToUDP(body, addr)
		}
	}()
	t.Cleanup(func() { upstream.Close(); <-done })
	srv := newTestUDPServer(t, upstream.LocalAddr().String())
	addr := fmt.Sprintf("127.0.0.1:%d", srv.lis.LocalAddr().(*net.UDPAddr).Port)
	for _, tc := range []struct {
		name string
		body []byte
		want []byte
	}{
		{"Empty", []byte{}, []byte{}},
		{"EmptyReply", []byte("empty-reply"), []byte{}},
		{"LargerThanMTU", bytes.Repeat([]byte("q"), udpBufSize+1), bytes.Repeat([]byte("q"), udpBufSize+1)},
		{"LargeReply", []byte("large-reply"), bytes.Repeat([]byte("r"), udpBufSize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("udp4", addr)
			require.Nil(t, err)
			defer conn.Close()
			require.Nil(t, conn.SetDeadline(time.Now().Add(750*time.Millisecond)))
			_, err = conn.Write(tc.body)
			require.Nil(t, err)
			buf := make([]byte, 65535)
			n, err := conn.Read(buf)
			require.Nil(t, err)
			assert.Equal(t, len(tc.want), n)
			assert.True(t, bytes.Equal(tc.want, buf[:n]), "The UDP datagram was changed")
		})
	}
}

func newTestUDPServer(t *testing.T, upstream string) *Server {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	require.Nil(t, err)
	cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{V4: "127.0.0.0/8"}
	_, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	require.Nil(t, err)
	adminSrv := admin.NewServer(&admin.Opts{OcteliumC: tst.C.OcteliumC, IsEmbedded: true})
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_UDP, Port: uint32(tests.GetPort()),
			Authorization: &corev1.Service_Spec_Authorization{InlinePolicies: []*corev1.InlinePolicy{
				{Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{
					{Effect: corev1.Policy_Spec_Rule_ALLOW, Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}},
				}}},
			}},
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "udp://" + upstream}},
			},
		},
	})
	require.Nil(t, err)
	vc, err := vcache.NewCache(ctx)
	require.Nil(t, err)
	vc.SetService(svc)
	oc, err := octovigilc.NewClient(ctx, &octovigilc.Opts{OcteliumC: tst.C.OcteliumC, VCache: vc})
	require.Nil(t, err)
	srv, err := New(ctx, &modes.Opts{OcteliumC: tst.C.OcteliumC, VCache: vc, OctovigilC: oc,
		LBManager: loadbalancer.NewLbManager(tst.C.OcteliumC, vc)})
	require.Nil(t, err)
	usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, user.NewServer(tst.C.OcteliumC), nil)
	require.Nil(t, err)
	require.Nil(t, usr.Connect())
	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{{V4: "127.0.0.1/32"}},
		L3Mode:    corev1.Session_Status_Connection_V4,
		Type:      corev1.Session_Status_Connection_WIREGUARD,
	}
	usr.Session, err = tst.C.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	require.Nil(t, err)
	oc.GetCache().SetSession(usr.Session)
	require.Nil(t, srv.Run(ctx))
	t.Cleanup(func() { srv.Close() })
	return srv
}

func TestConcurrentDatagrams(t *testing.T) {
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.Nil(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, addr, err := upstream.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = upstream.WriteToUDP(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { upstream.Close(); <-done })
	srv := newTestUDPServer(t, upstream.LocalAddr().String())
	addr := fmt.Sprintf("127.0.0.1:%d", srv.lis.LocalAddr().(*net.UDPAddr).Port)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			conn, err := net.Dial("udp4", addr)
			if !assert.Nil(t, err) {
				return
			}
			defer conn.Close()
			assert.Nil(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
			for _, size := range []int{1, 32, udpBufSize - 1, udpBufSize} {
				body := bytes.Repeat([]byte{byte(i)}, size)
				if _, err := conn.Write(body); !assert.Nil(t, err) {
					return
				}
				buf := make([]byte, 65535)
				n, err := conn.Read(buf)
				if !assert.Nil(t, err) {
					return
				}
				assert.Equal(t, body, buf[:n])
			}
		})
	}
	wg.Wait()
}

func TestPacketServiceUnavailable(t *testing.T) {
	vc, err := vcache.NewCache(t.Context())
	require.Nil(t, err)
	srv := &Server{vCache: vc}
	assert.NotNil(t, srv.handlePacket(t.Context(), nil, 0, &net.UDPAddr{}))
	vc.SetService(&corev1.Service{Spec: &corev1.Service_Spec{IsDisabled: true}})
	assert.Nil(t, srv.handlePacket(t.Context(), []byte("disabled"), 8, &net.UDPAddr{}))
}

func findSumDataPointByState(t *testing.T, rm *metricdata.ResourceMetrics, name, state string) (metricdata.DataPoint[int64], bool) {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			assert.True(t, ok, name)
			for _, dp := range sum.DataPoints {
				stateVal, ok := dp.Attributes.Value("state")
				if ok && stateVal.AsString() == state {
					return dp, true
				}
			}
		}
	}
	return metricdata.DataPoint[int64]{}, false
}

func findSumDataPoint(t *testing.T, rm *metricdata.ResourceMetrics, name string) metricdata.DataPoint[int64] {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			assert.True(t, ok, name)
			assert.Len(t, sum.DataPoints, 1)
			return sum.DataPoints[0]
		}
	}
	t.Fatalf("metric %s not found", name)
	return metricdata.DataPoint[int64]{}
}

type tstSrv struct {
	lis  *net.UDPConn
	port int
}

func newTestServer(port int) *tstSrv {

	return &tstSrv{
		port: port,
	}
}

func (s *tstSrv) run(t *testing.T, ctx context.Context) {
	var err error

	s.lis, err = net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: s.port,
	})
	assert.Nil(t, err)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				buf := make([]byte, udpBufSize)
				n, addr, err := s.lis.ReadFromUDP(buf)
				if err != nil {
					time.Sleep(100 * time.Millisecond)
					continue
				}

				s.lis.WriteToUDP(buf[:n], addr)
			}

		}
	}()
}

func (s *tstSrv) close() {
	if s.lis != nil {
		s.lis.Close()
	}
}

func TestServer(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	upstreamPort := tests.GetPort()

	upstreamSrv := newTestServer(upstreamPort)
	upstreamSrv.run(t, ctx)
	defer upstreamSrv.close()

	svc, err := adminSrv.CreateService(ctx, &v1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &v1.Service_Spec{
			Port: uint32(tests.GetPort()),
			Mode: v1.Service_Spec_UDP,

			Config: &v1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("udp://localhost:%d", upstreamPort),
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)
	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	/*
		logman, err := logmanager.NewLogManager(ctx, &logmanager.LogManagerOpts{})
		assert.Nil(t, err)

		metricsStore, err := metricsstore.NewMetricsStore(ctx, nil)
		assert.Nil(t, err)
	*/

	udpConnTrackTimeout = 200 * time.Millisecond

	metricsReader := setTestMeterProvider(t)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		// LogManager:   logman,
		LBManager: loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		// MetricsStore: metricsStore,
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err)

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", svc.Spec.Port))
	assert.Nil(t, err)

	{
		time.Sleep(1 * time.Second)
		c, err := net.DialUDP("udp", nil, udpAddr)
		assert.Nil(t, err)

		{

			msg := utilrand.GetRandomBytesMust(32)

			_, err = c.Write(msg)
			assert.Nil(t, err)
			err = c.SetDeadline(time.Now().Add(2 * time.Second))
			assert.Nil(t, err)

			buf := make([]byte, 4096)
			n, err := c.Read(buf)
			assert.NotNil(t, err)
			assert.Equal(t, 0, n)
		}
	}

	{
		var rm metricdata.ResourceMetrics
		assert.Nil(t, metricsReader.Collect(ctx, &rm))

		dp, found := findSumDataPointByState(t, &rm, "req.total", "DENIED")
		assert.True(t, found)
		assert.True(t, dp.Value > 0)
	}

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	c, err := net.DialUDP("udp", nil, udpAddr)
	assert.Nil(t, err)

	for i := 0; i < 5; i++ {
		msg := utilrand.GetRandomBytesMust(32)

		_, err = c.Write(msg)
		assert.Nil(t, err)

		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		assert.Nil(t, err)
		assert.Equal(t, msg, buf[:n])
		time.Sleep(100 * time.Millisecond)
	}

	err = c.Close()
	assert.Nil(t, err)

	time.Sleep(2 * time.Second)

	{
		var rm metricdata.ResourceMetrics
		assert.Nil(t, metricsReader.Collect(ctx, &rm))

		dp, found := findSumDataPointByState(t, &rm, "req.total", "ALLOWED")
		assert.True(t, found)
		assert.Equal(t, int64(1), dp.Value)

		sentDP := findSumDataPoint(t, &rm, "req.bytes_sent")
		assert.Equal(t, int64(5*32), sentDP.Value)

		receivedDP := findSumDataPoint(t, &rm, "req.bytes_received")
		assert.Equal(t, int64(5*32), receivedDP.Value)
	}

	err = srv.Close()
	assert.Nil(t, err)
}

func TestUDPLargeDatagrams(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			ip := net.IPv4(127, 0, 0, 1)
			if network == "udp6" {
				ip = net.IPv6loopback
			}
			upstream, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
			require.Nil(t, err)
			defer upstream.Close()
			srv := newTestUDPServer(t, upstream.LocalAddr().String())
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: srv.lis.LocalAddr().(*net.UDPAddr).Port}
			for _, size := range []int{1, 1499, 1500, 1501, 8192, 32768, 65507} {
				for _, direction := range []string{"Request", "Reply", "Both"} {
					t.Run(fmt.Sprintf("%s/%d", direction, size), func(t *testing.T) {
						client, err := net.DialUDP("udp4", nil, addr)
						require.Nil(t, err)
						defer client.Close()
						require.Nil(t, client.SetDeadline(time.Now().Add(3*time.Second)))
						require.Nil(t, upstream.SetDeadline(time.Now().Add(3*time.Second)))
						requestSize, replySize := 19, 29
						if direction != "Reply" {
							requestSize = size
						}
						if direction != "Request" {
							replySize = size
						}
						request := utilrand.GetRandomBytesMust(requestSize)
						reply := utilrand.GetRandomBytesMust(replySize)
						buf := make([]byte, 65535)
						exchange := func(request, reply []byte) {
							_, err := client.Write(request)
							require.Nil(t, err)
							n, source, err := upstream.ReadFromUDP(buf)
							require.Nil(t, err)
							require.Equal(t, len(request), n)
							require.True(t, bytes.Equal(request, buf[:n]), "The UDP request was changed")
							_, err = upstream.WriteToUDP(reply, source)
							require.Nil(t, err)
							n, err = client.Read(buf)
							require.Nil(t, err)
							require.Equal(t, len(reply), n)
							require.True(t, bytes.Equal(reply, buf[:n]), "The UDP reply was changed")
						}
						exchange(request, reply)
						srv.dctxMap.mu.Lock()
						dctx := srv.dctxMap.dctxMap[client.LocalAddr().String()]
						srv.dctxMap.mu.Unlock()
						require.NotNil(t, dctx)
						exchange([]byte("small request"), []byte("small reply"))
						assert.Eventually(t, func() bool {
							return dctx.bytesFromClient.Load() == int64(len(request)+len("small request")) &&
								dctx.bytesToClient.Load() == int64(len(reply)+len("small reply")) &&
								dctx.packetsFromClient.Load() == 2 && dctx.packetsToClient.Load() == 2
						}, time.Second, time.Millisecond)
					})
				}
			}
		})
	}
}

func TestUDPOversizedIPv6ReplyIsDropped(t *testing.T) {
	upstream, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	require.Nil(t, err)
	defer upstream.Close()
	srv := newTestUDPServer(t, upstream.LocalAddr().String())
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: srv.lis.LocalAddr().(*net.UDPAddr).Port,
	})
	require.Nil(t, err)
	defer client.Close()
	require.Nil(t, client.SetDeadline(time.Now().Add(3*time.Second)))
	require.Nil(t, upstream.SetDeadline(time.Now().Add(3*time.Second)))
	request := []byte("request")
	_, err = client.Write(request)
	require.Nil(t, err)
	buf := make([]byte, 65535)
	n, source, err := upstream.ReadFromUDP(buf)
	require.Nil(t, err)
	require.Equal(t, request, buf[:n])
	srv.dctxMap.mu.Lock()
	dctx := srv.dctxMap.dctxMap[client.LocalAddr().String()]
	srv.dctxMap.mu.Unlock()
	require.NotNil(t, dctx)
	_, err = upstream.WriteToUDP(utilrand.GetRandomBytesMust(65527), source)
	require.Nil(t, err)
	require.Nil(t, client.SetReadDeadline(time.Now().Add(150*time.Millisecond)))
	n, err = client.Read(buf)
	require.Error(t, err)
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout())
	assert.Zero(t, n)
	assert.Zero(t, dctx.bytesToClient.Load())
	assert.Zero(t, dctx.packetsToClient.Load())
	require.Eventually(t, func() bool {
		srv.dctxMap.mu.Lock()
		defer srv.dctxMap.mu.Unlock()
		return len(srv.dctxMap.dctxMap) == 0
	}, time.Second, time.Millisecond)
	require.Nil(t, client.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = client.Write(request)
	require.Nil(t, err)
	n, source, err = upstream.ReadFromUDP(buf)
	require.Nil(t, err)
	require.Equal(t, request, buf[:n])
	_, err = upstream.WriteToUDP([]byte("reply"), source)
	require.Nil(t, err)
	n, err = client.Read(buf)
	require.Nil(t, err)
	assert.Equal(t, "reply", string(buf[:n]))
}

func newUDPTestPair(t *testing.T, network string) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	ip := net.IPv4(127, 0, 0, 1)
	if network == "udp6" {
		ip = net.IPv6loopback
	}
	lis, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	require.Nil(t, err)
	t.Cleanup(func() { lis.Close() })
	conn, err := net.DialUDP(network, nil, lis.LocalAddr().(*net.UDPAddr))
	require.Nil(t, err)
	t.Cleanup(func() { conn.Close() })
	require.Nil(t, lis.SetDeadline(time.Now().Add(3*time.Second)))
	require.Nil(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	return lis, conn
}

func TestReadUDPDatagramSizes(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, connected := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/Connected%t", network, connected), func(t *testing.T) {
				lis, conn := newUDPTestPair(t, network)
				receiver, peer := lis, conn
				send := conn.Write
				if connected {
					receiver, peer = conn, lis
					send = func(buf []byte) (int, error) {
						return lis.WriteToUDP(buf, conn.LocalAddr().(*net.UDPAddr))
					}
				}
				maxSize := 65507
				if network == "udp6" {
					maxSize = 65527
				}
				buf := make([]byte, 64*1024)
				for _, size := range []int{0, 1, 1500, 1501, maxSize} {
					body := utilrand.GetRandomBytesMust(size)
					_, err := send(body)
					require.Nil(t, err)
					n, source, err := readUDPDatagram(receiver, buf)
					require.Nil(t, err)
					require.Equal(t, size, n)
					assert.True(t, bytes.Equal(body, buf[:n]), "The UDP datagram was changed")
					require.NotNil(t, source)
					assert.Equal(t, peer.LocalAddr().String(), source.String())
				}
			})
		}
	}
}

func TestReadUDPDatagramDropsTruncated(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, connected := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/Connected%t", network, connected), func(t *testing.T) {
				lis, conn := newUDPTestPair(t, network)
				receiver, peer := lis, conn
				send := conn.Write
				if connected {
					receiver, peer = conn, lis
					send = func(buf []byte) (int, error) {
						return lis.WriteToUDP(buf, conn.LocalAddr().(*net.UDPAddr))
					}
				}
				buf := make([]byte, 32)
				for _, size := range []int{33, 128} {
					_, err := send(bytes.Repeat([]byte("d"), size))
					require.Nil(t, err)
				}
				body := bytes.Repeat([]byte("v"), len(buf))
				_, err := send(body)
				require.Nil(t, err)
				n, source, err := readUDPDatagram(receiver, buf)
				require.Nil(t, err)
				assert.Equal(t, body, buf[:n])
				require.NotNil(t, source)
				assert.Equal(t, peer.LocalAddr().String(), source.String())
				require.Nil(t, receiver.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
				n, _, err = readUDPDatagram(receiver, buf)
				require.Error(t, err)
				var netErr net.Error
				require.ErrorAs(t, err, &netErr)
				assert.True(t, netErr.Timeout())
				assert.Zero(t, n)
			})
		}
	}
}

func TestReadUDPDatagramErrors(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(fmt.Sprintf("Closed%t", closed), func(t *testing.T) {
			lis, conn := newUDPTestPair(t, "udp4")
			if closed {
				require.Nil(t, lis.Close())
			} else {
				_, err := conn.Write(bytes.Repeat([]byte("x"), 64))
				require.Nil(t, err)
				require.Nil(t, lis.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
			}
			n, _, err := readUDPDatagram(lis, make([]byte, 32))
			require.Error(t, err)
			assert.Zero(t, n)
			if closed {
				assert.ErrorIs(t, err, net.ErrClosed)
			} else {
				var netErr net.Error
				require.ErrorAs(t, err, &netErr)
				assert.True(t, netErr.Timeout())
			}
		})
	}
}

func TestUDPDatagramBufferIsolation(t *testing.T) {
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.Nil(t, err)
	defer upstream.Close()
	srv := newTestUDPServer(t, upstream.LocalAddr().String())
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP: net.IPv4(127, 0, 0, 1), Port: srv.lis.LocalAddr().(*net.UDPAddr).Port,
	})
	require.Nil(t, err)
	defer client.Close()
	require.Nil(t, client.SetDeadline(time.Now().Add(3*time.Second)))
	require.Nil(t, upstream.SetDeadline(time.Now().Add(3*time.Second)))
	bodies := make([][]byte, 12)
	for i := range bodies {
		size := []int{17, 1501, 8192, 16384}[i%4]
		bodies[i] = utilrand.GetRandomBytesMust(size)
		bodies[i][0] = byte(i)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		seen := make(map[byte]bool)
		for range bodies {
			n, addr, err := upstream.ReadFromUDP(buf)
			if !assert.Nil(t, err) || !assert.Positive(t, n) {
				return
			}
			id := buf[0]
			if !assert.Less(t, int(id), len(bodies)) || !assert.False(t, seen[id]) {
				return
			}
			seen[id] = true
			if !assert.True(t, bytes.Equal(bodies[id], buf[:n]), "The UDP request was changed") {
				return
			}
			_, err = upstream.WriteToUDP(buf[:n], addr)
			if !assert.Nil(t, err) {
				return
			}
		}
	}()
	t.Cleanup(func() {
		upstream.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("The UDP upstream did not stop")
		}
	})
	for _, body := range bodies {
		_, err := client.Write(body)
		require.Nil(t, err)
	}
	buf := make([]byte, 65535)
	seen := make(map[byte]bool)
	for range bodies {
		n, err := client.Read(buf)
		require.Nil(t, err)
		require.Positive(t, n)
		id := buf[0]
		require.Less(t, int(id), len(bodies))
		require.False(t, seen[id])
		seen[id] = true
		require.True(t, bytes.Equal(bodies[id], buf[:n]), "The UDP reply was changed")
	}
}

func exchangeUDPTestDatagram(t *testing.T, client, upstream *net.UDPConn, request, reply []byte) *net.UDPAddr {
	t.Helper()
	require.Nil(t, client.SetDeadline(time.Now().Add(2*time.Second)))
	require.Nil(t, upstream.SetDeadline(time.Now().Add(2*time.Second)))
	n, err := client.Write(request)
	require.Nil(t, err)
	require.Equal(t, len(request), n)
	buf := make([]byte, 65535)
	n, source, err := upstream.ReadFromUDP(buf)
	require.Nil(t, err)
	require.Equal(t, len(request), n)
	require.True(t, bytes.Equal(request, buf[:n]), "The UDP request was changed")
	n, err = upstream.WriteToUDP(reply, source)
	require.Nil(t, err)
	require.Equal(t, len(reply), n)
	n, err = client.Read(buf)
	require.Nil(t, err)
	require.Equal(t, len(reply), n)
	require.True(t, bytes.Equal(reply, buf[:n]), "The UDP reply was changed")
	return source
}

func TestUDPEmptyDatagramSequences(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			reader := setTestMeterProvider(t)
			ip := net.IPv4(127, 0, 0, 1)
			if network == "udp6" {
				ip = net.IPv6loopback
			}
			upstream, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
			require.Nil(t, err)
			defer upstream.Close()
			srv := newTestUDPServer(t, upstream.LocalAddr().String())
			client, err := net.DialUDP("udp4", nil, &net.UDPAddr{
				IP: net.IPv4(127, 0, 0, 1), Port: srv.lis.LocalAddr().(*net.UDPAddr).Port,
			})
			require.Nil(t, err)
			defer client.Close()
			messages := []struct {
				request []byte
				reply   []byte
			}{
				{nil, nil},
				{nil, []byte("reply to empty request")},
				{[]byte("request for empty reply"), nil},
				{[]byte{}, []byte{}},
				{[]byte("nonempty request"), []byte("nonempty reply")},
				{nil, nil},
				{nil, nil},
				{utilrand.GetRandomBytesMust(8192), nil},
				{nil, utilrand.GetRandomBytesMust(8192)},
				{[]byte("last request"), []byte("last reply")},
			}
			var current *dctx
			var source *net.UDPAddr
			var received, sent int64
			for i, message := range messages {
				peer := exchangeUDPTestDatagram(t, client, upstream, message.request, message.reply)
				srv.dctxMap.mu.Lock()
				active := srv.dctxMap.dctxMap[client.LocalAddr().String()]
				srv.dctxMap.mu.Unlock()
				require.NotNil(t, active)
				if current == nil {
					current = active
					source = peer
				} else {
					require.Same(t, current, active)
					assert.Equal(t, source.String(), peer.String())
				}
				received += int64(len(message.request))
				sent += int64(len(message.reply))
				require.Eventually(t, func() bool {
					return current.bytesFromClient.Load() == received && current.bytesToClient.Load() == sent &&
						current.packetsFromClient.Load() == int64(i+1) && current.packetsToClient.Load() == int64(i+1)
				}, time.Second, time.Millisecond)
			}
			for _, conn := range []*net.UDPConn{client, upstream} {
				require.Nil(t, conn.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
				_, _, err := conn.ReadFromUDP(make([]byte, 65535))
				var netErr net.Error
				require.ErrorAs(t, err, &netErr)
				assert.True(t, netErr.Timeout())
			}
			require.Nil(t, srv.Close())
			var rm metricdata.ResourceMetrics
			require.Eventually(t, func() bool {
				if reader.Collect(t.Context(), &rm) != nil {
					return false
				}
				var packetsSent, packetsReceived int64
				for _, scope := range rm.ScopeMetrics {
					for _, m := range scope.Metrics {
						sum, ok := m.Data.(metricdata.Sum[int64])
						if !ok {
							continue
						}
						for _, point := range sum.DataPoints {
							switch m.Name {
							case "req.packets_sent":
								packetsSent += point.Value
							case "req.packets_received":
								packetsReceived += point.Value
							}
						}
					}
				}
				return packetsSent == int64(len(messages)) && packetsReceived == int64(len(messages))
			}, time.Second, time.Millisecond)
			assert.Equal(t, sent, findSumDataPoint(t, &rm, "req.bytes_sent").Value)
			assert.Equal(t, received, findSumDataPoint(t, &rm, "req.bytes_received").Value)
			activeMetrics := 0
			for _, scope := range rm.ScopeMetrics {
				for _, m := range scope.Metrics {
					if m.Name != "req.active" && m.Name != "session.active" {
						continue
					}
					sum, ok := m.Data.(metricdata.Sum[int64])
					require.True(t, ok)
					for _, point := range sum.DataPoints {
						service, ok := point.Attributes.Value("octelium.vigil.svc.name")
						if ok && service.AsString() == srv.vCache.GetService().Metadata.Name {
							activeMetrics++
							assert.Zero(t, point.Value, m.Name)
						}
					}
				}
			}
			assert.Equal(t, 2, activeMetrics)
		})
	}
}

func TestUDPEmptyDatagramsConcurrentClients(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			ip := net.IPv4(127, 0, 0, 1)
			if network == "udp6" {
				ip = net.IPv6loopback
			}
			upstream, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
			require.Nil(t, err)
			var calls atomic.Int64
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 65535)
				for {
					n, source, err := upstream.ReadFromUDP(buf)
					if err != nil {
						return
					}
					calls.Add(1)
					if _, err := upstream.WriteToUDP(buf[:n], source); !assert.Nil(t, err) {
						return
					}
				}
			}()
			t.Cleanup(func() { upstream.Close(); <-done })
			srv := newTestUDPServer(t, upstream.LocalAddr().String())
			results := make(chan *dctx, 8)
			var wg sync.WaitGroup
			for i := range 8 {
				wg.Go(func() {
					client, err := net.DialUDP("udp4", nil, &net.UDPAddr{
						IP: net.IPv4(127, 0, 0, 1), Port: srv.lis.LocalAddr().(*net.UDPAddr).Port,
					})
					if !assert.Nil(t, err) {
						return
					}
					t.Cleanup(func() { client.Close() })
					buf := make([]byte, 65535)
					for _, size := range []int{0, 1, 0, 32, 0, 8192, 0} {
						if !assert.Nil(t, client.SetDeadline(time.Now().Add(2*time.Second))) {
							return
						}
						body := bytes.Repeat([]byte{byte(i + 1)}, size)
						if _, err := client.Write(body); !assert.Nil(t, err) {
							return
						}
						n, err := client.Read(buf)
						if !assert.Nil(t, err) || !assert.Equal(t, size, n) || !assert.True(t, bytes.Equal(body, buf[:n])) {
							return
						}
					}
					srv.dctxMap.mu.Lock()
					current := srv.dctxMap.dctxMap[client.LocalAddr().String()]
					srv.dctxMap.mu.Unlock()
					results <- current
				})
			}
			wg.Wait()
			close(results)
			count := 0
			for current := range results {
				count++
				require.NotNil(t, current)
				require.Eventually(t, func() bool {
					return current.packetsFromClient.Load() == 7 && current.packetsToClient.Load() == 7 &&
						current.bytesFromClient.Load() == 8225 && current.bytesToClient.Load() == 8225
				}, time.Second, time.Millisecond)
			}
			assert.Equal(t, 8, count)
			assert.Equal(t, int64(56), calls.Load())
		})
	}
}

func TestUDPEmptyDatagramWriteFailures(t *testing.T) {
	for _, direction := range []string{"Request", "Reply"} {
		t.Run(direction, func(t *testing.T) {
			upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.Nil(t, err)
			defer upstream.Close()
			srv := newTestUDPServer(t, upstream.LocalAddr().String())
			client, err := net.DialUDP("udp4", nil, &net.UDPAddr{
				IP: net.IPv4(127, 0, 0, 1), Port: srv.lis.LocalAddr().(*net.UDPAddr).Port,
			})
			require.Nil(t, err)
			defer client.Close()
			source := exchangeUDPTestDatagram(t, client, upstream, []byte("request"), []byte("reply"))
			srv.dctxMap.mu.Lock()
			current := srv.dctxMap.dctxMap[client.LocalAddr().String()]
			srv.dctxMap.mu.Unlock()
			require.NotNil(t, current)
			require.Eventually(t, func() bool {
				return current.packetsFromClient.Load() == 1 && current.packetsToClient.Load() == 1
			}, time.Second, time.Millisecond)
			if direction == "Request" {
				require.Nil(t, current.connUpstream.SetWriteDeadline(time.Now().Add(-time.Second)))
				err := srv.handlePacket(t.Context(), nil, 0, client.LocalAddr().(*net.UDPAddr))
				var netErr net.Error
				require.ErrorAs(t, err, &netErr)
				assert.True(t, netErr.Timeout())
				assert.Equal(t, int64(1), current.packetsFromClient.Load())
				assert.Equal(t, int64(len("request")), current.bytesFromClient.Load())
				require.Nil(t, current.connUpstream.SetWriteDeadline(time.Time{}))
			} else {
				require.Nil(t, srv.lis.SetWriteDeadline(time.Now().Add(-time.Second)))
				_, err := upstream.WriteToUDP(nil, source)
				require.Nil(t, err)
				require.Eventually(t, func() bool {
					srv.dctxMap.mu.Lock()
					defer srv.dctxMap.mu.Unlock()
					return srv.dctxMap.dctxMap[client.LocalAddr().String()] == nil
				}, time.Second, time.Millisecond)
				assert.Equal(t, int64(1), current.packetsToClient.Load())
				assert.Equal(t, int64(len("reply")), current.bytesToClient.Load())
				require.Nil(t, srv.lis.SetWriteDeadline(time.Time{}))
			}
			exchangeUDPTestDatagram(t, client, upstream, nil, nil)
			srv.dctxMap.mu.Lock()
			active := srv.dctxMap.dctxMap[client.LocalAddr().String()]
			srv.dctxMap.mu.Unlock()
			require.NotNil(t, active)
			if direction == "Request" {
				assert.Same(t, current, active)
			} else {
				assert.NotSame(t, current, active)
			}
		})
	}
}

func TestReadUDPDatagramTruncatedThenEmpty(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, connected := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/Connected%t", network, connected), func(t *testing.T) {
				lis, conn := newUDPTestPair(t, network)
				receiver, peer := lis, conn
				send := conn.Write
				if connected {
					receiver, peer = conn, lis
					send = func(body []byte) (int, error) {
						return lis.WriteToUDP(body, conn.LocalAddr().(*net.UDPAddr))
					}
				}
				for _, body := range [][]byte{bytes.Repeat([]byte("truncated"), 8), nil, []byte("next")} {
					_, err := send(body)
					require.Nil(t, err)
				}
				buf := make([]byte, 32)
				n, source, err := readUDPDatagram(receiver, buf)
				require.Nil(t, err)
				assert.Zero(t, n)
				require.NotNil(t, source)
				assert.Equal(t, peer.LocalAddr().String(), source.String())
				n, _, err = readUDPDatagram(receiver, buf)
				require.Nil(t, err)
				assert.Equal(t, "next", string(buf[:n]))
			})
		}
	}
}

func TestUDPEmptyDatagramAuthorization(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("Disabled%t", disabled), func(t *testing.T) {
			upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.Nil(t, err)
			defer upstream.Close()
			srv := newTestUDPServer(t, upstream.LocalAddr().String())
			client, err := net.DialUDP("udp4", nil, &net.UDPAddr{
				IP: net.IPv4(127, 0, 0, 1), Port: srv.lis.LocalAddr().(*net.UDPAddr).Port,
			})
			require.Nil(t, err)
			defer client.Close()
			original := srv.vCache.GetService()
			svc := srv.vCache.GetService()
			if disabled {
				svc.Spec.IsDisabled = true
			} else {
				svc.Spec.Authorization.InlinePolicies[0].Spec.Rules[0].Effect = corev1.Policy_Spec_Rule_DENY
			}
			svc, err = srv.octeliumC.CoreC().UpdateService(t.Context(), svc)
			require.Nil(t, err)
			srv.vCache.SetService(svc)
			require.Nil(t, srv.handlePacket(t.Context(), nil, 0, client.LocalAddr().(*net.UDPAddr)))
			srv.dctxMap.mu.Lock()
			count := len(srv.dctxMap.dctxMap)
			srv.dctxMap.mu.Unlock()
			assert.Zero(t, count)
			require.Nil(t, upstream.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
			_, _, err = upstream.ReadFromUDP(make([]byte, 65535))
			var netErr net.Error
			require.ErrorAs(t, err, &netErr)
			assert.True(t, netErr.Timeout())
			svc.Spec = original.Spec
			svc, err = srv.octeliumC.CoreC().UpdateService(t.Context(), svc)
			require.Nil(t, err)
			srv.vCache.SetService(svc)
			exchangeUDPTestDatagram(t, client, upstream, nil, nil)
		})
	}
}

func TestUDPDatagramsReusedClientAddress(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("Empty%t", empty), func(t *testing.T) {
			upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.Nil(t, err)
			defer upstream.Close()
			srv := newTestUDPServer(t, upstream.LocalAddr().String())
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: srv.lis.LocalAddr().(*net.UDPAddr).Port}
			client, err := net.DialUDP("udp4", nil, addr)
			require.Nil(t, err)
			defer client.Close()
			source := exchangeUDPTestDatagram(t, client, upstream, []byte("request"), []byte("reply"))
			local := client.LocalAddr().(*net.UDPAddr)
			srv.dctxMap.mu.Lock()
			current := srv.dctxMap.dctxMap[local.String()]
			srv.dctxMap.mu.Unlock()
			require.NotNil(t, current)
			require.Nil(t, client.Close())
			replacement, err := net.DialUDP("udp4", local, addr)
			require.Nil(t, err)
			defer replacement.Close()
			assert.Equal(t, local.String(), replacement.LocalAddr().String())
			received, sent := int64(len("request")), int64(len("reply"))
			messages := []struct {
				request []byte
				reply   []byte
			}{
				{[]byte("request"), []byte("reply")},
				{[]byte("request"), []byte("reply")},
				{[]byte("request"), []byte("reply")},
			}
			if empty {
				messages[0].request, messages[0].reply = nil, nil
				messages[1].reply = nil
				messages[2].request = nil
			}
			for _, message := range messages {
				peer := exchangeUDPTestDatagram(t, replacement, upstream, message.request, message.reply)
				assert.Equal(t, source.String(), peer.String())
				received += int64(len(message.request))
				sent += int64(len(message.reply))
			}
			srv.dctxMap.mu.Lock()
			active := srv.dctxMap.dctxMap[local.String()]
			srv.dctxMap.mu.Unlock()
			assert.Same(t, current, active)
			require.Eventually(t, func() bool {
				return current.packetsFromClient.Load() == 4 && current.packetsToClient.Load() == 4 &&
					current.bytesFromClient.Load() == received && current.bytesToClient.Load() == sent
			}, time.Second, time.Millisecond)
		})
	}
}
