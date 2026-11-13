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

package socks5

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"context"

	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	xproxy "golang.org/x/net/proxy"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
)

func setTestMeterProvider(t *testing.T) *sdkmetric.ManualReader {
	prevProvider := otel.GetMeterProvider()
	t.Cleanup(func() {
		otel.SetMeterProvider(prevProvider)
	})

	reader := sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))

	return reader
}

func TestTarget(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr *statute.AddrSpec
		want string
		typ  corev1.RequestContext_Request_SOCKS5_Connect_AddressType
	}{
		{"domain", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: "EXAMPLE.COM.", Port: 443}, "example.com:443", corev1.RequestContext_Request_SOCKS5_Connect_DOMAIN},
		{"IPv4", &statute.AddrSpec{AddrType: statute.ATYPIPv4, IP: net.ParseIP("192.0.2.1"), Port: 1}, "192.0.2.1:1", corev1.RequestContext_Request_SOCKS5_Connect_IPV4},
		{"IPv6", &statute.AddrSpec{AddrType: statute.ATYPIPv6, IP: net.ParseIP("2001:db8::1"), Port: 65535}, "[2001:db8::1]:65535", corev1.RequestContext_Request_SOCKS5_Connect_IPV6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newTarget(&gosocks5.Request{
				Request:     statute.Request{Command: statute.CommandConnect},
				RawDestAddr: tc.addr,
			})
			require.Nil(t, err)
			assert.Equal(t, tc.want, got.addr)
			assert.Equal(t, tc.typ, got.toRequestAddressType())
			assert.NotEmpty(t, got.toLogAddressType().String())
			assert.NotEmpty(t, got.metricAddressType())
			request := (&Server{}).getDownstreamReq(t.Context(), nil, got)
			assert.Equal(t, got.host, request.Request.GetSocks5().GetConnect().Host)
			assert.Equal(t, uint32(got.port), request.Request.GetSocks5().GetConnect().Port)
		})
	}
}

func TestTargetInvalid(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr *statute.AddrSpec
	}{
		{"nil destination", nil},
		{"zero port", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: "example.com"}},
		{"negative port", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: "example.com", Port: -1}},
		{"large port", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: "example.com", Port: 65536}},
		{"unknown address type", &statute.AddrSpec{AddrType: 255, Port: 443}},
		{"empty domain", &statute.AddrSpec{AddrType: statute.ATYPDomain, Port: 443}},
		{"long domain", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: strings.Repeat("a", 254), Port: 443}},
		{"NUL domain", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: "example\x00.com", Port: 443}},
		{"slash domain", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: "example.com/path", Port: 443}},
		{"backslash domain", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: `example.com\path`, Port: 443}},
		{"missing IPv4", &statute.AddrSpec{AddrType: statute.ATYPIPv4, Port: 443}},
		{"IPv6 as IPv4", &statute.AddrSpec{AddrType: statute.ATYPIPv4, IP: net.ParseIP("::1"), Port: 443}},
		{"missing IPv6", &statute.AddrSpec{AddrType: statute.ATYPIPv6, Port: 443}},
		{"IPv4 as IPv6", &statute.AddrSpec{AddrType: statute.ATYPIPv6, IP: net.ParseIP("127.0.0.1"), Port: 443}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newTarget(&gosocks5.Request{
				Request:     statute.Request{Command: statute.CommandConnect},
				RawDestAddr: tc.addr,
			})
			assert.NotNil(t, err)
			assert.Nil(t, got)
		})
	}
	got, err := newTarget(nil)
	assert.NotNil(t, err)
	assert.Nil(t, got)
	for _, command := range []byte{0, statute.CommandBind, statute.CommandAssociate, 255} {
		got, err := newTarget(&gosocks5.Request{
			Request:     statute.Request{Command: command},
			RawDestAddr: &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: "example.com", Port: 443},
		})
		assert.NotNil(t, err)
		assert.Nil(t, got)
	}
}

func TestEmbeddedSessionInvalid(t *testing.T) {
	srv := &Server{}
	for _, username := range []string{"", "../root", "root\x00", "root/other", strings.Repeat("a", 1024)} {
		req := &gosocks5.Request{
			AuthContext: &gosocks5.AuthContext{
				Method:  statute.MethodUserPassAuth,
				Payload: map[string]string{"username": username, "password": strings.Repeat("p", 1024)},
			},
		}
		got, err := srv.getEmbeddedUpstreamSession(t.Context(), req)
		assert.NotNil(t, err)
		assert.Nil(t, got)
	}
	assert.Empty(t, getAuthUsername(nil))
	assert.Empty(t, getAuthUsername(&gosocks5.Request{}))
	assert.Empty(t, getAuthUsername(&gosocks5.Request{
		AuthContext: &gosocks5.AuthContext{
			Method:  statute.MethodNoAuth,
			Payload: map[string]string{"username": "root"},
		},
	}))
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

type echoServer struct {
	lis net.Listener
}

func newEchoServer(t *testing.T, port int) *echoServer {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	assert.Nil(t, err)

	s := &echoServer{lis: lis}

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return s
}

func (s *echoServer) close() {
	if s.lis != nil {
		s.lis.Close()
	}
}

type upstreamProxy struct {
	lis net.Listener
}

func newUpstreamProxy(t *testing.T, port int) *upstreamProxy {
	srv := gosocks5.NewServer(
		gosocks5.WithAuthMethods([]gosocks5.Authenticator{
			gosocks5.NoAuthAuthenticator{},
		}),
	)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	assert.Nil(t, err)

	p := &upstreamProxy{lis: lis}

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(conn)
		}
	}()

	return p
}

func (p *upstreamProxy) close() {
	if p.lis != nil {
		p.lis.Close()
	}
}

func socks5Dial(t *testing.T, proxyPort int, target string) (net.Conn, error) {
	dialer, err := xproxy.SOCKS5("tcp", fmt.Sprintf("localhost:%d", proxyPort), nil, xproxy.Direct)
	assert.Nil(t, err)
	return dialer.Dial("tcp", target)
}

func roundTrip(t *testing.T, conn net.Conn) {
	msg := utilrand.GetRandomBytesMust(32)

	_, err := conn.Write(msg)
	assert.Nil(t, err)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, msg, buf[:n])
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

	targetPort := tests.GetPort()
	targetSrv := newEchoServer(t, targetPort)
	defer targetSrv.close()

	upstreamPort := tests.GetPort()
	upstreamSrv := newUpstreamProxy(t, upstreamPort)
	defer upstreamSrv.close()

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			Port: uint32(tests.GetPort()),
			Mode: corev1.Service_Spec_SOCKS5,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("socks5://localhost:%d", upstreamPort),
					},
				},
				Type: &corev1.Service_Spec_Config_Socks5{
					Socks5: &corev1.Service_Spec_Config_SOCKS5{},
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
	assert.Nil(t, err)
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

	metricsReader := setTestMeterProvider(t)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	{
		conn, err := socks5Dial(t, int(svc.Spec.Port), fmt.Sprintf("localhost:%d", targetPort))
		assert.NotNil(t, err)
		if conn != nil {
			conn.Close()
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

	octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	{
		conn, err := socks5Dial(t, int(svc.Spec.Port), fmt.Sprintf("localhost:%d", targetPort))
		assert.Nil(t, err, "%+v", err)
		roundTrip(t, conn)
		err = conn.Close()
		assert.Nil(t, err)
	}

	time.Sleep(1 * time.Second)

	{
		var rm metricdata.ResourceMetrics
		assert.Nil(t, metricsReader.Collect(ctx, &rm))

		dp, found := findSumDataPointByState(t, &rm, "req.total", "ALLOWED")
		assert.True(t, found)
		assert.Equal(t, int64(1), dp.Value)

		sentDP := findSumDataPoint(t, &rm, "req.bytes_sent")
		assert.True(t, sentDP.Value > 0)

		receivedDP := findSumDataPoint(t, &rm, "req.bytes_received")
		assert.True(t, receivedDP.Value > 0)
	}

	{
		conn, err := socks5Dial(t, int(svc.Spec.Port), fmt.Sprintf("127.0.0.1:%d", targetPort))
		assert.Nil(t, err, "%+v", err)
		roundTrip(t, conn)
		err = conn.Close()
		assert.Nil(t, err)
	}

	{
		conn, err := socks5Dial(t, int(svc.Spec.Port), fmt.Sprintf("localhost:%d", targetPort))
		assert.Nil(t, err, "%+v", err)
		for i := 0; i < 8; i++ {
			roundTrip(t, conn)
		}
		err = conn.Close()
		assert.Nil(t, err)
	}

	{
		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `ctx.request.socks5.connect.host == "blocked.example.com"`,
									},
								},
								Effect: corev1.Policy_Spec_Rule_DENY,
							},
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
		}

		svc, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svc)
		assert.Nil(t, err)
		vCache.SetService(svc)

		time.Sleep(1 * time.Second)

		{
			conn, err := socks5Dial(t, int(svc.Spec.Port), "blocked.example.com:80")
			assert.NotNil(t, err)
			if conn != nil {
				conn.Close()
			}
		}

		{
			conn, err := socks5Dial(t, int(svc.Spec.Port), fmt.Sprintf("localhost:%d", targetPort))
			assert.Nil(t, err, "%+v", err)
			roundTrip(t, conn)
			err = conn.Close()
			assert.Nil(t, err)
		}
	}

	err = srv.Close()
	assert.Nil(t, err)
}

func newSOCKS5ProxyTestPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	lis, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.Nil(t, err)
	defer lis.Close()
	client, err := net.DialTCP("tcp4", nil, lis.Addr().(*net.TCPAddr))
	require.Nil(t, err)
	t.Cleanup(func() { client.Close() })
	require.Nil(t, lis.SetDeadline(time.Now().Add(5*time.Second)))
	server, err := lis.AcceptTCP()
	require.Nil(t, err)
	t.Cleanup(func() { server.Close() })
	require.Nil(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	require.Nil(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	return client, server
}

func TestSOCKS5ProxyHalfCloseDirections(t *testing.T) {
	crt, err := utils_cert.GenerateSelfSignedCert("localhost", []string{"localhost"}, time.Hour)
	require.Nil(t, err)
	certificate, err := tls.X509KeyPair(crt.MustGetCertPEM(), crt.MustGetPrivateKeyPEM())
	require.Nil(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(crt.Certificate)
	for _, downstreamTLS := range []bool{false, true} {
		for _, clientFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("DownstreamTLS%t/ClientFirst%t", downstreamTLS, clientFirst), func(t *testing.T) {
				var client, downstream net.Conn
				client, downstream = newSOCKS5ProxyTestPair(t)
				if downstreamTLS {
					tlsClient := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})
					tlsServer := tls.Server(downstream, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
					done := make(chan error, 1)
					go func() { done <- tlsServer.HandshakeContext(t.Context()) }()
					require.Nil(t, tlsClient.HandshakeContext(t.Context()))
					require.Nil(t, <-done)
					client, downstream = tlsClient, tlsServer
				}
				upstream, backend := newSOCKS5ProxyTestPair(t)
				p := &proxy{dctx: &dctx{id: t.Name()}}
				done := make(chan struct{})
				go func() { defer close(done); p.doServe(downstream, bufio.NewReader(downstream), upstream) }()
				t.Cleanup(func() {
					downstream.Close()
					upstream.Close()
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("The SOCKS5 proxy did not stop after closing its connections")
					}
				})
				var first, second net.Conn = client, backend
				if !clientFirst {
					first, second = backend, client
				}
				_, err := first.Write([]byte("first"))
				require.Nil(t, err)
				require.Nil(t, first.(interface{ CloseWrite() error }).CloseWrite())
				body, err := io.ReadAll(second)
				require.Nil(t, err)
				assert.Equal(t, "first", string(body))
				timer := time.NewTimer(750 * time.Millisecond)
				defer timer.Stop()
				<-timer.C
				_, err = second.Write([]byte("second"))
				require.Nil(t, err)
				require.Nil(t, second.(interface{ CloseWrite() error }).CloseWrite())
				body, err = io.ReadAll(first)
				require.Nil(t, err)
				assert.Equal(t, "second", string(body))
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("The SOCKS5 proxy did not stop after both half-closes")
				}
				toClient, fromClient := int64(6), int64(5)
				if !clientFirst {
					toClient, fromClient = 5, 6
				}
				assert.Equal(t, toClient, p.bytesToDownstream)
				assert.Equal(t, fromClient, p.bytesFromDownstream)
			})
		}
	}
}

type tstSOCKS5ProxyFaultConn struct {
	net.Conn
	readErr   error
	writeErr  error
	panicRead bool
}

func (c *tstSOCKS5ProxyFaultConn) Read(buf []byte) (int, error) {
	if c.panicRead {
		panic("SOCKS5 read failed")
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(buf)
}

func (c *tstSOCKS5ProxyFaultConn) Write(buf []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(buf)
}

type tstSOCKS5ProxyCloseWriteErrorConn struct {
	net.Conn
}

func (c *tstSOCKS5ProxyCloseWriteErrorConn) CloseWrite() error {
	return io.ErrClosedPipe
}

func TestSOCKS5ProxyCopyFailureClosesBothConnections(t *testing.T) {
	for _, name := range []string{"ReadError", "WriteError", "CloseWriteError", "ReadPanic"} {
		t.Run(name, func(t *testing.T) {
			client, downstream := net.Pipe()
			upstream, backend := net.Pipe()
			require.Nil(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
			require.Nil(t, backend.SetReadDeadline(time.Now().Add(2*time.Second)))
			var reader io.Reader = downstream
			var back net.Conn = upstream
			switch name {
			case "ReadError":
				reader = &tstSOCKS5ProxyFaultConn{Conn: downstream, readErr: io.ErrUnexpectedEOF}
			case "WriteError":
				back = &tstSOCKS5ProxyFaultConn{Conn: upstream, writeErr: io.ErrClosedPipe}
			case "CloseWriteError":
				reader = &tstSOCKS5ProxyFaultConn{Conn: downstream, readErr: io.EOF}
				back = &tstSOCKS5ProxyCloseWriteErrorConn{Conn: upstream}
			case "ReadPanic":
				reader = &tstSOCKS5ProxyFaultConn{Conn: downstream, panicRead: true}
			}
			p := &proxy{dctx: &dctx{id: name}}
			done := make(chan struct{})
			go func() { defer close(done); p.doServe(downstream, reader, back) }()
			t.Cleanup(func() {
				client.Close()
				downstream.Close()
				upstream.Close()
				backend.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("The SOCKS5 proxy did not stop during cleanup")
				}
			})
			if name == "WriteError" {
				require.Nil(t, client.SetWriteDeadline(time.Now().Add(time.Second)))
				_, err := client.Write([]byte("request"))
				require.Nil(t, err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("The SOCKS5 proxy did not stop after a copy failure")
			}
			for _, peer := range []net.Conn{client, backend} {
				_, err := peer.Read(make([]byte, 1))
				assert.ErrorIs(t, err, io.EOF)
			}
		})
	}
}

type tstSecretOcteliumC struct {
	octeliumc.ClientInterface
	rcorev1.ResourceServiceClient
	deadline time.Time
}

func (c *tstSecretOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c
}

func (c *tstSecretOcteliumC) GetSecret(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Secret, error) {
	c.deadline, _ = ctx.Deadline()
	return &corev1.Secret{
		Metadata: &metav1.Metadata{Name: in.Name},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{Value: "password"},
		},
	}, nil
}

func newTestUpstreamProxy(upstreamAddr, targetAddr string) (*proxy, *corev1.Service) {
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "socks5.default"},
		Spec: &corev1.Service_Spec{
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("socks5://%s", upstreamAddr),
					},
				},
				Type: &corev1.Service_Spec_Config_Socks5{
					Socks5: &corev1.Service_Spec_Config_SOCKS5{
						Auth: &corev1.Service_Spec_Config_SOCKS5_Auth{
							Type: &corev1.Service_Spec_Config_SOCKS5_Auth_UsernamePassword_{
								UsernamePassword: &corev1.Service_Spec_Config_SOCKS5_Auth_UsernamePassword{
									Username: "octelium",
									Password: &corev1.Service_Spec_Config_SOCKS5_Auth_UsernamePassword_Password{
										Type: &corev1.Service_Spec_Config_SOCKS5_Auth_UsernamePassword_Password_FromSecret{
											FromSecret: "socks5-password",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		Status: &corev1.Service_Status{},
	}

	return newProxy(&dctx{
		target:    &target{addr: targetAddr},
		svcConfig: svc.Spec.Config,
		authResp: &coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext: &corev1.RequestContext{Service: svc},
		},
	}, loadbalancer.NewLbManager(nil, nil)), svc
}

func TestGetUpstreamConn(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	targetPort := tests.GetPort()
	targetSrv := newEchoServer(t, targetPort)
	defer targetSrv.close()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	defer lis.Close()

	upstreamSrv := gosocks5.NewServer(
		gosocks5.WithAuthMethods([]gosocks5.Authenticator{
			gosocks5.UserPassAuthenticator{
				Credentials: gosocks5.StaticCredentials{"octelium": "password"},
			},
		}),
	)
	go upstreamSrv.Serve(lis)

	secretMan, err := secretman.New(ctx, &tstSecretOcteliumC{}, nil)
	require.Nil(t, err)

	p, svc := newTestUpstreamProxy(lis.Addr().String(), fmt.Sprintf("127.0.0.1:%d", targetPort))

	conn, err := p.getUpstreamConn(ctx, svc, secretMan)
	require.Nil(t, err, "%+v", err)
	defer conn.Close()

	cancel()
	time.Sleep(500 * time.Millisecond)

	require.Nil(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	msg := utilrand.GetRandomBytesMust(32)
	_, err = conn.Write(msg)
	require.Nil(t, err)

	cw, ok := conn.(interface{ CloseWrite() error })
	require.True(t, ok, "%T", conn)
	require.Nil(t, cw.CloseWrite())

	ret, err := io.ReadAll(conn)
	assert.Nil(t, err)
	assert.Equal(t, msg, ret)
}

func TestGetUpstreamConnStalled(t *testing.T) {
	for _, tc := range []struct {
		name     string
		canceled bool
	}{
		{"deadline", false},
		{"canceled", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			timeout := time.Second
			if tc.canceled {
				timeout = time.Minute
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()

			lis, err := net.Listen("tcp", "127.0.0.1:0")
			require.Nil(t, err)
			defer lis.Close()

			acceptedCh := make(chan struct{})
			closedCh := make(chan struct{})
			go func() {
				conn, err := lis.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				close(acceptedCh)
				io.Copy(io.Discard, conn)
				close(closedCh)
			}()

			if tc.canceled {
				go func() {
					select {
					case <-acceptedCh:
						cancel()
					case <-ctx.Done():
					}
				}()
			}

			octeliumC := &tstSecretOcteliumC{}
			secretMan, err := secretman.New(ctx, octeliumC, nil)
			require.Nil(t, err)

			p, svc := newTestUpstreamProxy(lis.Addr().String(), "127.0.0.1:80")

			startedAt := time.Now()
			errCh := make(chan error, 1)
			go func() {
				conn, err := p.getUpstreamConn(ctx, svc, secretMan)
				assert.Nil(t, conn)
				errCh <- err
			}()

			select {
			case err := <-errCh:
				if tc.canceled {
					assert.ErrorIs(t, err, context.Canceled)
					assert.WithinRange(t, octeliumC.deadline,
						startedAt.Add(upstreamConnectTimeout), time.Now().Add(upstreamConnectTimeout))
				} else {
					assert.ErrorIs(t, err, context.DeadlineExceeded)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("getUpstreamConn did not return")
			}

			select {
			case <-closedCh:
			case <-time.After(5 * time.Second):
				t.Fatal("upstream conn was not closed")
			}
		})
	}
}
