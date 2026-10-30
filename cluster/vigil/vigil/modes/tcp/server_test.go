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

package tcp

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"context"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	v1 "github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/protobuf/proto"
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

func TestTCPHalfCloseAllowsDelayedResponse(t *testing.T) {
	newPair := func() (*net.TCPConn, *net.TCPConn) {
		lis, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.Nil(t, err)
		defer lis.Close()
		client, err := net.DialTCP("tcp4", nil, lis.Addr().(*net.TCPAddr))
		require.Nil(t, err)
		server, err := lis.AcceptTCP()
		require.Nil(t, err)
		t.Cleanup(func() { client.Close(); server.Close() })
		require.Nil(t, client.SetDeadline(time.Now().Add(3*time.Second)))
		require.Nil(t, server.SetDeadline(time.Now().Add(3*time.Second)))
		return client, server
	}
	client, downstream := newPair()
	upstream, backend := newPair()
	p := &proxy{dctx: &dctx{id: "half-close"}}
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		p.doServe(downstream, upstream)
	}()
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		defer backend.CloseWrite()
		body, err := io.ReadAll(backend)
		assert.Nil(t, err)
		assert.Equal(t, "request", string(body))
		timer := time.NewTimer(750 * time.Millisecond)
		defer timer.Stop()
		<-timer.C
		backend.Write([]byte("response after processing"))
	}()
	_, err := client.Write([]byte("request"))
	require.Nil(t, err)
	require.Nil(t, client.CloseWrite())
	body, err := io.ReadAll(client)
	require.Nil(t, err)
	assert.Equal(t, "response after processing", string(body))
	select {
	case <-proxyDone:
	case <-time.After(3 * time.Second):
		t.Error("The TCP proxy did not stop")
	}
	select {
	case <-backendDone:
	case <-time.After(3 * time.Second):
		t.Error("The TCP backend did not stop")
	}
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
	lis  net.Listener
	port int

	crt    *tls.Certificate
	caPool *x509.CertPool
}

func newTestServer(port int) *tstSrv {

	return &tstSrv{
		port: port,
	}
}

func (s *tstSrv) run(t *testing.T) {

	var err error
	if s.crt != nil {

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{*s.crt},
		}
		if s.caPool != nil {
			tlsCfg.RootCAs = s.caPool
		}
		s.lis, err = tls.Listen("tcp", fmt.Sprintf(":%d", s.port), tlsCfg)
		assert.Nil(t, err)
	} else {
		s.lis, err = net.Listen("tcp", fmt.Sprintf(":%d", s.port))
		assert.Nil(t, err)
	}

	go func() {
		for {
			conn, err := s.lis.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()
				for {
					buf := make([]byte, 4096)
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					conn.Write(buf[:n])
				}
			}(conn)

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
	upstreamSrv.run(t)
	defer upstreamSrv.close()

	svc, err := adminSrv.CreateService(ctx, &v1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &v1.Service_Spec{
			Port: uint32(tests.GetPort()),
			Mode: corev1.Service_Spec_TCP,
			Config: &v1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("tcp://localhost:%d", upstreamPort),
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

	/*
		logManager, err := logmanager.NewLogManager(ctx, &logmanager.LogManagerOpts{})
		assert.Nil(t, err)
		metricsStore, err := metricsstore.NewMetricsStore(ctx, nil)
		assert.Nil(t, err)
	*/

	metricsReader := setTestMeterProvider(t)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		// LogManager:   logManager,
		LBManager: loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		// MetricsStore: metricsStore,
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err)
	{
		time.Sleep(1 * time.Second)
		c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", svc.Spec.Port))
		assert.Nil(t, err)

		buf := make([]byte, 4096)
		n, err := c.Read(buf)

		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)

		c.Close()
	}

	{
		var rm metricdata.ResourceMetrics
		assert.Nil(t, metricsReader.Collect(ctx, &rm))

		dp, found := findSumDataPointByState(t, &rm, "req.total", "DENIED")
		assert.True(t, found)
		assert.Equal(t, int64(1), dp.Value)
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

	c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", svc.Spec.Port))
	assert.Nil(t, err)

	msg := utilrand.GetRandomBytesMust(32)

	_, err = c.Write(msg)
	assert.Nil(t, err)

	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, msg, buf[:n])
	err = c.Close()
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	{
		var rm metricdata.ResourceMetrics
		assert.Nil(t, metricsReader.Collect(ctx, &rm))

		dp, found := findSumDataPointByState(t, &rm, "req.total", "ALLOWED")
		assert.True(t, found)
		assert.Equal(t, int64(1), dp.Value)

		sentDP := findSumDataPoint(t, &rm, "req.bytes_sent")
		assert.Equal(t, int64(len(msg)), sentDP.Value)

		receivedDP := findSumDataPoint(t, &rm, "req.bytes_received")
		assert.Equal(t, int64(len(msg)), receivedDP.Value)
	}

	err = srv.Close()
	assert.Nil(t, err)

	{
		// test mTLS
		upstreamSrv.close()

		root, err := utils_cert.GenerateCARoot()
		assert.Nil(t, err)
		sn, err := utils_cert.GenerateSerialNumber()
		assert.Nil(t, err)
		srvCrt, err := utils_cert.GenerateCertificate(&x509.Certificate{
			BasicConstraintsValid: true,
			SerialNumber:          sn,
			Subject: pkix.Name{
				CommonName: "localhost",
			},

			DNSNames: []string{"localhost"},

			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, root.Certificate, root.PrivateKey, false)
		assert.Nil(t, err)

		srvCert, err := tls.X509KeyPair((srvCrt.MustGetCertPEM()), (srvCrt.MustGetPrivateKeyPEM()))
		assert.Nil(t, err)
		upstreamSrv.crt = &srvCert
		srvCaPool := x509.NewCertPool()
		ok := srvCaPool.AppendCertsFromPEM(root.MustGetCertPEM())
		assert.True(t, ok)
		upstreamSrv.run(t)

		clientCrt, err := utils_cert.GenerateCertificate(&x509.Certificate{
			BasicConstraintsValid: true,
			SerialNumber:          sn,
			Subject: pkix.Name{
				CommonName: "client",
			},

			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, root.Certificate, root.PrivateKey, false)
		assert.Nil(t, err)

		secReq := &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(6),
			},
			Spec: &corev1.Secret_Spec{},
		}
		ucorev1.ToSecret(secReq).SetCertificate(
			string(clientCrt.MustGetCertPEM()),
			string(clientCrt.MustGetPrivateKeyPEM()))

		sec, err := adminSrv.CreateSecret(ctx, secReq)
		assert.Nil(t, err)

		svc.Spec.Config.ClientCertificate = &corev1.Service_Spec_Config_ClientCertificate{

			Type: &corev1.Service_Spec_Config_ClientCertificate_FromSecret{
				FromSecret: sec.Metadata.Name,
			},

			TrustedCAs: []string{
				string(root.MustGetCertPEM()),
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		/*
			logManager, err := logmanager.NewLogManager(ctx, &logmanager.LogManagerOpts{})
			assert.Nil(t, err)

			metricsStore, err := metricsstore.NewMetricsStore(ctx, nil)
			assert.Nil(t, err)
		*/

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			// LogManager:   logManager,
			LBManager: loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
			// MetricsStore: metricsStore,
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", svc.Spec.Port))
		assert.Nil(t, err)

		msg := utilrand.GetRandomBytesMust(32)

		_, err = c.Write(msg)
		assert.Nil(t, err)

		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, msg, buf[:n])
		err = c.Close()
		assert.Nil(t, err)
	}
}

func assertClosedByDeadline(t *testing.T, c net.Conn, timeout time.Duration) {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(timeout + 8*time.Second)); err != nil {
		t.Fatal(err)
	}

	startedAt := time.Now()
	_, err := io.Copy(io.Discard, c)
	elapsed := time.Since(startedAt)

	assert.False(t, isTimeoutErr(err), "the server never closed the idle conn: %+v", err)
	assert.Less(t, elapsed, timeout+8*time.Second)
	assert.Greater(t, elapsed, timeout/2)
}

func isTimeoutErr(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func TestTLSHandshakeDeadline(t *testing.T) {

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
	upstreamSrv.run(t)
	t.Cleanup(func() {
		upstreamSrv.close()
	})

	svc, err := adminSrv.CreateService(ctx, &v1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &v1.Service_Spec{
			Port:  uint32(tests.GetPort()),
			Mode:  corev1.Service_Spec_TCP,
			IsTLS: true,
			Config: &v1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("tcp://localhost:%d", upstreamPort),
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
	t.Cleanup(func() {
		srv.Close()
	})

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

	c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", svc.Spec.Port))
	assert.Nil(t, err)
	defer c.Close()

	assertClosedByDeadline(t, c, handshakeTimeout)
}

func TestUpstreamTLSFromConfigTLS(t *testing.T) {

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

	root, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)
	sn, err := utils_cert.GenerateSerialNumber()
	assert.Nil(t, err)
	srvCrt, err := utils_cert.GenerateCertificate(&x509.Certificate{
		BasicConstraintsValid: true,
		SerialNumber:          sn,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		DNSNames:    []string{"localhost"},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, root.Certificate, root.PrivateKey, false)
	assert.Nil(t, err)

	srvCert, err := tls.X509KeyPair(srvCrt.MustGetCertPEM(), srvCrt.MustGetPrivateKeyPEM())
	assert.Nil(t, err)

	upstreamPort := tests.GetPort()
	upstreamSrv := newTestServer(upstreamPort)
	upstreamSrv.crt = &srvCert
	upstreamSrv.run(t)
	t.Cleanup(func() {
		upstreamSrv.close()
	})

	svc, err := adminSrv.CreateService(ctx, &v1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &v1.Service_Spec{
			Port: uint32(tests.GetPort()),
			Mode: corev1.Service_Spec_TCP,
			Config: &v1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("tcp://localhost:%d", upstreamPort),
					},
				},
				Tls: &corev1.Service_Spec_Config_TLS{
					TrustedCAs: []string{
						string(root.MustGetCertPEM()),
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
	t.Cleanup(func() {
		srv.Close()
	})

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

	c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", svc.Spec.Port))
	assert.Nil(t, err)
	defer c.Close()

	msg := utilrand.GetRandomBytesMust(32)

	_, err = c.Write(msg)
	assert.Nil(t, err)

	assert.Nil(t, c.SetReadDeadline(time.Now().Add(10*time.Second)))

	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, msg, buf[:n])
}

func newTCPProxyTestPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
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

func TestTCPProxyHalfCloseDirections(t *testing.T) {
	crt, err := utils_cert.GenerateSelfSignedCert("localhost", []string{"localhost"}, time.Hour)
	require.Nil(t, err)
	certificate, err := tls.X509KeyPair(crt.MustGetCertPEM(), crt.MustGetPrivateKeyPEM())
	require.Nil(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(crt.Certificate)
	for _, tc := range []struct {
		name       string
		downstream bool
		upstream   bool
	}{
		{name: "Plain"},
		{name: "DownstreamTLS", downstream: true},
		{name: "UpstreamTLS", upstream: true},
		{name: "BothTLS", downstream: true, upstream: true},
	} {
		for _, clientFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/ClientFirst%t", tc.name, clientFirst), func(t *testing.T) {
				newPair := func(isTLS bool) (net.Conn, net.Conn) {
					client, server := newTCPProxyTestPair(t)
					if !isTLS {
						return client, server
					}
					tlsClient := tls.Client(client, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})
					tlsServer := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
					done := make(chan error, 1)
					go func() { done <- tlsServer.HandshakeContext(t.Context()) }()
					require.Nil(t, tlsClient.HandshakeContext(t.Context()))
					require.Nil(t, <-done)
					return tlsClient, tlsServer
				}
				client, downstream := newPair(tc.downstream)
				upstream, backend := newPair(tc.upstream)
				p := &proxy{dctx: &dctx{id: t.Name()}}
				done := make(chan struct{})
				go func() { defer close(done); p.doServe(downstream, upstream) }()
				t.Cleanup(func() {
					downstream.Close()
					upstream.Close()
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("The TCP proxy did not stop after closing its connections")
					}
				})
				first, second := client, backend
				if !clientFirst {
					first, second = backend, client
				}
				_, err := first.Write([]byte("first"))
				require.Nil(t, err)
				require.Nil(t, first.(closeWriter).CloseWrite())
				body, err := io.ReadAll(second)
				require.Nil(t, err)
				assert.Equal(t, "first", string(body))
				timer := time.NewTimer(750 * time.Millisecond)
				defer timer.Stop()
				<-timer.C
				_, err = second.Write([]byte("second"))
				require.Nil(t, err)
				require.Nil(t, second.(closeWriter).CloseWrite())
				body, err = io.ReadAll(first)
				require.Nil(t, err)
				assert.Equal(t, "second", string(body))
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("The TCP proxy did not stop after both half-closes")
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

func TestTCPProxyCancellation(t *testing.T) {
	for _, halfClosed := range []bool{false, true} {
		t.Run(fmt.Sprintf("HalfClosed%t", halfClosed), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			lis, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.Nil(t, err)
			defer lis.Close()
			require.Nil(t, lis.SetDeadline(time.Now().Add(3*time.Second)))
			client, downstream := newTCPProxyTestPair(t)
			svc := &corev1.Service{
				Metadata: &metav1.Metadata{Uid: "service"},
				Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_TCP, Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "tcp://" + lis.Addr().String()}},
				}},
				Status: &corev1.Service_Status{},
			}
			vc, err := vcache.NewCache(ctx)
			require.Nil(t, err)
			vc.SetService(svc)
			p := newProxy(&dctx{
				id: t.Name(), conn: downstream, svcConfig: svc.Spec.Config,
				authResp: &coctovigilv1.AuthenticateAndAuthorizeResponse{RequestContext: &corev1.RequestContext{Service: svc}},
			}, loadbalancer.NewLbManager(nil, vc))
			done := make(chan struct{})
			go func() { defer close(done); p.serve(ctx, svc, nil, time.Now()) }()
			backend, err := lis.AcceptTCP()
			require.Nil(t, err)
			t.Cleanup(func() {
				cancel()
				client.Close()
				downstream.Close()
				backend.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("The TCP proxy did not stop during cleanup")
				}
			})
			require.Nil(t, backend.SetDeadline(time.Now().Add(3*time.Second)))
			if halfClosed {
				_, err := client.Write([]byte("request"))
				require.Nil(t, err)
				require.Nil(t, client.CloseWrite())
				body, err := io.ReadAll(backend)
				require.Nil(t, err)
				assert.Equal(t, "request", string(body))
			} else {
				_, err := client.Write([]byte("ready"))
				require.Nil(t, err)
				buf := make([]byte, len("ready"))
				_, err = io.ReadFull(backend, buf)
				require.Nil(t, err)
				assert.Equal(t, "ready", string(buf))
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("The TCP proxy did not stop after cancellation")
			}
			assert.Nil(t, p.upstreamErr)
			require.Nil(t, client.SetReadDeadline(time.Now().Add(time.Second)))
			_, err = client.Read(make([]byte, 1))
			assert.ErrorIs(t, err, io.EOF)
		})
	}
}

type tstTCPProxyFaultConn struct {
	net.Conn
	readErr   error
	writeErr  error
	panicRead bool
}

func (c *tstTCPProxyFaultConn) Read(buf []byte) (int, error) {
	if c.panicRead {
		panic("TCP read failed")
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.Conn.Read(buf)
}

func (c *tstTCPProxyFaultConn) Write(buf []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.Conn.Write(buf)
}

type tstTCPProxyCloseWriteErrorConn struct {
	net.Conn
}

func (c *tstTCPProxyCloseWriteErrorConn) CloseWrite() error {
	return io.ErrClosedPipe
}

func TestTCPProxyCopyFailureClosesBothConnections(t *testing.T) {
	for _, name := range []string{"ReadError", "WriteError", "CloseWriteError", "ReadPanic"} {
		t.Run(name, func(t *testing.T) {
			client, downstream := net.Pipe()
			upstream, backend := net.Pipe()
			require.Nil(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
			require.Nil(t, backend.SetReadDeadline(time.Now().Add(2*time.Second)))
			var front, back net.Conn = downstream, upstream
			switch name {
			case "ReadError":
				front = &tstTCPProxyFaultConn{Conn: downstream, readErr: io.ErrUnexpectedEOF}
			case "WriteError":
				back = &tstTCPProxyFaultConn{Conn: upstream, writeErr: io.ErrClosedPipe}
			case "CloseWriteError":
				front = &tstTCPProxyFaultConn{Conn: downstream, readErr: io.EOF}
				back = &tstTCPProxyCloseWriteErrorConn{Conn: upstream}
			case "ReadPanic":
				front = &tstTCPProxyFaultConn{Conn: downstream, panicRead: true}
			}
			p := &proxy{dctx: &dctx{id: name}}
			done := make(chan struct{})
			go func() { defer close(done); p.doServe(front, back) }()
			t.Cleanup(func() {
				client.Close()
				downstream.Close()
				upstream.Close()
				backend.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("The TCP proxy did not stop during cleanup")
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
				t.Fatal("The TCP proxy did not stop after a copy failure")
			}
			for _, peer := range []net.Conn{client, backend} {
				_, err := peer.Read(make([]byte, 1))
				assert.ErrorIs(t, err, io.EOF)
			}
		})
	}
}

func TestCloseWriteFallbackClosesConnection(t *testing.T) {
	peer, conn := net.Pipe()
	defer peer.Close()
	defer conn.Close()
	require.Nil(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	require.Nil(t, closeWrite(conn))
	_, err := peer.Read(make([]byte, 1))
	assert.ErrorIs(t, err, io.EOF)
}

func TestServerHalfCloseSessionMetrics(t *testing.T) {
	ctx := t.Context()
	records := newTCPLogRecorder(t)
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	fakeC := tst.C
	cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	require.Nil(t, err)
	cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{V4: "127.0.0.0/8", V6: "::1/128"}
	_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	require.Nil(t, err)
	adminSrv := admin.NewServer(&admin.Opts{OcteliumC: fakeC.OcteliumC, IsEmbedded: true})
	usrSrv := user.NewServer(fakeC.OcteliumC)
	lis, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.Nil(t, err)
	defer lis.Close()
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(6)},
		Spec: &corev1.Service_Spec{
			Port: uint32(tests.GetPort()), Mode: corev1.Service_Spec_TCP,
			Config: &corev1.Service_Spec_Config{Upstream: &corev1.Service_Spec_Config_Upstream{
				Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "tcp://" + lis.Addr().String()},
			}},
			Authorization: &corev1.Service_Spec_Authorization{InlinePolicies: []*corev1.InlinePolicy{{
				Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{
					Effect:    corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
				}}},
			}}},
		},
	})
	require.Nil(t, err)
	svc, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	require.Nil(t, err)
	vCache, err := vcache.NewCache(ctx)
	require.Nil(t, err)
	vCache.SetService(svc)
	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{VCache: vCache, OcteliumC: fakeC.OcteliumC})
	require.Nil(t, err)
	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	require.Nil(t, err)
	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	require.Nil(t, err)
	require.Nil(t, usr.Connect())
	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{{V4: "127.0.0.1/32", V6: "::1/128"}},
		Type:      corev1.Session_Status_Connection_WIREGUARD,
		L3Mode:    corev1.Session_Status_Connection_V4,
	}
	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	require.Nil(t, err)
	usr.Resync()
	octovigilC.GetCache().SetSession(usr.Session)
	metricsReader := setTestMeterProvider(t)
	srv, err := New(ctx, &modes.Opts{
		OcteliumC: fakeC.OcteliumC, VCache: vCache, OctovigilC: octovigilC,
		SecretMan: secretMan, LBManager: loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	require.Nil(t, err)
	t.Cleanup(func() { srv.Close() })
	require.Nil(t, srv.Run(ctx))
	client, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(svc.Spec.Port)})
	require.Nil(t, err)
	defer client.Close()
	require.Nil(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	request, response := "request", "response after processing"
	_, err = client.Write([]byte(request))
	require.Nil(t, err)
	require.Nil(t, client.CloseWrite())
	require.Nil(t, lis.SetDeadline(time.Now().Add(5*time.Second)))
	backend, err := lis.AcceptTCP()
	require.Nil(t, err)
	defer backend.Close()
	require.Nil(t, backend.SetDeadline(time.Now().Add(5*time.Second)))
	body, err := io.ReadAll(backend)
	require.Nil(t, err)
	require.Equal(t, request, string(body))
	start := nextTCPAccessLog(t, records)
	connected := nextTCPAccessLog(t, records)
	assert.Equal(t, corev1.AccessLog_Entry_Info_TCP_START, start.Entry.Info.GetTcp().Type)
	assert.Equal(t, corev1.AccessLog_Entry_Info_TCP_CONNECTED, connected.Entry.Info.GetTcp().Type)
	assert.NotEmpty(t, start.Entry.Common.ConnectionID)
	assert.Equal(t, start.Entry.Common.ConnectionID, connected.Entry.Common.ConnectionID)
	assert.True(t, proto.Equal(start.Entry.Common.StartedAt, connected.Entry.Common.StartedAt))
	assert.True(t, proto.Equal(start.Entry.Common.SessionRef, connected.Entry.Common.SessionRef))
	assert.True(t, proto.Equal(start.Entry.Common.Reason, connected.Entry.Common.Reason))
	assert.Nil(t, start.Entry.Common.Network.UpstreamLocal)
	assert.Nil(t, start.Entry.Common.Network.UpstreamRemote)
	assert.True(t, proto.Equal(logentry.GetEndpoint(client.LocalAddr()), connected.Entry.Common.Network.Downstream))
	assert.True(t, proto.Equal(logentry.GetEndpoint(backend.RemoteAddr()), connected.Entry.Common.Network.UpstreamLocal))
	assert.True(t, proto.Equal(logentry.GetEndpoint(backend.LocalAddr()), connected.Entry.Common.Network.UpstreamRemote))
	var rm metricdata.ResourceMetrics
	findActive := func(name string) int64 {
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != name {
					continue
				}
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				for _, dp := range sum.DataPoints {
					serviceName, ok := dp.Attributes.Value("octelium.vigil.svc.name")
					if ok && serviceName.AsString() == svc.Metadata.Name {
						return dp.Value
					}
				}
			}
		}
		t.Fatalf("metric %s for service %s not found", name, svc.Metadata.Name)
		return 0
	}
	require.Nil(t, metricsReader.Collect(ctx, &rm))
	assert.Equal(t, int64(1), findActive("req.active"))
	assert.Equal(t, int64(1), findActive("session.active"))
	timer := time.NewTimer(750 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	_, err = backend.Write([]byte(response))
	require.Nil(t, err)
	require.Nil(t, backend.CloseWrite())
	body, err = io.ReadAll(client)
	require.Nil(t, err)
	assert.Equal(t, response, string(body))
	require.Eventually(t, func() bool {
		srv.dctxMap.mu.Lock()
		defer srv.dctxMap.mu.Unlock()
		return len(srv.dctxMap.dctxMap) == 0
	}, 3*time.Second, 10*time.Millisecond)
	end := nextTCPAccessLog(t, records)
	assert.Equal(t, corev1.AccessLog_Entry_Info_TCP_END, end.Entry.Info.GetTcp().Type)
	assert.Equal(t, start.Entry.Common.ConnectionID, end.Entry.Common.ConnectionID)
	assert.True(t, proto.Equal(start.Entry.Common.StartedAt, end.Entry.Common.StartedAt))
	assert.True(t, proto.Equal(connected.Entry.Common.Network, end.Entry.Common.Network))
	assert.Equal(t, uint64(len(request)), end.Entry.Info.GetTcp().ReceivedBytes)
	assert.Equal(t, uint64(len(response)), end.Entry.Info.GetTcp().SentBytes)
	assert.NotEqual(t, start.Metadata.Id, connected.Metadata.Id)
	assert.NotEqual(t, connected.Metadata.Id, end.Metadata.Id)
	rm = metricdata.ResourceMetrics{}
	require.Nil(t, metricsReader.Collect(ctx, &rm))
	dp, found := findSumDataPointByState(t, &rm, "req.total", "ALLOWED")
	assert.True(t, found)
	assert.Equal(t, int64(1), dp.Value)
	assert.Equal(t, int64(0), findActive("req.active"))
	assert.Equal(t, int64(0), findActive("session.active"))
	assert.Equal(t, int64(len(response)), findSumDataPoint(t, &rm, "req.bytes_sent").Value)
	assert.Equal(t, int64(len(request)), findSumDataPoint(t, &rm, "req.bytes_received").Value)
}
