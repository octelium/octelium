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

package dns

import (
	"fmt"
	"net"
	"testing"
	"time"

	"context"

	"github.com/miekg/dns"
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
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
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

func findSumDataPointByRcodeClass(t *testing.T, rm *metricdata.ResourceMetrics, name, state, rcodeClass string) (metricdata.DataPoint[int64], bool) {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			assert.True(t, ok, name)
			for _, dp := range sum.DataPoints {
				stateVal, ok := dp.Attributes.Value("state")
				if !ok || stateVal.AsString() != state {
					continue
				}
				rcodeVal, ok := dp.Attributes.Value("rcode_class")
				if ok && rcodeVal.AsString() == rcodeClass {
					return dp, true
				}
			}
		}
	}
	return metricdata.DataPoint[int64]{}, false
}

type testResponseWriter struct {
	msg *dns.Msg
}

func (w *testResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (w *testResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}

func (w *testResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg
	return nil
}

func (w *testResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (w *testResponseWriter) Close() error {
	return nil
}

func (w *testResponseWriter) TsigStatus() error {
	return nil
}

func (w *testResponseWriter) TsigTimersOnly(bool) {
}

func (w *testResponseWriter) Hijack() {
}

func TestInvalidRequest(t *testing.T) {
	tests := []*dns.Msg{
		{},
		{
			Question: []dns.Question{
				{Name: "allowed.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				{Name: "denied.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
		{
			MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeUpdate},
			Question: []dns.Question{
				{Name: "example.", Qtype: dns.TypeSOA, Qclass: dns.ClassINET},
			},
		},
		{
			MsgHdr: dns.MsgHdr{Response: true},
			Question: []dns.Question{
				{Name: "example.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			},
		},
	}

	for _, req := range tests {
		w := &testResponseWriter{}
		assert.NotPanics(t, func() {
			new(Server).ServeDNS(w, req)
		})
		assert.NotNil(t, w.msg)
		assert.Equal(t, dns.RcodeFormatError, w.msg.Rcode)
	}
}

func TestRequestPanic(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.", dns.TypeA)

	assert.NotPanics(t, func() {
		new(Server).ServeDNS(&testResponseWriter{}, req)
	})
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

	svc, err := adminSrv.CreateService(ctx, &v1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &v1.Service_Spec{
			Port: uint32(tests.GetPort()),
			Mode: corev1.Service_Spec_DNS,
			Config: &corev1.Service_Spec_Config{
				Upstream: &v1.Service_Spec_Config_Upstream{
					Type: &v1.Service_Spec_Config_Upstream_Url{
						Url: "dns://8.8.8.8",
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

	time.Sleep(1 * time.Second)

	{
		c := dns.Client{
			Timeout: 5 * time.Second,
		}

		m := dns.Msg{}

		m.SetQuestion("dns.google.", dns.TypeA)

		r, _, err := c.Exchange(&m, net.JoinHostPort("localhost", fmt.Sprintf("%d", svc.Spec.Port)))
		assert.Nil(t, err)

		assert.Equal(t, r.Rcode, dns.RcodeRefused)
	}

	{
		var rm metricdata.ResourceMetrics
		assert.Nil(t, metricsReader.Collect(ctx, &rm))

		dp, found := findSumDataPointByState(t, &rm, "req.total", "DENIED")
		assert.True(t, found)
		assert.True(t, dp.Value > 0)

		qtypeVal, ok := dp.Attributes.Value("qtype")
		assert.True(t, ok)
		assert.Equal(t, "A", qtypeVal.AsString())

		rcodeVal, ok := dp.Attributes.Value("rcode_class")
		assert.True(t, ok)
		assert.Equal(t, "REFUSED", rcodeVal.AsString())
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
		c := dns.Client{
			Timeout: 5 * time.Second,
		}

		m := dns.Msg{}

		m.SetQuestion("dns.google.", dns.TypeA)

		r, _, err := c.Exchange(&m, net.JoinHostPort("localhost", fmt.Sprintf("%d", svc.Spec.Port)))
		assert.Nil(t, err)

		assert.True(t, r.Answer[0].(*dns.A).A.String() == "8.8.8.8" || r.Answer[0].(*dns.A).A.String() == "8.8.4.4")
	}

	{
		var rm metricdata.ResourceMetrics
		assert.Nil(t, metricsReader.Collect(ctx, &rm))

		dp, found := findSumDataPointByState(t, &rm, "req.total", "ALLOWED")
		assert.True(t, found)
		assert.Equal(t, int64(1), dp.Value)

		rcodeVal, ok := dp.Attributes.Value("rcode_class")
		assert.True(t, ok)
		assert.Equal(t, "NOERROR", rcodeVal.AsString())
	}

	{
		c := dns.Client{
			Timeout: 5 * time.Second,
		}

		m := dns.Msg{}

		m.SetQuestion(fmt.Sprintf("%s.com.", utilrand.GetRandomStringCanonical(18)), dns.TypeA)

		r, _, err := c.Exchange(&m, net.JoinHostPort("localhost", fmt.Sprintf("%d", svc.Spec.Port)))
		assert.Nil(t, err)

		assert.Equal(t, r.Rcode, dns.RcodeNameError)
	}

	{
		var rm metricdata.ResourceMetrics
		assert.Nil(t, metricsReader.Collect(ctx, &rm))

		dp, found := findSumDataPointByRcodeClass(t, &rm, "req.total", "ALLOWED", "NXDOMAIN")
		assert.True(t, found)
		assert.Equal(t, int64(1), dp.Value)
	}

	err = srv.Close()
	assert.Nil(t, err)

}

func TestServerTLS(t *testing.T) {

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

	svc, err := adminSrv.CreateService(ctx, &v1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &v1.Service_Spec{
			Port: uint32(tests.GetPort()),
			Mode: corev1.Service_Spec_DNS,
			Config: &v1.Service_Spec_Config{
				Upstream: &v1.Service_Spec_Config_Upstream{
					Type: &v1.Service_Spec_Config_Upstream_Url{
						Url: "tls://8.8.8.8:853",
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

	time.Sleep(1 * time.Second)

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
		c := dns.Client{
			Timeout: 5 * time.Second,
		}

		m := dns.Msg{}

		m.SetQuestion("dns.google.", dns.TypeA)

		r, _, err := c.Exchange(&m, net.JoinHostPort("localhost", fmt.Sprintf("%d", svc.Spec.Port)))
		assert.Nil(t, err)

		assert.True(t, r.Answer[0].(*dns.A).A.String() == "8.8.8.8" || r.Answer[0].(*dns.A).A.String() == "8.8.4.4")
	}

	{
		c := dns.Client{
			Timeout: 5 * time.Second,
		}

		m := dns.Msg{}

		m.SetQuestion(fmt.Sprintf("%s.com.", utilrand.GetRandomStringCanonical(18)), dns.TypeA)

		r, _, err := c.Exchange(&m, net.JoinHostPort("localhost", fmt.Sprintf("%d", svc.Spec.Port)))
		assert.Nil(t, err)

		assert.Equal(t, r.Rcode, dns.RcodeNameError)
	}

	err = srv.Close()
	assert.Nil(t, err)

}
