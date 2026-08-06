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
	"fmt"
	"net"
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
