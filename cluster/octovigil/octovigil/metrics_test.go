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

package octovigil

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
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

func TestAtAuthorizationRequestEndWithAdditionalAttrs(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	m, err := newCommonMetrics(ctx)
	assert.Nil(t, err)

	m.atAuthorizationRequestStart()
	m.atAuthorizationRequestEnd(time.Now(),
		metric.WithAttributeSet(
			attribute.NewSet(
				attribute.Bool("req.authorized", false),
				attribute.Bool("req.error", false))))

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	totalDP := findSumDataPoint(t, &rm, "authorization.req.total")
	authVal, ok := totalDP.Attributes.Value("req.authorized")
	assert.True(t, ok)
	assert.False(t, authVal.AsBool())

	_, ok = totalDP.Attributes.Value("req.error")
	assert.True(t, ok)
}

func TestAtAuthorizationRequestEndWithoutAdditionalAttrs(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	m, err := newCommonMetrics(ctx)
	assert.Nil(t, err)

	m.atAuthorizationRequestStart()
	m.atAuthorizationRequestEnd(time.Now(), nil)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	totalDP := findSumDataPoint(t, &rm, "authorization.req.total")
	_, ok := totalDP.Attributes.Value("req.authorized")
	assert.False(t, ok)
}

func TestIsAuthorizedWithMetricsAttributes(t *testing.T) {
	ctx := context.Background()

	reader := setTestMeterProvider(t)

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(tst.C.OcteliumC)

	ns, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	svc, err := adminSrv.CreateService(ctx, tests.GenService(ns.Metadata.Name))
	assert.Nil(t, err)

	srv, err := New(ctx, tst.C.OcteliumC)
	assert.Nil(t, err)
	srv.cache.SetService(svc)
	assert.Nil(t, srv.cache.SetNamespace(ns))

	usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	srv.cache.SetUser(usr.Usr)

	assert.Nil(t, usr.Connect())
	usr.Resync()

	srv.cache.SetSession(usr.Session)

	req := &coctovigilv1.DownstreamRequest{
		Source: &coctovigilv1.DownstreamRequest_Source{
			Address: umetav1.ToDualStackNetwork(usr.Session.Status.Connection.Addresses[0]).ToIP().Ipv4,
		},
	}

	// No Authorization policy is configured on the Service, so the request must be denied.
	resp, err := srv.AuthenticateAndAuthorize(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
		Service: svc,
		Request: req,
	})
	assert.Nil(t, err)
	assert.True(t, resp.IsAuthenticated)
	assert.False(t, resp.IsAuthorized)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	dp := findSumDataPoint(t, &rm, "authorization.req.total")

	svcVal, ok := dp.Attributes.Value("service")
	assert.True(t, ok)
	assert.Equal(t, svc.Metadata.Name, svcVal.AsString())

	nsVal, ok := dp.Attributes.Value("namespace")
	assert.True(t, ok)
	assert.Equal(t, ns.Metadata.Name, nsVal.AsString())

	reasonVal, ok := dp.Attributes.Value("reason")
	assert.True(t, ok)
	assert.NotEqual(t, "", reasonVal.AsString())
}

type failingMeter struct {
	metric.Meter
	name string
	err  error
}

func (m *failingMeter) Int64UpDownCounter(name string, opts ...metric.Int64UpDownCounterOption) (metric.Int64UpDownCounter, error) {
	if name == m.name {
		return nil, m.err
	}
	return m.Meter.Int64UpDownCounter(name, opts...)
}

func (m *failingMeter) Int64Counter(name string, opts ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	if name == m.name {
		return nil, m.err
	}
	return m.Meter.Int64Counter(name, opts...)
}

func (m *failingMeter) Float64Histogram(name string, opts ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	if name == m.name {
		return nil, m.err
	}
	return m.Meter.Float64Histogram(name, opts...)
}

type failingMeterProvider struct {
	metric.MeterProvider
	meter metric.Meter
}

func (m *failingMeterProvider) Meter(name string, opts ...metric.MeterOption) metric.Meter {
	return m.meter
}

func TestCommonMetricsErrors(t *testing.T) {
	setTestMeterProvider(t)
	previous := otel.GetMeterProvider()
	t.Cleanup(func() { otel.SetMeterProvider(previous) })
	for _, name := range []string{"authorization.req.active", "authorization.req.total", "authorization.req.duration"} {
		t.Run(name, func(t *testing.T) {
			errTst := errors.New("could not create instrument")
			provider := sdkmetric.NewMeterProvider()
			t.Cleanup(func() { provider.Shutdown(context.Background()) })
			otel.SetMeterProvider(&failingMeterProvider{meter: &failingMeter{Meter: provider.Meter("default"), name: name, err: errTst}})
			metrics, err := newCommonMetrics(t.Context())
			assert.Nil(t, metrics)
			assert.ErrorIs(t, err, errTst)
		})
	}
}

func TestAuthorizationMetricsOutcomes(t *testing.T) {
	for _, mode := range []string{"Allowed", "Denied", "Error"} {
		t.Run(mode, func(t *testing.T) {
			reader := setTestMeterProvider(t)
			srv, coreC := newAuthorizationService(t)
			switch mode {
			case "Denied":
				coreC.service.Spec.Authorization = nil
			case "Error":
				coreC.service.Spec.Authorization.Policies = []string{"invalid..name"}
			}
			di, err := srv.s.GetDownstreamInfo(t.Context(), "100.64.0.2")
			assert.Nil(t, err)
			allowed, _, err := srv.s.isAuthorizedWithMetrics(t.Context(), srv.s.getReqCtx(di, nil, coreC.service), nil)
			assert.Equal(t, mode == "Allowed", allowed)
			assert.Equal(t, mode == "Error", err != nil)
			var metrics metricdata.ResourceMetrics
			assert.Nil(t, reader.Collect(t.Context(), &metrics))
			total := findSumDataPoint(t, &metrics, "authorization.req.total")
			assert.Equal(t, int64(1), total.Value)
			value, ok := total.Attributes.Value("req.error")
			assert.True(t, ok)
			assert.Equal(t, mode == "Error", value.AsBool())
			value, ok = total.Attributes.Value("req.authorized")
			assert.True(t, ok)
			assert.Equal(t, mode == "Allowed", value.AsBool())
			_, ok = total.Attributes.Value("reason")
			assert.Equal(t, mode != "Allowed", ok)
			active := findSumDataPoint(t, &metrics, "authorization.req.active")
			assert.Equal(t, int64(0), active.Value)
		})
	}
}
