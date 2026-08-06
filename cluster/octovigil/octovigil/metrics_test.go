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
