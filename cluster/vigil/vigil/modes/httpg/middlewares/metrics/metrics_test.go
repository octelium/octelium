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

package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func newTestSvc() *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "svc1",
		},
		Spec: &corev1.Service_Spec{},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "ns1"},
			RegionRef:    &metav1.ObjectReference{Name: "region1"},
		},
	}
}

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

func TestServeHTTPDeniedReason(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	commonMetrics, err := metricutils.NewCommonMetrics(ctx, newTestSvc())
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	mdlwr, err := New(ctx, next, commonMetrics)
	assert.Nil(t, err)

	reqCtx := &middlewares.RequestContext{
		CreatedAt:    time.Now(),
		IsAuthorized: false,
		DecisionReason: &corev1.AccessLog_Entry_Common_Reason{
			Type: corev1.AccessLog_Entry_Common_Reason_SESSION_EXPIRED,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req = req.WithContext(context.WithValue(req.Context(), middlewares.CtxRequestContext, reqCtx))

	rec := httptest.NewRecorder()
	mdlwr.ServeHTTP(rec, req)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	dp := findSumDataPoint(t, &rm, "req.total")

	stateVal, ok := dp.Attributes.Value("state")
	assert.True(t, ok)
	assert.Equal(t, "DENIED", stateVal.AsString())

	reasonVal, ok := dp.Attributes.Value("reason")
	assert.True(t, ok)
	assert.Equal(t, "SESSION_EXPIRED", reasonVal.AsString())
}

func TestServeHTTPAllowedNoReason(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	commonMetrics, err := metricutils.NewCommonMetrics(ctx, newTestSvc())
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mdlwr, err := New(ctx, next, commonMetrics)
	assert.Nil(t, err)

	reqCtx := &middlewares.RequestContext{
		CreatedAt:    time.Now(),
		IsAuthorized: true,
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	req = req.WithContext(context.WithValue(req.Context(), middlewares.CtxRequestContext, reqCtx))

	rec := httptest.NewRecorder()
	mdlwr.ServeHTTP(rec, req)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	dp := findSumDataPoint(t, &rm, "req.total")

	stateVal, ok := dp.Attributes.Value("state")
	assert.True(t, ok)
	assert.Equal(t, "ALLOWED", stateVal.AsString())

	_, ok = dp.Attributes.Value("reason")
	assert.False(t, ok)
}
