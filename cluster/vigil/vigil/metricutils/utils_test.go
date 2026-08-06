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

package metricutils

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
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

func findHistogramDataPoint(t *testing.T, rm *metricdata.ResourceMetrics, name string) metricdata.HistogramDataPoint[float64] {
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != name {
				continue
			}
			his, ok := m.Data.(metricdata.Histogram[float64])
			assert.True(t, ok, name)
			assert.Len(t, his.DataPoints, 1)
			return his.DataPoints[0]
		}
	}
	t.Fatalf("metric %s not found", name)
	return metricdata.HistogramDataPoint[float64]{}
}

func TestAtRequestEndWithAdditionalAttrs(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	m, err := NewCommonMetrics(ctx, newTestSvc())
	assert.Nil(t, err)

	m.AtRequestStart()
	m.AtRequestEnd(time.Now(), metric.WithAttributes(attribute.String("state", "DENIED")))

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	totalDP := findSumDataPoint(t, &rm, "req.total")
	stateVal, ok := totalDP.Attributes.Value("state")
	assert.True(t, ok)
	assert.Equal(t, "DENIED", stateVal.AsString())

	svcVal, ok := totalDP.Attributes.Value(attribute.Key(GetKey("name")))
	assert.True(t, ok)
	assert.Equal(t, "svc1", svcVal.AsString())

	durationDP := findHistogramDataPoint(t, &rm, "req.duration")
	stateVal2, ok := durationDP.Attributes.Value("state")
	assert.True(t, ok)
	assert.Equal(t, "DENIED", stateVal2.AsString())
}

func TestAtRequestEndWithoutAdditionalAttrs(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	m, err := NewCommonMetrics(ctx, newTestSvc())
	assert.Nil(t, err)

	m.AtRequestStart()
	m.AtRequestEnd(time.Now(), nil)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	totalDP := findSumDataPoint(t, &rm, "req.total")
	_, ok := totalDP.Attributes.Value("state")
	assert.False(t, ok)

	svcVal, ok := totalDP.Attributes.Value(attribute.Key(GetKey("name")))
	assert.True(t, ok)
	assert.Equal(t, "svc1", svcVal.AsString())
}

func TestAddBytesTransferred(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	m, err := NewCommonMetrics(ctx, newTestSvc())
	assert.Nil(t, err)

	m.AddBytesTransferred(100, 42)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	sentDP := findSumDataPoint(t, &rm, "req.bytes_sent")
	assert.Equal(t, int64(100), sentDP.Value)

	receivedDP := findSumDataPoint(t, &rm, "req.bytes_received")
	assert.Equal(t, int64(42), receivedDP.Value)
}

func TestAddBytesTransferredSkipsZero(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	m, err := NewCommonMetrics(ctx, newTestSvc())
	assert.Nil(t, err)

	m.AddBytesTransferred(0, 0)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	for _, sm := range rm.ScopeMetrics {
		for _, mt := range sm.Metrics {
			assert.NotEqual(t, "req.bytes_sent", mt.Name)
			assert.NotEqual(t, "req.bytes_received", mt.Name)
		}
	}
}
