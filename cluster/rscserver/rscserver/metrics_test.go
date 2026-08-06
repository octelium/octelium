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

package rscserver

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
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

func TestAtRequestEndWithAdditionalAttrs(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	m, err := newCommonMetrics(ctx)
	assert.Nil(t, err)

	m.atRequestStart()
	m.atRequestEnd(time.Now(),
		metric.WithAttributes(
			attribute.Bool("error", false),
			attribute.String("op", "get"),
		))

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	totalDP := findSumDataPoint(t, &rm, "req.total")
	opVal, ok := totalDP.Attributes.Value("op")
	assert.True(t, ok)
	assert.Equal(t, "get", opVal.AsString())

	_, ok = totalDP.Attributes.Value("error")
	assert.True(t, ok)
}

func TestAtRequestEndWithoutAdditionalAttrs(t *testing.T) {
	ctx := context.Background()
	reader := setTestMeterProvider(t)

	m, err := newCommonMetrics(ctx)
	assert.Nil(t, err)

	m.atRequestStart()
	m.atRequestEnd(time.Now(), nil)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	totalDP := findSumDataPoint(t, &rm, "req.total")
	_, ok := totalDP.Attributes.Value("op")
	assert.False(t, ok)
}

func TestHandleUnaryRequestMetricsAttributes(t *testing.T) {
	reader := setTestMeterProvider(t)

	tst, err := initTest()
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	ctx := context.Background()

	srv, err := NewServer(ctx, nil)
	assert.Nil(t, err)

	api := "core"
	version := "v1"
	kind := ucorev1.KindUser

	obj := newTestResource(kind)
	obj.GetMetadata().Name = utilrand.GetRandomStringLowercase(8)
	created, err := srv.doCreate(ctx, obj, api, version, kind)
	assert.Nil(t, err)

	info := &grpc.UnaryServerInfo{
		FullMethod: "/octelium.api.rsc.core.v1.ResourceService/GetUser",
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return nil, nil
	}

	_, err = srv.handleUnaryRequest(ctx, &rmetav1.GetOptions{Uid: created.GetMetadata().Uid}, info, handler)
	assert.Nil(t, err)

	var rm metricdata.ResourceMetrics
	assert.Nil(t, reader.Collect(ctx, &rm))

	dp := findSumDataPoint(t, &rm, "req.total")

	apiVal, ok := dp.Attributes.Value("api")
	assert.True(t, ok)
	assert.Equal(t, api, apiVal.AsString())

	kindVal, ok := dp.Attributes.Value("kind")
	assert.True(t, ok)
	assert.Equal(t, kind, kindVal.AsString())

	opVal, ok := dp.Attributes.Value("op")
	assert.True(t, ok)
	assert.Equal(t, "get", opVal.AsString())
}
