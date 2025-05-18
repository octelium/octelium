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

package otelutils

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/octelium/octelium/cluster/common/components"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

var defaultAddr = "octelium-collector.octelium.svc:8080"

func CreateMetricsProvider(ctx context.Context, addr string) (*sdkmetric.MeterProvider, error) {

	resource, err := getResource(ctx)
	if err != nil {
		return nil, err
	}

	if addr == "" {
		addr = defaultAddr
	}

	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(addr),
		otlpmetricgrpc.WithInsecure(),
	}

	exporter, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	var interval time.Duration
	if interval == 0 {
		interval = 10 * time.Second
	}

	reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(interval))

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource),
		sdkmetric.WithReader(reader),
	)

	otel.SetMeterProvider(meterProvider)

	return meterProvider, nil
}

func GetMeter() metric.Meter {
	return otel.GetMeterProvider().Meter("default")
}

func GetComponentKeyWithPrefix(arg string) string {
	return fmt.Sprintf("%s.%s.%s", components.MyComponentNamespace(), components.MyComponentType(), arg)
}

func SetProcessMetrics(ctx context.Context) error {

	meter := GetMeter()

	var attrs []metric.ObserveOption

	goroutineNum, err := meter.Int64ObservableUpDownCounter("process.goroutines")
	if err != nil {
		return err
	}

	uptime, err := meter.Int64ObservableCounter("process.uptime", metric.WithUnit("seconds"))
	if err != nil {
		return err
	}

	heapAlloc, err := meter.Int64ObservableUpDownCounter(
		"process.mem.heap_alloc",
		metric.WithUnit("bytes"),
		metric.WithDescription("Bytes allocated by heap"),
	)
	if err != nil {
		return err
	}

	meter.RegisterCallback(func(ctx context.Context, observer metric.Observer) error {
		observer.ObserveInt64(goroutineNum, int64(runtime.NumGoroutine()), attrs...)
		observer.ObserveInt64(uptime, int64(time.Since(components.RuntimeStartedAt()).Seconds()), attrs...)

		memStats := &runtime.MemStats{}
		runtime.ReadMemStats(memStats)

		observer.ObserveInt64(heapAlloc, int64(memStats.HeapAlloc), attrs...)

		return nil
	},
		goroutineNum,
		uptime,
		heapAlloc,
	)

	return nil
}
