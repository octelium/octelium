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
	"runtime"
	"runtime/metrics"
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

	conn, err := getGRPCConn(ctx, addr)
	if err != nil {
		return nil, err
	}

	exporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
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

const (
	smHeapAlloc = iota
	smMemTotal
	smStacks
	smGCCycles
	smGCHeapGoal
	smCPUGC
	smCPUTotal
)

func SetProcessMetrics(ctx context.Context) error {
	meter := GetMeter()

	goroutines, err := meter.Int64ObservableGauge(
		"process.goroutines",
		metric.WithUnit("goroutines"),
		metric.WithDescription("Current number of goroutines"),
	)
	if err != nil {
		return err
	}

	gomaxprocs, err := meter.Int64ObservableGauge(
		"process.gomaxprocs",
		metric.WithDescription("Current GOMAXPROCS setting"),
	)
	if err != nil {
		return err
	}

	uptime, err := meter.Int64ObservableCounter(
		"process.uptime",
		metric.WithUnit("seconds"),
		metric.WithDescription("Process uptime in seconds"),
	)
	if err != nil {
		return err
	}

	heapAlloc, err := meter.Int64ObservableGauge(
		"process.mem.heap_alloc",
		metric.WithUnit("bytes"),
		metric.WithDescription("Bytes of allocated heap objects"),
	)
	if err != nil {
		return err
	}

	memTotal, err := meter.Int64ObservableGauge(
		"process.mem.total",
		metric.WithUnit("bytes"),
		metric.WithDescription("Total bytes of memory mapped by the Go runtime"),
	)
	if err != nil {
		return err
	}

	stacks, err := meter.Int64ObservableGauge(
		"process.mem.stacks",
		metric.WithUnit("bytes"),
		metric.WithDescription("Memory used by goroutine stacks"),
	)
	if err != nil {
		return err
	}

	gcCycles, err := meter.Int64ObservableCounter(
		"process.gc.cycles",
		metric.WithUnit("gc-cycles"),
		metric.WithDescription("Completed GC cycles"),
	)
	if err != nil {
		return err
	}

	gcHeapGoal, err := meter.Int64ObservableGauge(
		"process.gc.heap_goal",
		metric.WithUnit("bytes"),
		metric.WithDescription("Target heap size for the next GC cycle"),
	)
	if err != nil {
		return err
	}

	cpuGCSeconds, err := meter.Float64ObservableCounter(
		"process.cpu.gc_seconds",
		metric.WithUnit("seconds"),
		metric.WithDescription("Cumulative CPU time spent in garbage collection"),
	)
	if err != nil {
		return err
	}

	cpuSeconds, err := meter.Float64ObservableCounter(
		"process.cpu.seconds",
		metric.WithUnit("seconds"),
		metric.WithDescription("Cumulative CPU time consumed by the Go runtime"),
	)
	if err != nil {
		return err
	}

	samples := []metrics.Sample{
		smHeapAlloc:  {Name: "/memory/classes/heap/objects:bytes"},
		smMemTotal:   {Name: "/memory/classes/total:bytes"},
		smStacks:     {Name: "/memory/classes/heap/stacks:bytes"},
		smGCCycles:   {Name: "/gc/cycles/total:gc-cycles"},
		smGCHeapGoal: {Name: "/gc/heap/goal:bytes"},
		smCPUGC:      {Name: "/cpu/classes/gc/total:cpu-seconds"},
		smCPUTotal:   {Name: "/cpu/classes/total:cpu-seconds"},
	}

	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		o.ObserveInt64(goroutines, int64(runtime.NumGoroutine()))
		o.ObserveInt64(gomaxprocs, int64(runtime.GOMAXPROCS(0)))
		o.ObserveInt64(uptime, int64(time.Since(components.RuntimeStartedAt()).Seconds()))

		metrics.Read(samples)

		observeProcessUint(o, heapAlloc, samples[smHeapAlloc])
		observeProcessUint(o, memTotal, samples[smMemTotal])
		observeProcessUint(o, stacks, samples[smStacks])
		observeProcessUint(o, gcCycles, samples[smGCCycles])
		observeProcessUint(o, gcHeapGoal, samples[smGCHeapGoal])
		observeProcessFloat(o, cpuGCSeconds, samples[smCPUGC])
		observeProcessFloat(o, cpuSeconds, samples[smCPUTotal])

		return nil
	},
		goroutines,
		gomaxprocs,
		uptime,
		heapAlloc,
		memTotal,
		stacks,
		gcCycles,
		gcHeapGoal,
		cpuGCSeconds,
		cpuSeconds,
	)

	return err
}

func observeProcessUint(o metric.Observer, inst metric.Int64Observable, s metrics.Sample) {
	if s.Value.Kind() != metrics.KindUint64 {
		return
	}

	o.ObserveInt64(inst, uint64ToInt64Saturating(s.Value.Uint64()))
}

func observeProcessFloat(o metric.Observer, inst metric.Float64Observable, s metrics.Sample) {
	if s.Value.Kind() != metrics.KindFloat64 {
		return
	}

	o.ObserveFloat64(inst, s.Value.Float64())
}

func uint64ToInt64Saturating(v uint64) int64 {
	const maxInt64 = uint64(1<<63 - 1)
	if v > maxInt64 {
		return int64(maxInt64)
	}
	return int64(v)
}
