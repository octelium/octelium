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

package metricsstore

/*
import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

type MetricsStore struct {
	octeliumC octeliumc.ClientInterface
	meter     metric.Meter
	exporter  sdkmetric.Exporter

	totalRequests   metric.Int64Counter
	activeRequests  metric.Int64UpDownCounter
	requestDuration metric.Float64Histogram

	svcUID     string
	svcName    string
	nsUID      string
	nsName     string
	podUID     string
	regionName string

	svcMode string

	isDummy bool
}

type MetricStoreOpts struct {
	Service   *corev1.Service
	OcteliumC octeliumc.ClientInterface
}

func NewMetricsStore(ctx context.Context, opts *MetricStoreOpts) (*MetricsStore, error) {
	if opts == nil {
		return &MetricsStore{
			isDummy: true,
		}, nil
	}

	var err error

	svc := opts.Service
	ret := &MetricsStore{
		octeliumC:  opts.OcteliumC,
		svcUID:     svc.Metadata.Uid,
		svcName:    svc.Metadata.Name,
		nsUID:      svc.Status.NamespaceRef.Uid,
		nsName:     svc.Status.NamespaceRef.Name,
		podUID:     os.Getenv("OCTELIUM_POD_UID"),
		regionName: os.Getenv("OCTELIUM_REGION_NAME"),
		svcMode:    ucorev1.ToService(svc).GetMode().String(),
	}

	cc, err := ret.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}

	endpoint := func() string {
		if cc.Spec.Observability == nil ||
			cc.Spec.Observability.Receiver == nil ||
			cc.Spec.Observability.Receiver.Endpoint == "" {
			return ""
		}
		return cc.Spec.Observability.Receiver.Endpoint
	}()

	if endpoint == "" {
		ret.isDummy = true
		return ret, nil
	}

	interval := func() time.Duration {
		if cc.Spec.Observability == nil || cc.Spec.Observability.Metrics == nil ||
			cc.Spec.Observability.Metrics.IntervalDuration == nil {
			return 0
		}
		return umetav1.ToDuration(cc.Spec.Observability.Metrics.IntervalDuration).ToGo()
	}()

	ret.exporter, err = otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithInsecure(),
		otlpmetricgrpc.WithEndpoint(endpoint))
	if err != nil {
		return nil, err
	}

	if interval == 0 {
		interval = 10 * time.Second
	}

	otelServiceName := fmt.Sprintf("com.octelium.service.%s",
		opts.Service.Metadata.Name)

	reader := sdkmetric.NewPeriodicReader(ret.exporter, sdkmetric.WithInterval(interval))

	attrs := []attribute.KeyValue{
		semconv.ServiceNameKey.String(otelServiceName),
		semconv.ServiceVersionKey.String(ldflags.SemVer),
	}

	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		attrs...,
	)

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
	)

	ret.meter = meterProvider.Meter(otelServiceName,
		metric.WithInstrumentationVersion("1.0.0"),
		metric.WithInstrumentationAttributes(ret.getCommonAttributes()...))

	ret.totalRequests, err = ret.meter.Int64Counter("req.total")
	if err != nil {
		return nil, err
	}

	ret.activeRequests, err = ret.meter.Int64UpDownCounter("req.active")
	if err != nil {
		return nil, err
	}

	ret.requestDuration, err = ret.meter.Float64Histogram("req.duration", metric.WithUnit("ms"))
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (m *MetricsStore) getCommonAttributes() []attribute.KeyValue {
	return []attribute.KeyValue{

		{
			Key:   "octelium.svc.name",
			Value: attribute.StringValue(m.svcName),
		},

		{
			Key:   "octelium.svc.namespace.name",
			Value: attribute.StringValue(m.nsName),
		},
		{
			Key:   "octelium.svc.pod.uid",
			Value: attribute.StringValue(m.podUID),
		},
		{
			Key:   "octelium.svc.region.name",
			Value: attribute.StringValue(m.regionName),
		},
		{
			Key:   "octelium.svc.mode",
			Value: attribute.StringValue(m.svcMode),
		},
	}
}

func (m *MetricsStore) AtRequestStart() {
	if m.isDummy {
		return
	}

	m.activeRequests.Add(context.Background(), 1)
}

func (m *MetricsStore) AtRequestEnd(startTime time.Time, additionalAttrs []attribute.KeyValue) {
	if m.isDummy {
		return
	}

	ctx := context.Background()
	m.activeRequests.Add(ctx, -1)

	m.requestDuration.Record(ctx,
		float64(time.Since(startTime).Nanoseconds())/1000000)
	m.totalRequests.Add(ctx, 1, metric.WithAttributes())
}

func (m *MetricsStore) Run(ctx context.Context) error {
	if m.isDummy {
		return nil
	}

	meter := m.meter
	startTime := time.Now()

	var attrs []metric.ObserveOption

	goroutineNum, err := meter.Int64ObservableUpDownCounter("process.goroutines")
	if err != nil {
		return err
	}

	uptime, err := meter.Int64ObservableCounter("process.uptime", metric.WithUnit("ms"))
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
		observer.ObserveInt64(uptime, time.Since(startTime).Milliseconds(), attrs...)

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

func (m *MetricsStore) Close() error {
	if m.isDummy {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.exporter.Shutdown(ctx); err != nil {
		otel.Handle(err)
	}

	return nil
}
*/
