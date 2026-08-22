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
	"fmt"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

func GetKey(arg string) string {
	return fmt.Sprintf("octelium.vigil.svc.%s", arg)
}

func GetServiceAttributes(svc *corev1.Service) attribute.Set {

	return attribute.NewSet(
		attribute.String(GetKey("name"), svc.Metadata.Name),
		attribute.String(GetKey("namespace.name"), svc.Status.NamespaceRef.Name),
		attribute.String(GetKey("region.name"), svc.Status.RegionRef.Name),
		attribute.String(GetKey("mode"), ucorev1.ToService(svc).GetMode().String()),
	)
}

type CommonMetrics struct {
	TotalRequests      metric.Int64Counter
	ActiveRequests     metric.Int64UpDownCounter
	RequestDuration    metric.Float64Histogram
	BytesSent          metric.Int64Counter
	BytesReceived      metric.Int64Counter
	CommonAttributeSet attribute.Set

	ActiveSessions  metric.Int64UpDownCounter
	SessionDuration metric.Float64Histogram

	ConnRejected metric.Int64Counter

	RequestTTFB metric.Float64Histogram

	PacketsSent     metric.Int64Counter
	PacketsReceived metric.Int64Counter
}

var sessionDurationBoundaries = []float64{
	100, 500, 1000, 5000, 15000, 60000, 300000, 900000,
	1800000, 3600000, 14400000, 43200000, 86400000,
}

func NewCommonMetrics(ctx context.Context, svc *corev1.Service) (*CommonMetrics, error) {
	ret := &CommonMetrics{}
	var err error

	meter := otelutils.GetMeter()

	ret.ActiveRequests, err = meter.Int64UpDownCounter(
		"req.active", metric.WithDescription("Number of active requests"))
	if err != nil {
		return nil, err
	}

	ret.TotalRequests, err = meter.Int64Counter("req.total",
		metric.WithDescription("Total number of requests"))
	if err != nil {
		return nil, err
	}

	ret.RequestDuration, err = meter.Float64Histogram("req.duration",
		metric.WithUnit("ms"), metric.WithDescription("Request duration in milliseconds"))
	if err != nil {
		return nil, err
	}

	ret.BytesSent, err = meter.Int64Counter("req.bytes_sent",
		metric.WithUnit("bytes"), metric.WithDescription("Total bytes sent downstream"))
	if err != nil {
		return nil, err
	}

	ret.BytesReceived, err = meter.Int64Counter("req.bytes_received",
		metric.WithUnit("bytes"), metric.WithDescription("Total bytes received from downstream"))
	if err != nil {
		return nil, err
	}

	ret.ActiveSessions, err = meter.Int64UpDownCounter("session.active",
		metric.WithDescription("Number of active sessions"))
	if err != nil {
		return nil, err
	}

	ret.SessionDuration, err = meter.Float64Histogram("session.duration",
		metric.WithUnit("ms"), metric.WithDescription("Session duration in milliseconds"),
		metric.WithExplicitBucketBoundaries(sessionDurationBoundaries...))
	if err != nil {
		return nil, err
	}

	ret.ConnRejected, err = meter.Int64Counter("conn.rejected",
		metric.WithDescription(
			"Total number of downstream connections rejected before a session is established"))
	if err != nil {
		return nil, err
	}

	ret.RequestTTFB, err = meter.Float64Histogram("req.ttfb",
		metric.WithUnit("ms"),
		metric.WithDescription("Time to first response byte in milliseconds"))
	if err != nil {
		return nil, err
	}

	ret.PacketsSent, err = meter.Int64Counter("req.packets_sent",
		metric.WithDescription("Total packets sent downstream"))
	if err != nil {
		return nil, err
	}

	ret.PacketsReceived, err = meter.Int64Counter("req.packets_received",
		metric.WithDescription("Total packets received from downstream"))
	if err != nil {
		return nil, err
	}

	ret.CommonAttributeSet = GetServiceAttributes(svc)

	return ret, nil
}

func (m *CommonMetrics) AtRequestStart() {
	m.ActiveRequests.Add(context.Background(), 1, metric.WithAttributeSet(m.CommonAttributeSet))
}

func (m *CommonMetrics) AtRequestEnd(startTime time.Time, additionalAttrSet metric.MeasurementOption) {

	ctx := context.Background()
	m.ActiveRequests.Add(ctx, -1,
		metric.WithAttributeSet(m.CommonAttributeSet))

	durationMs := float64(time.Since(startTime).Nanoseconds()) / 1000000

	if additionalAttrSet == nil {
		m.RequestDuration.Record(ctx, durationMs, metric.WithAttributeSet(m.CommonAttributeSet))
		m.TotalRequests.Add(ctx, 1, metric.WithAttributeSet(m.CommonAttributeSet))
		return
	}

	m.RequestDuration.Record(ctx, durationMs, metric.WithAttributeSet(m.CommonAttributeSet), additionalAttrSet)
	m.TotalRequests.Add(ctx, 1, metric.WithAttributeSet(m.CommonAttributeSet), additionalAttrSet)
}

func (m *CommonMetrics) AddBytesTransferred(sent, received int64,
	additionalAttrSets ...metric.MeasurementOption) {
	ctx := context.Background()

	opts := m.addOpts(additionalAttrSets...)

	if sent > 0 {
		m.BytesSent.Add(ctx, sent, opts...)
	}

	if received > 0 {
		m.BytesReceived.Add(ctx, received, opts...)
	}
}

func (m *CommonMetrics) AddPacketsTransferred(sent, received int64,
	additionalAttrSets ...metric.MeasurementOption) {
	ctx := context.Background()

	opts := m.addOpts(additionalAttrSets...)

	if sent > 0 {
		m.PacketsSent.Add(ctx, sent, opts...)
	}

	if received > 0 {
		m.PacketsReceived.Add(ctx, received, opts...)
	}
}

func (m *CommonMetrics) AtSessionStart() {
	m.ActiveSessions.Add(context.Background(), 1,
		metric.WithAttributeSet(m.CommonAttributeSet))
}

func (m *CommonMetrics) AtSessionEnd(startTime time.Time,
	additionalAttrSets ...metric.MeasurementOption) {
	ctx := context.Background()

	m.ActiveSessions.Add(ctx, -1, metric.WithAttributeSet(m.CommonAttributeSet))

	durationMs := float64(time.Since(startTime).Nanoseconds()) / 1000000
	m.SessionDuration.Record(ctx, durationMs, m.recordOpts(additionalAttrSets...)...)
}

func (m *CommonMetrics) AddConnRejected(stage string,
	additionalAttrSets ...metric.MeasurementOption) {
	opts := m.addOpts(additionalAttrSets...)
	opts = append(opts, metric.WithAttributes(attribute.String("stage", stage)))

	m.ConnRejected.Add(context.Background(), 1, opts...)
}

func (m *CommonMetrics) addOpts(
	additionalAttrSets ...metric.MeasurementOption) []metric.AddOption {
	ret := make([]metric.AddOption, 0, len(additionalAttrSets)+1)
	ret = append(ret, metric.WithAttributeSet(m.CommonAttributeSet))

	for _, attrSet := range additionalAttrSets {
		if attrSet == nil {
			continue
		}
		ret = append(ret, attrSet)
	}

	return ret
}

func (m *CommonMetrics) recordOpts(
	additionalAttrSets ...metric.MeasurementOption) []metric.RecordOption {
	ret := make([]metric.RecordOption, 0, len(additionalAttrSets)+1)
	ret = append(ret, metric.WithAttributeSet(m.CommonAttributeSet))

	for _, attrSet := range additionalAttrSets {
		if attrSet == nil {
			continue
		}
		ret = append(ret, attrSet)
	}

	return ret
}
