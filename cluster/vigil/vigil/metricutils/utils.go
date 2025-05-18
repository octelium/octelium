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
	CommonAttributeSet attribute.Set
}

func NewCommonMetrics(ctx context.Context, svc *corev1.Service) (*CommonMetrics, error) {
	ret := &CommonMetrics{}
	var err error

	meter := otelutils.GetMeter()

	ret.ActiveRequests, err = meter.Int64UpDownCounter(
		otelutils.GetComponentKeyWithPrefix("req.active"), metric.WithDescription("Number of active requests"))
	if err != nil {
		return nil, err
	}

	ret.TotalRequests, err = meter.Int64Counter(otelutils.GetComponentKeyWithPrefix("req.total"),
		metric.WithDescription("Total number of requests"))
	if err != nil {
		return nil, err
	}

	ret.RequestDuration, err = meter.Float64Histogram(otelutils.GetComponentKeyWithPrefix("req.duration"),
		metric.WithUnit("ms"), metric.WithDescription("Request duration in milliseconds"))
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

	m.RequestDuration.Record(ctx,
		float64(time.Since(startTime).Nanoseconds())/1000000,
		metric.WithAttributeSet(m.CommonAttributeSet),
	)
	m.TotalRequests.Add(ctx, 1,
		metric.WithAttributeSet(m.CommonAttributeSet))
}
