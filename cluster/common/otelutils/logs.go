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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

type LogManagerV2 struct {
}

func getResource(ctx context.Context) (*resource.Resource, error) {

	ret := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String("octelium"),
		semconv.ServiceVersionKey.String("1.0.0"),
		attribute.String("octelium.component.type", components.MyComponentType()),
		attribute.String("octelium.component.uid", components.MyComponentUID()),
		attribute.String("octelium.component.namespace", components.MyComponentNamespace()),
		attribute.String("octelium.component.version", ldflags.GetVersion()),
		attribute.String("octelium.region.name", vutils.GetMyRegionName()),
	)

	return ret, nil
}

func CreateLoggerProvider(ctx context.Context, addr string) (*sdklog.LoggerProvider, error) {
	if addr == "" {
		addr = defaultAddr
	}

	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(addr),
		otlploggrpc.WithInsecure(),
	}

	exporter, err := otlploggrpc.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	resource, err := getResource(ctx)
	if err != nil {
		return nil, err
	}

	loggerProvider := sdklog.NewLoggerProvider(
		sdklog.WithResource(resource),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
	)

	return loggerProvider, nil
}

func GetLogger() log.Logger {
	return global.GetLoggerProvider().Logger("default")
}

func EmitAccessLog(in *corev1.AccessLog) {
	inMap := pbutils.MustConvertToMap(in)

	ret := log.Record{}
	ret.SetTimestamp((in.GetMetadata().CreatedAt.AsTime()))
	ret.SetObservedTimestamp(pbutils.Now().AsTime())
	ret.SetSeverity(log.SeverityInfo)

	ret.SetBody(convertValue(inMap))

	GetLogger().Emit(context.Background(), ret)
}
