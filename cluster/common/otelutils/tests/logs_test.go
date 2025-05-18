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
	"net"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

const tstAddr = "localhost:34567"

type tstSrv struct {
	plogotlp.UnimplementedGRPCServer
	t *testing.T
}

func (s *tstSrv) Export(ctx context.Context, req plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {

	reqMap := req.Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Map().AsRaw()

	accessLog := &corev1.AccessLog{}
	err := pbutils.UnmarshalFromMap(reqMap, accessLog)
	assert.Nil(s.t, err)
	assert.Equal(s.t, "octelium", accessLog.Metadata.ActorRef.Name)

	zap.L().Debug("SUCCESS NEW REQ", zap.Any("req", accessLog))

	return plogotlp.NewExportResponse(), nil
}

type tstSrvMetric struct {
	pmetricotlp.UnimplementedGRPCServer
	t *testing.T
}

func (s *tstSrvMetric) Export(ctx context.Context, req pmetricotlp.ExportRequest) (pmetricotlp.ExportResponse, error) {

	js, err := req.MarshalJSON()
	assert.Nil(s.t, err)

	zap.L().Debug("_________===_____", zap.String("ii", string(js)))

	return pmetricotlp.NewExportResponse(), nil
}

func TestServer(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	grpcSrv := grpc.NewServer()
	srv := &tstSrv{
		t: t,
	}

	metricsSrv := &tstSrvMetric{
		t: t,
	}

	plogotlp.RegisterGRPCServer(grpcSrv, srv)
	pmetricotlp.RegisterGRPCServer(grpcSrv, metricsSrv)

	go func() {

		lis, err := net.Listen("tcp", tstAddr)
		if err != nil {
			return
		}
		grpcSrv.Serve(lis)
	}()

	time.Sleep(1 * time.Second)

	logProvider, err := otelutils.CreateLoggerProvider(ctx, tstAddr)
	assert.Nil(t, err)

	metricsProvider, err := otelutils.CreateMetricsProvider(ctx, tstAddr)
	assert.Nil(t, err)

	global.SetLoggerProvider(logProvider)
	otel.SetMeterProvider(metricsProvider)

	err = otelutils.SetProcessMetrics(ctx)
	assert.Nil(t, err)

	for i := 0; i < 5; i++ {
		logEntry := &corev1.AccessLog{
			Metadata: &metav1.LogMetadata{
				CreatedAt: pbutils.Now(),
				ActorRef: &metav1.ObjectReference{
					Name: "octelium",
				},
			},
			Entry: &corev1.AccessLog_Entry{
				Common: &corev1.AccessLog_Entry_Common{
					Status:    corev1.AccessLog_Entry_Common_ALLOWED,
					StartedAt: pbutils.Now(),
				},
			},
		}

		otelutils.EmitAccessLog(logEntry)
		// logman.Set(logEntry)
	}

	m1, err := otelutils.GetMeter().Int64Gauge("m1")
	assert.Nil(t, err)
	for i := 0; i < 10; i++ {

		set1 := attribute.NewSet(attribute.String("k____1", utilrand.GetRandomStringCanonical(4)))
		set2 := attribute.NewSet(attribute.String("k____2", utilrand.GetRandomStringCanonical(4)))
		m1.Record(ctx, int64(i), metric.WithAttributeSet(set1), metric.WithAttributeSet(set2))
		time.Sleep(100 * time.Millisecond)
	}

	h1, err := otelutils.GetMeter().Float64Histogram("his1", metric.WithUnit("ms"))
	assert.Nil(t, err)
	startTime := time.Now()
	for i := 0; i < 10; i++ {
		h1.Record(ctx, float64(time.Since(startTime).Nanoseconds())/1000000,
			metric.WithAttributes(attribute.String("j1", utilrand.GetRandomStringCanonical(4))))
		time.Sleep(100 * time.Millisecond)
	}

	err = logProvider.ForceFlush(ctx)
	assert.Nil(t, err)
	err = metricsProvider.ForceFlush(ctx)
	assert.Nil(t, err)

	err = logProvider.Shutdown(ctx)
	assert.Nil(t, err)

	err = metricsProvider.Shutdown(ctx)
	assert.Nil(t, err)

	time.Sleep(3 * time.Second)
}
