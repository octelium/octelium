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
	"math"
	"net"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/components/otelcore"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

	metricsProvider.ForceFlush(ctx)

	err = logProvider.Shutdown(ctx)
	assert.Nil(t, err)

	metricsProvider.Shutdown(ctx)

	time.Sleep(3 * time.Second)
}

type componentLogSrv struct {
	plogotlp.UnimplementedGRPCServer
	records chan plog.LogRecord
}

func (s *componentLogSrv) Export(ctx context.Context, req plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	resources := req.Logs().ResourceLogs()
	for i := range resources.Len() {
		scopes := resources.At(i).ScopeLogs()
		for j := range scopes.Len() {
			records := scopes.At(j).LogRecords()
			for k := range records.Len() {
				record := plog.NewLogRecord()
				records.At(k).CopyTo(record)
				select {
				case s.records <- record:
				case <-ctx.Done():
					return plogotlp.NewExportResponse(), ctx.Err()
				}
			}
		}
	}
	return plogotlp.NewExportResponse(), nil
}

func TestComponentLogExport(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	levels := []struct {
		level    zapcore.Level
		severity plog.SeverityNumber
		want     corev1.ComponentLog_Entry_Level
	}{
		{zapcore.DebugLevel, plog.SeverityNumberDebug, corev1.ComponentLog_Entry_DEBUG},
		{zapcore.InfoLevel, plog.SeverityNumberInfo, corev1.ComponentLog_Entry_INFO},
		{zapcore.WarnLevel, plog.SeverityNumberWarn, corev1.ComponentLog_Entry_WARN},
		{zapcore.ErrorLevel, plog.SeverityNumberError, corev1.ComponentLog_Entry_ERROR},
		{zapcore.DPanicLevel, plog.SeverityNumberFatal, corev1.ComponentLog_Entry_PANIC},
		{zapcore.PanicLevel, plog.SeverityNumberFatal2, corev1.ComponentLog_Entry_PANIC},
		{zapcore.FatalLevel, plog.SeverityNumberFatal3, corev1.ComponentLog_Entry_FATAL},
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	srv := &componentLogSrv{records: make(chan plog.LogRecord, len(levels)+1)}
	grpcSrv := grpc.NewServer()
	plogotlp.RegisterGRPCServer(grpcSrv, srv)
	done := make(chan error, 1)
	go func() {
		done <- grpcSrv.Serve(lis)
	}()
	t.Cleanup(func() {
		grpcSrv.Stop()
		err := <-done
		assert.True(t, err == nil || err == grpc.ErrServerStopped, "%+v", err)
	})

	exporter, err := otlploggrpc.New(ctx, otlploggrpc.WithEndpoint(lis.Addr().String()), otlploggrpc.WithInsecure())
	require.Nil(t, err)
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.Nil(t, provider.Shutdown(ctx))
	})

	c := otelcore.NewOTELCore(provider.Logger("component-test")).With([]zapcore.Field{
		zap.String("context", "original"), zap.Float32("float32", 1.5),
	})
	require.NotNil(t, c)
	for _, level := range levels {
		require.Nil(t, c.Write(zapcore.Entry{Level: level.level, Time: time.Now(), Message: level.level.String()},
			[]zapcore.Field{zap.Float64("float64", -2.5), zap.Uint64("uint64", math.MaxUint64), zap.Float64("nan", math.NaN())}))
	}
	logger := zap.New(zapcore.NewTee(zapcore.NewNopCore(), c))
	logger.With(zap.String("context", "child"), zap.String("request", "request")).Warn("child")
	require.Nil(t, provider.ForceFlush(ctx))

	seen := map[string]bool{}
	for range len(levels) + 1 {
		var record plog.LogRecord
		select {
		case record = <-srv.records:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		res := &corev1.ComponentLog{}
		require.Nil(t, pbutils.UnmarshalJSON([]byte(record.Body().Str()), res))
		assert.False(t, seen[res.Entry.Message])
		seen[res.Entry.Message] = true
		assert.Equal(t, "core/v1", res.ApiVersion)
		assert.Equal(t, "ComponentLog", res.Kind)
		assert.NotEmpty(t, res.Metadata.Id)
		assert.False(t, record.Timestamp().AsTime().IsZero())
		assert.False(t, record.ObservedTimestamp().AsTime().IsZero())
		fields := res.Entry.Fields.Fields
		assert.Equal(t, 1.5, fields["float32"].GetNumberValue())
		if res.Entry.Message == "child" {
			assert.Equal(t, plog.SeverityNumberWarn, record.SeverityNumber())
			assert.Equal(t, "warn", record.SeverityText())
			assert.Equal(t, corev1.ComponentLog_Entry_WARN, res.Entry.Level)
			assert.Equal(t, "child", fields["context"].GetStringValue())
			assert.Equal(t, "request", fields["request"].GetStringValue())
			assert.Len(t, fields, 3)
			continue
		}
		assert.Equal(t, "original", fields["context"].GetStringValue())
		assert.Equal(t, -2.5, fields["float64"].GetNumberValue())
		assert.Equal(t, float64(math.MaxUint64), fields["uint64"].GetNumberValue())
		assert.Equal(t, "NaN", fields["nan"].GetStringValue())
		assert.Len(t, fields, 5)
		found := false
		for _, level := range levels {
			if res.Entry.Message == level.level.String() {
				assert.Equal(t, level.severity, record.SeverityNumber())
				assert.Equal(t, level.level.String(), record.SeverityText())
				assert.Equal(t, level.want, res.Entry.Level)
				found = true
				break
			}
		}
		assert.True(t, found, res.Entry.Message)
	}
	assert.Len(t, seen, len(levels)+1)
}
