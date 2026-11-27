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
	"errors"
	"math"
	"math/rand/v2"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/noop"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/protobuf/types/known/structpb"
)

type testLogExporter struct {
	records    chan sdklog.Record
	batchSizes chan int
	err        error
	stopped    atomic.Bool
}

func (e *testLogExporter) Export(ctx context.Context, records []sdklog.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.stopped.Load() {
		return sdklog.ErrExporterShutdown
	}
	if len(records) == 0 {
		return nil
	}
	if e.err != nil {
		return e.err
	}
	e.batchSizes <- len(records)
	for _, record := range records {
		e.records <- record.Clone()
	}
	return nil
}

func (e *testLogExporter) ForceFlush(context.Context) error {
	return nil
}

func (e *testLogExporter) Shutdown(context.Context) error {
	e.stopped.Store(true)
	return nil
}

func TestLoggerProviderLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resource, err := getResource(ctx)
	require.Nil(t, err)
	exporter := &testLogExporter{
		records:    make(chan sdklog.Record, 16),
		batchSizes: make(chan int, 16),
	}
	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(resource),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter,
			sdklog.WithMaxQueueSize(16), sdklog.WithExportMaxBatchSize(4),
			sdklog.WithExportInterval(time.Hour))),
	)
	previous := otel.GetLoggerProvider()
	otel.SetLoggerProvider(provider)
	t.Cleanup(func() {
		otel.SetLoggerProvider(previous)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.Nil(t, provider.Shutdown(ctx))
	})

	now := time.Now()
	for i := range 6 {
		record := log.Record{}
		record.SetTimestamp(now)
		record.SetSeverity(log.SeverityInfo)
		record.SetBody(attribute.MapValue(attribute.String("message", "exported")))
		record.AddAttributes(attribute.Int("sequence", i))
		GetLogger().Emit(ctx, record)
	}
	require.Nil(t, provider.ForceFlush(ctx))
	require.Len(t, exporter.records, 6)

	seen := map[int64]bool{}
	for range 6 {
		record := <-exporter.records
		assert.Equal(t, now, record.Timestamp())
		assert.Equal(t, log.SeverityInfo, record.Severity())
		assert.Equal(t, attribute.MapValue(attribute.String("message", "exported")), record.Body())
		assert.True(t, resource.Equal(record.Resource()))
		value, ok := record.Resource().Set().Value("service.name")
		assert.True(t, ok)
		assert.Equal(t, "octelium", value.AsString())
		assert.Equal(t, "default", record.InstrumentationScope().Name)
		require.Equal(t, 1, record.AttributesLen())
		record.WalkAttributes(func(kv attribute.KeyValue) bool {
			assert.Equal(t, attribute.Key("sequence"), kv.Key)
			assert.False(t, seen[kv.Value.AsInt64()])
			seen[kv.Value.AsInt64()] = true
			return true
		})
	}
	for i := range 6 {
		assert.True(t, seen[int64(i)])
	}

	for range 3 {
		record := log.Record{}
		record.SetBody(attribute.StringValue("shutdown"))
		GetLogger().Emit(ctx, record)
	}
	require.Nil(t, provider.Shutdown(ctx))
	assert.True(t, exporter.stopped.Load())
	require.Len(t, exporter.records, 3)
	for range 3 {
		record := <-exporter.records
		assert.Equal(t, "shutdown", record.Body().AsString())
	}
	for len(exporter.batchSizes) > 0 {
		assert.LessOrEqual(t, <-exporter.batchSizes, 4)
	}
	GetLogger().Emit(ctx, log.Record{})
	assert.Empty(t, exporter.records)
}

func TestLoggerProviderExportError(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	want := errors.New("export failed")
	exporter := &testLogExporter{err: want}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(
		exporter, sdklog.WithExportInterval(time.Hour))))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.Nil(t, provider.Shutdown(ctx))
	})
	provider.Logger("default").Emit(ctx, log.Record{})
	assert.ErrorIs(t, provider.ForceFlush(ctx), want)

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	assert.ErrorIs(t, provider.ForceFlush(canceled), context.Canceled)
}

func TestEmitAccessLogInvalidUTF8(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	exporter := &testLogExporter{
		records:    make(chan sdklog.Record, 16),
		batchSizes: make(chan int, 16),
	}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(
		exporter, sdklog.WithExportInterval(time.Hour))))
	previous := otel.GetLoggerProvider()
	otel.SetLoggerProvider(provider)
	t.Cleanup(func() {
		otel.SetLoggerProvider(previous)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.Nil(t, provider.Shutdown(ctx))
	})

	newAccessLog := func(path, userAgent string) *corev1.AccessLog {
		return &corev1.AccessLog{
			Metadata: &metav1.LogMetadata{
				CreatedAt: pbutils.Timestamp(time.Unix(1700000000, 0)),
			},
			Entry: &corev1.AccessLog_Entry{
				Info: &corev1.AccessLog_Entry_Info{
					Type: &corev1.AccessLog_Entry_Info_Http{
						Http: &corev1.AccessLog_Entry_Info_HTTP{
							Request: &corev1.AccessLog_Entry_Info_HTTP_Request{
								Path:      path,
								UserAgent: userAgent,
							},
						},
					},
				},
			},
		}
	}

	for _, tc := range []struct {
		in   *corev1.AccessLog
		want *corev1.AccessLog
	}{
		{newAccessLog("/admin", "agent"), newAccessLog("/admin", "agent")},
		{newAccessLog("/admin/\xff", "a\xffb"), newAccessLog("/admin/\uFFFD", "a\uFFFDb")},
	} {
		original := pbutils.Clone(tc.in)

		EmitAccessLog(tc.in)
		require.Nil(t, provider.ForceFlush(ctx))
		require.Len(t, exporter.records, 1)

		record := <-exporter.records
		assert.NotEmpty(t, record.Body().AsMap())
		assert.Equal(t, convertValue(pbutils.MustConvertToMap(tc.want)), record.Body())
		assert.True(t, pbutils.IsEqual(original, tc.in))
	}
}

func TestEmitAccessLogRandom(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	exporter := &testLogExporter{
		records:    make(chan sdklog.Record, 16),
		batchSizes: make(chan int, 16),
	}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(
		exporter, sdklog.WithExportInterval(time.Hour))))
	previous := otel.GetLoggerProvider()
	otel.SetLoggerProvider(provider)
	t.Cleanup(func() {
		otel.SetLoggerProvider(previous)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.Nil(t, provider.Shutdown(ctx))
	})

	r := &testRandom{Rand: rand.New(rand.NewPCG(20261127, 2)), maxDepth: 10}
	var nInvalid int

	for i := range 1000 {
		r.invalid = i%4 == 3
		in := newTestAccessLog(r)
		want := getLegacyAccessLogBody(in)
		if _, err := pbutils.ConvertToMap(in); err != nil {
			nInvalid++
		}

		EmitAccessLog(in)
		require.Nil(t, provider.ForceFlush(ctx))
		require.Len(t, exporter.records, 1)
		<-exporter.batchSizes

		record := <-exporter.records
		assert.Equal(t, want, record.Body())
		assert.Equal(t, in.Metadata.CreatedAt.AsTime(), record.Timestamp())
		assert.Equal(t, log.SeverityInfo, record.Severity())
		assert.Equal(t, want, getLegacyAccessLogBody(in))
	}

	assert.Greater(t, nInvalid, 50)
}

func TestEmitAccessLogUnconvertible(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	exporter := &testLogExporter{
		records:    make(chan sdklog.Record, 16),
		batchSizes: make(chan int, 16),
	}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(
		exporter, sdklog.WithExportInterval(time.Hour))))
	previous := otel.GetLoggerProvider()
	otel.SetLoggerProvider(provider)
	t.Cleanup(func() {
		otel.SetLoggerProvider(previous)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.Nil(t, provider.Shutdown(ctx))
	})

	in := &corev1.AccessLog{
		Metadata: &metav1.LogMetadata{
			CreatedAt: pbutils.Timestamp(time.Unix(1700000000, 0)),
		},
		Entry: &corev1.AccessLog_Entry{
			Info: &corev1.AccessLog_Entry_Info{
				Type: &corev1.AccessLog_Entry_Info_Http{
					Http: &corev1.AccessLog_Entry_Info_HTTP{
						Request: &corev1.AccessLog_Entry_Info_HTTP_Request{
							Path: "/admin/\xff",
							BodyMap: &structpb.Struct{Fields: map[string]*structpb.Value{
								"a": structpb.NewNumberValue(math.NaN()),
							}},
						},
					},
				},
			},
		},
	}
	original := pbutils.Clone(in)

	EmitAccessLog(in)
	require.Nil(t, provider.ForceFlush(ctx))
	require.Len(t, exporter.records, 1)

	record := <-exporter.records
	assert.Equal(t, attribute.MapValue(), record.Body())
	assert.Equal(t, time.Unix(1700000000, 0).UTC(), record.Timestamp())
	assert.True(t, pbutils.IsEqual(original, in))
}

func newTestHTTPAccessLog(bodyMap *structpb.Struct) *corev1.AccessLog {
	ref := func(kind, name string) *metav1.ObjectReference {
		return &metav1.ObjectReference{
			ApiVersion: "core/v1",
			Kind:       kind,
			Name:       name,
			Uid:        "8b1f3c2a-0001-4d6e-9f10-000000000001",
		}
	}

	return &corev1.AccessLog{
		ApiVersion: "core/v1",
		Kind:       "AccessLog",
		Metadata: &metav1.LogMetadata{
			Id:        "abc-123-def",
			CreatedAt: pbutils.Now(),
			ActorRef:  ref("Session", "session"),
			TargetRef: ref("Service", "svc"),
		},
		Entry: &corev1.AccessLog_Entry{
			Common: &corev1.AccessLog_Entry_Common{
				StartedAt: pbutils.Now(),
				EndedAt:   pbutils.Now(),
				Status:    corev1.AccessLog_Entry_Common_ALLOWED,
				Mode:      corev1.Service_Spec_HTTP,
				Reason: &corev1.AccessLog_Entry_Common_Reason{
					Type: corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH,
				},
				UserRef:      ref("User", "alice"),
				SessionRef:   ref("Session", "session"),
				DeviceRef:    ref("Device", "device"),
				ServiceRef:   ref("Service", "svc"),
				NamespaceRef: ref("Namespace", "default"),
				RegionRef:    ref("Region", "default"),
				Network: &corev1.AccessLog_Entry_Common_Network{
					Downstream: &corev1.AccessLog_Entry_Common_Network_Endpoint{
						Ip:   "100.64.0.12",
						Port: 40000,
					},
				},
			},
			Info: &corev1.AccessLog_Entry_Info{
				Type: &corev1.AccessLog_Entry_Info_Http{
					Http: &corev1.AccessLog_Entry_Info_HTTP{
						Request: &corev1.AccessLog_Entry_Info_HTTP_Request{
							Path:      "/api/v1/items",
							Method:    "GET",
							Uri:       "/api/v1/items?limit=20",
							UserAgent: "Mozilla/5.0 (X11; Linux x86_64)",
							Scheme:    "https",
							BodyMap:   bodyMap,
						},
						Response: &corev1.AccessLog_Entry_Info_HTTP_Response{
							Code:        200,
							BodyBytes:   1234,
							ContentType: "application/json",
						},
						HttpVersion: corev1.AccessLog_Entry_Info_HTTP_HTTP11,
					},
				},
			},
		},
	}
}

func newTestBodyMap(t testing.TB) *structpb.Struct {
	items := make([]any, 0, 8)
	for i := range 8 {
		items = append(items, map[string]any{
			"id":      float64(i),
			"name":    "item",
			"enabled": i%2 == 0,
			"tags":    []any{"a", "b"},
		})
	}

	ret, err := structpb.NewStruct(map[string]any{
		"model":  "model",
		"stream": false,
		"items":  items,
	})
	require.NoError(t, err)

	return ret
}

func TestEmitAccessLogAllocs(t *testing.T) {
	previous := otel.GetLoggerProvider()
	otel.SetLoggerProvider(noop.NewLoggerProvider())
	t.Cleanup(func() {
		otel.SetLoggerProvider(previous)
	})

	for _, in := range []*corev1.AccessLog{
		newTestHTTPAccessLog(nil),
		newTestHTTPAccessLog(newTestBodyMap(t)),
	} {
		emitAllocs := testing.AllocsPerRun(100, func() {
			EmitAccessLog(in)
		})
		convertAllocs := testing.AllocsPerRun(100, func() {
			convertProtoMessage(in)
		})
		assert.LessOrEqual(t, emitAllocs, convertAllocs+1)
	}
}

func BenchmarkEmitAccessLog(b *testing.B) {
	for _, tc := range []struct {
		name string
		in   *corev1.AccessLog
	}{
		{"HTTP", newTestHTTPAccessLog(nil)},
		{"HTTPBodyMap", newTestHTTPAccessLog(newTestBodyMap(b))},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				EmitAccessLog(tc.in)
			}
		})
	}
}
