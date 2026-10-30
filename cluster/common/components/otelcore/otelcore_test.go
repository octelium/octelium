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

package otelcore

import (
	"context"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/types/known/structpb"
)

type recordingLogger struct {
	log.Logger
	records []log.Record
}

func (l *recordingLogger) Emit(ctx context.Context, record log.Record) {
	l.records = append(l.records, record)
}

func TestCoreWrite(t *testing.T) {
	l := &recordingLogger{}
	c := NewOTELCore(l)
	assert.True(t, c.Enabled(zapcore.InfoLevel))
	assert.NotNil(t, c.Check(zapcore.Entry{Level: zapcore.InfoLevel}, nil))
	assert.Nil(t, c.Sync())
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	assert.Nil(t, c.Write(zapcore.Entry{Level: zapcore.InfoLevel, Message: "message", Time: now, Caller: zapcore.EntryCaller{Function: "function", File: "file.go", Line: 42}}, []zapcore.Field{zap.String("key", "value")}))
	assert.Len(t, l.records, 1)
	record := l.records[0]
	assert.Equal(t, now, record.Timestamp())
	assert.False(t, record.ObservedTimestamp().IsZero())
	assert.Equal(t, "info", record.SeverityText())
	res := &corev1.ComponentLog{}
	assert.Nil(t, pbutils.UnmarshalJSON([]byte(record.Body().AsString()), res))
	assert.Equal(t, "message", res.Entry.Message)
	assert.Equal(t, "function", res.Entry.Function)
	assert.Equal(t, "file.go", res.Entry.File)
	assert.EqualValues(t, 42, res.Entry.Line)
	assert.Equal(t, corev1.ComponentLog_Entry_INFO, res.Entry.Level)
	assert.Equal(t, "value", res.Entry.Fields.Fields["key"].GetStringValue())
	assert.NotEmpty(t, res.Metadata.Id)
}

func TestCoreFields(t *testing.T) {
	c := &otelCore{}
	assert.Nil(t, c.getFields(nil))
	now := time.Date(2025, 1, 1, 0, 0, 0, 123, time.FixedZone("zone", 3600))
	fields := c.getFields([]zapcore.Field{
		zap.String("string", "value"), zap.Error(fmt.Errorf("failed")),
		zap.Binary("binary", []byte("abc")), zap.ByteString("bytes", []byte("abc")),
		zap.Bool("true", true), zap.Bool("false", false), zap.Int64("number", 42), zap.Duration("duration", time.Second),
		zap.Time("time", now), {Key: "utc", Type: zapcore.TimeType, Integer: now.UnixNano()},
		{Key: "full", Type: zapcore.TimeFullType, Interface: now},
		zap.Any("message", &corev1.User{}), zap.Any("unsupported", map[string]string{"key": "value"}),
	})
	assert.Equal(t, "value", fields.Fields["string"].GetStringValue())
	assert.Equal(t, "failed", fields.Fields["error"].GetStringValue())
	assert.Equal(t, "YWJj", fields.Fields["binary"].GetStringValue())
	assert.Equal(t, "YWJj", fields.Fields["bytes"].GetStringValue())
	assert.True(t, fields.Fields["true"].GetBoolValue())
	assert.False(t, fields.Fields["false"].GetBoolValue())
	assert.Equal(t, float64(42), fields.Fields["number"].GetNumberValue())
	assert.Equal(t, float64(time.Second), fields.Fields["duration"].GetNumberValue())
	for _, key := range []string{"time", "utc", "full"} {
		assert.Equal(t, now.UTC().Format(time.RFC3339Nano), fields.Fields[key].GetStringValue())
	}
	assert.Equal(t, "{}", fields.Fields["message"].GetStringValue())
	_, ok := fields.Fields["unsupported"]
	assert.False(t, ok)
	for level, want := range map[zapcore.Level]corev1.ComponentLog_Entry_Level{
		zapcore.DebugLevel:  corev1.ComponentLog_Entry_DEBUG,
		zapcore.InfoLevel:   corev1.ComponentLog_Entry_INFO,
		zapcore.ErrorLevel:  corev1.ComponentLog_Entry_ERROR,
		zapcore.DPanicLevel: corev1.ComponentLog_Entry_PANIC,
		zapcore.FatalLevel:  corev1.ComponentLog_Entry_FATAL,
	} {
		assert.Equal(t, want, c.getLevel(level))
	}
}

func TestCoreWith(t *testing.T) {
	l := &recordingLogger{}
	c := NewOTELCore(l)
	empty := c.With(nil)
	require.NotNil(t, empty)
	assert.NotSame(t, c, empty)

	fields := []zapcore.Field{zap.String("context", "original"), zap.String("value", "base")}
	root := zap.New(c)
	base := root.With(fields...)
	fields[0] = zap.String("context", "changed")
	left := base.With(zap.String("branch", "left"), zap.String("value", "left"))
	right := base.With(zap.String("branch", "right"))
	child := left.With(zap.String("child", "child"), zap.String("value", "child"))

	root.Info("root")
	base.Info("base")
	left.Info("left", zap.String("value", "entry"), zap.String("request", "first"))
	left.Info("left-again")
	right.Info("right")
	child.Info("child")
	zap.New(empty).Info("empty", zap.String("request", "empty"))
	cloned := base.Core().With(nil)
	require.NotNil(t, cloned)
	zap.New(cloned).Info("cloned", zap.String("value", "cloned"))
	base.Info("base-again")

	want := []map[string]any{
		{},
		{"context": "original", "value": "base"},
		{"context": "original", "value": "entry", "branch": "left", "request": "first"},
		{"context": "original", "value": "left", "branch": "left"},
		{"context": "original", "value": "base", "branch": "right"},
		{"context": "original", "value": "child", "branch": "left", "child": "child"},
		{"request": "empty"},
		{"context": "original", "value": "cloned"},
		{"context": "original", "value": "base"},
	}
	require.Len(t, l.records, len(want))
	for i, record := range l.records {
		res := &corev1.ComponentLog{}
		require.Nil(t, pbutils.UnmarshalJSON([]byte(record.Body().AsString()), res))
		assert.Equal(t, want[i], res.Entry.Fields.AsMap(), res.Entry.Message)
	}
}

func TestCoreWithSnapshot(t *testing.T) {
	l := &recordingLogger{}
	data := []byte("abc")
	usr := &corev1.User{Metadata: &metav1.Metadata{Name: "original"}}
	fields := []zapcore.Field{
		zap.String("context", "original"), zap.Binary("binary", data),
		zap.ByteString("bytes", data), zap.Any("user", usr),
	}
	c := NewOTELCore(l).With(fields)
	require.NotNil(t, c)
	fields[0] = zap.String("context", "changed")
	data[0] = 'z'
	usr.Metadata.Name = "changed"

	zap.New(c).Info("snapshot")
	require.Len(t, l.records, 1)
	res := &corev1.ComponentLog{}
	require.Nil(t, pbutils.UnmarshalJSON([]byte(l.records[0].Body().AsString()), res))
	assert.Equal(t, "original", res.Entry.Fields.Fields["context"].GetStringValue())
	assert.Equal(t, "YWJj", res.Entry.Fields.Fields["binary"].GetStringValue())
	assert.Equal(t, "YWJj", res.Entry.Fields.Fields["bytes"].GetStringValue())
	value := &corev1.User{}
	require.Nil(t, pbutils.UnmarshalJSON([]byte(res.Entry.Fields.Fields["user"].GetStringValue()), value))
	assert.Equal(t, "original", value.Metadata.Name)
}

type concurrentRecordingLogger struct {
	log.Logger
	records chan log.Record
}

func (l *concurrentRecordingLogger) Emit(ctx context.Context, record log.Record) {
	l.records <- record
}

func TestCoreWithConcurrent(t *testing.T) {
	const workers = 16
	const requests = 32
	l := &concurrentRecordingLogger{records: make(chan log.Record, workers*requests+1)}
	c := NewOTELCore(l).With([]zapcore.Field{zap.String("context", "shared")})
	require.NotNil(t, c)
	logger := zap.New(c)
	var wg sync.WaitGroup
	for worker := range workers {
		wg.Go(func() {
			child := logger.With(zap.Int("worker", worker))
			for request := range requests {
				child.With(zap.Int("request", request)).Info("request")
			}
		})
	}
	wg.Wait()
	logger.Info("parent")
	close(l.records)

	seen := map[int]bool{}
	count := 0
	for record := range l.records {
		count++
		res := &corev1.ComponentLog{}
		require.Nil(t, pbutils.UnmarshalJSON([]byte(record.Body().AsString()), res))
		fields := res.Entry.Fields.Fields
		assert.Equal(t, "shared", fields["context"].GetStringValue())
		if res.Entry.Message == "parent" {
			assert.Len(t, fields, 1)
			continue
		}
		require.Len(t, fields, 3)
		worker := int(fields["worker"].GetNumberValue())
		request := int(fields["request"].GetNumberValue())
		require.GreaterOrEqual(t, worker, 0)
		require.Less(t, worker, workers)
		require.GreaterOrEqual(t, request, 0)
		require.Less(t, request, requests)
		key := worker*requests + request
		assert.False(t, seen[key])
		seen[key] = true
	}
	assert.Equal(t, workers*requests+1, count)
	assert.Len(t, seen, workers*requests)
}

func TestCoreNumbers(t *testing.T) {
	for _, tc := range []struct {
		field zapcore.Field
		want  float64
	}{
		{zap.Float32("float32", 1.5), 1.5},
		{zap.Float32("negative-float32", -2.5), -2.5},
		{zap.Float32("smallest-float32", math.SmallestNonzeroFloat32), float64(math.SmallestNonzeroFloat32)},
		{zap.Float32("largest-float32", math.MaxFloat32), float64(math.MaxFloat32)},
		{zap.Float32("negative-zero-float32", float32(math.Copysign(0, -1))), math.Copysign(0, -1)},
		{zap.Float64("float64", 1.5), 1.5},
		{zap.Float64("negative-float64", -2.5), -2.5},
		{zap.Float64("zero-float64", 0), 0},
		{zap.Float64("negative-zero-float64", math.Copysign(0, -1)), math.Copysign(0, -1)},
		{zap.Float64("smallest-float64", math.SmallestNonzeroFloat64), math.SmallestNonzeroFloat64},
		{zap.Float64("largest-float64", math.MaxFloat64), math.MaxFloat64},
		{zap.Float64("lowest-float64", -math.MaxFloat64), -math.MaxFloat64},
		{zap.Int("int", -42), -42},
		{zap.Int8("int8", math.MinInt8), math.MinInt8},
		{zap.Int16("int16", math.MinInt16), math.MinInt16},
		{zap.Int32("int32", math.MinInt32), math.MinInt32},
		{zap.Int64("int64", math.MinInt64), float64(math.MinInt64)},
		{zap.Int64("largest-int64", math.MaxInt64), float64(math.MaxInt64)},
		{zap.Uint("uint", 42), 42},
		{zap.Uint8("uint8", math.MaxUint8), math.MaxUint8},
		{zap.Uint16("uint16", math.MaxUint16), math.MaxUint16},
		{zap.Uint32("uint32", math.MaxUint32), math.MaxUint32},
		{zap.Uint64("uint64", uint64(math.MaxInt64)+1), float64(uint64(math.MaxInt64) + 1)},
		{zap.Uint64("largest-uint64", math.MaxUint64), float64(math.MaxUint64)},
		{zap.Uintptr("uintptr", ^uintptr(0)), float64(^uintptr(0))},
		{zap.Duration("duration", -time.Second), float64(-time.Second)},
	} {
		t.Run(tc.field.Key, func(t *testing.T) {
			l := &recordingLogger{}
			c := NewOTELCore(l)
			require.Nil(t, c.Write(zapcore.Entry{Level: zapcore.InfoLevel, Time: time.Now()}, []zapcore.Field{tc.field}))
			require.Len(t, l.records, 1)
			res := &corev1.ComponentLog{}
			require.Nil(t, pbutils.UnmarshalJSON([]byte(l.records[0].Body().AsString()), res))
			value := res.Entry.Fields.Fields[tc.field.Key]
			require.NotNil(t, value)
			assert.IsType(t, &structpb.Value_NumberValue{}, value.Kind)
			assert.Equal(t, tc.want, value.GetNumberValue())
			assert.Equal(t, math.Signbit(tc.want), math.Signbit(value.GetNumberValue()))
		})
	}
}

func TestCoreFloatSpecialValues(t *testing.T) {
	for _, tc := range []struct {
		field zapcore.Field
		want  string
	}{
		{zap.Float32("nan-float32", float32(math.NaN())), "NaN"},
		{zap.Float32("inf-float32", float32(math.Inf(1))), "+Inf"},
		{zap.Float32("negative-inf-float32", float32(math.Inf(-1))), "-Inf"},
		{zap.Float64("nan-float64", math.NaN()), "NaN"},
		{zap.Float64("inf-float64", math.Inf(1)), "+Inf"},
		{zap.Float64("negative-inf-float64", math.Inf(-1)), "-Inf"},
	} {
		t.Run(tc.field.Key, func(t *testing.T) {
			l := &recordingLogger{}
			c := NewOTELCore(l)
			require.Nil(t, c.Write(zapcore.Entry{Level: zapcore.WarnLevel, Time: time.Now(), Message: "special float"},
				[]zapcore.Field{tc.field, zap.String("context", "retained")}))
			child := c.With([]zapcore.Field{tc.field})
			require.NotNil(t, child)
			require.Nil(t, child.Write(zapcore.Entry{Level: zapcore.WarnLevel, Time: time.Now(), Message: "special float context"},
				[]zapcore.Field{zap.String("context", "retained")}))
			require.Len(t, l.records, 2)
			for _, record := range l.records {
				res := &corev1.ComponentLog{}
				require.Nil(t, pbutils.UnmarshalJSON([]byte(record.Body().AsString()), res))
				assert.Equal(t, tc.want, res.Entry.Fields.Fields[tc.field.Key].GetStringValue())
				assert.Equal(t, "retained", res.Entry.Fields.Fields["context"].GetStringValue())
			}
		})
	}
}

func TestCoreLevels(t *testing.T) {
	for _, tc := range []struct {
		level    zapcore.Level
		severity log.Severity
		want     corev1.ComponentLog_Entry_Level
	}{
		{zapcore.DebugLevel, log.SeverityDebug, corev1.ComponentLog_Entry_DEBUG},
		{zapcore.InfoLevel, log.SeverityInfo, corev1.ComponentLog_Entry_INFO},
		{zapcore.WarnLevel, log.SeverityWarn, corev1.ComponentLog_Entry_WARN},
		{zapcore.ErrorLevel, log.SeverityError, corev1.ComponentLog_Entry_ERROR},
		{zapcore.DPanicLevel, log.SeverityFatal1, corev1.ComponentLog_Entry_PANIC},
		{zapcore.PanicLevel, log.SeverityFatal2, corev1.ComponentLog_Entry_PANIC},
		{zapcore.FatalLevel, log.SeverityFatal3, corev1.ComponentLog_Entry_FATAL},
		{zapcore.Level(-2), log.SeverityUndefined, corev1.ComponentLog_Entry_LEVEL_UNSET},
		{zapcore.Level(6), log.SeverityUndefined, corev1.ComponentLog_Entry_LEVEL_UNSET},
	} {
		t.Run(tc.level.String(), func(t *testing.T) {
			l := &recordingLogger{}
			c := NewOTELCore(l)
			require.Nil(t, c.Write(zapcore.Entry{Level: tc.level, Time: time.Now(), Message: "level"}, nil))
			require.Len(t, l.records, 1)
			assert.Equal(t, tc.severity, l.records[0].Severity())
			assert.Equal(t, tc.level.String(), l.records[0].SeverityText())
			res := &corev1.ComponentLog{}
			require.Nil(t, pbutils.UnmarshalJSON([]byte(l.records[0].Body().AsString()), res))
			assert.Equal(t, tc.want, res.Entry.Level)
		})
	}
}
