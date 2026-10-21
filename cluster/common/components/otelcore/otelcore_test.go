package otelcore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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
