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
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/components/otelcore"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/log"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type testOTELLogger struct {
	log.Logger
	records []log.Record
}

func (l *testOTELLogger) Emit(ctx context.Context, record log.Record) {
	l.records = append(l.records, record)
}

func (l *testOTELLogger) getComponentLogs(t *testing.T) []*corev1.ComponentLog {
	var ret []*corev1.ComponentLog
	for _, record := range l.records {
		res := &corev1.ComponentLog{}
		require.Nil(t, pbutils.UnmarshalJSON([]byte(record.Body().AsString()), res))
		assert.Equal(t, record.SeverityText(), res.Entry.Message)
		assert.NotEmpty(t, res.Metadata.Id)
		res.Metadata.Id = ""
		res.Metadata.CreatedAt = nil
		res.Entry.Time = nil
		ret = append(ret, res)
	}
	return ret
}

func TestNewZapLogger(t *testing.T) {
	levels := []zapcore.Level{zapcore.DebugLevel, zapcore.InfoLevel, zapcore.WarnLevel, zapcore.ErrorLevel}
	usr := &corev1.User{
		Metadata: &metav1.Metadata{Name: "user", Uid: "user-uid"},
		Spec:     &corev1.User_Spec{Type: corev1.User_Spec_HUMAN, Email: "user@example.com"},
	}

	for _, level := range levels {
		t.Run(level.String(), func(t *testing.T) {
			stdCore, stdLogs := observer.New(level)
			oldStdCore, oldStdLogs := observer.New(level)
			stdLogger := zap.New(zapcore.NewSamplerWithOptions(stdCore, time.Second, 100, 100)).
				With(zap.String("uid", "component-uid"))
			oldStdLogger := zap.New(zapcore.NewSamplerWithOptions(oldStdCore, time.Second, 100, 100)).
				With(zap.String("uid", "component-uid"))

			l := &testOTELLogger{}
			oldL := &testOTELLogger{}
			logger := newZapLogger(stdLogger, l)
			oldLogger := zap.New(zapcore.NewTee(oldStdLogger.Core(),
				otelcore.NewOTELCore(oldL, zapcore.DebugLevel)))
			assert.Equal(t, level, logger.Level())
			assert.Equal(t, zapcore.DebugLevel, oldLogger.Level())

			for _, lgr := range []*zap.Logger{logger, oldLogger} {
				child := lgr.With(zap.String("context", "child"))
				for _, entryLevel := range levels {
					lgr.Log(entryLevel, entryLevel.String(), zap.Any("user", usr), zap.Error(errors.New("failed")))
					child.Log(entryLevel, entryLevel.String(), zap.Int("count", 3))
				}
			}

			var want []string
			for _, entryLevel := range levels {
				if entryLevel >= level {
					want = append(want, entryLevel.String(), entryLevel.String())
				}
			}

			var gotStd []string
			for _, entry := range stdLogs.All() {
				gotStd = append(gotStd, entry.Message)
				assert.Equal(t, "component-uid", entry.ContextMap()["uid"])
			}
			assert.Equal(t, want, gotStd)
			require.Equal(t, oldStdLogs.Len(), stdLogs.Len())
			for i, entry := range stdLogs.AllUntimed() {
				assert.Equal(t, oldStdLogs.AllUntimed()[i], entry)
			}

			var got []string
			for _, record := range l.records {
				got = append(got, record.SeverityText())
			}
			assert.Equal(t, want, got)

			require.Len(t, oldL.records, 2*len(levels))
			var oldWant []map[string]any
			for _, res := range oldL.getComponentLogs(t) {
				entryLevel, err := zapcore.ParseLevel(res.Entry.Message)
				require.Nil(t, err)
				if entryLevel >= level {
					oldWant = append(oldWant, pbutils.MustConvertToMap(res))
				}
			}
			var newGot []map[string]any
			for _, res := range l.getComponentLogs(t) {
				newGot = append(newGot, pbutils.MustConvertToMap(res))
			}
			assert.Equal(t, oldWant, newGot)
		})
	}
}

func TestNewZapLoggerComponent(t *testing.T) {
	stdLogger := zap.L()
	t.Cleanup(func() {
		zap.ReplaceGlobals(stdLogger)
	})

	for _, tc := range []struct {
		env  string
		want []string
	}{
		{"OCTELIUM_PRODUCTION", []string{"info", "warn", "error"}},
		{"OCTELIUM_DEV", []string{"debug", "info", "warn", "error"}},
	} {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("OCTELIUM_DEV", "")
			t.Setenv("OCTELIUM_PRODUCTION", "")
			t.Setenv(tc.env, "true")

			l := &testOTELLogger{}
			components.RunComponent(func(ctx context.Context) error {
				logger := newZapLogger(zap.L(), l)
				logger.Debug("debug", zap.Any("user", &corev1.User{}))
				logger.Info("info")
				logger.Warn("warn")
				logger.Error("error")
				return nil
			}, nil)

			var got []string
			for _, record := range l.records {
				got = append(got, record.SeverityText())
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
