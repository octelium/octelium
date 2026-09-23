// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package liboctelium

import (
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestLogCore(t *testing.T) {
	var logs []*mobilev1.Log

	logger := zap.New(newLogCore(mobilev1.Log_INFO, func(log *mobilev1.Log) {
		logs = append(logs, log)
	}))

	logger.Debug("debug msg")
	assert.Equal(t, 0, len(logs))

	logger.Info("info msg", zap.String("domain", "example.com"))
	assert.Equal(t, 1, len(logs))
	assert.Equal(t, mobilev1.Log_INFO, logs[0].Level)
	assert.True(t, logs[0].CreatedAt.IsValid())
	assert.True(t, strings.HasPrefix(logs[0].Message, "info msg"))
	assert.True(t, strings.Contains(logs[0].Message, `"domain": "example.com"`))

	logger.With(zap.String("component", "tunnel")).Warn("warn msg", zap.Int("gen", 2))
	assert.Equal(t, 2, len(logs))
	assert.Equal(t, mobilev1.Log_WARN, logs[1].Level)
	assert.True(t, strings.Contains(logs[1].Message, `"component": "tunnel"`))
	assert.True(t, strings.Contains(logs[1].Message, `"gen": 2`))

	logger.Error("error msg")
	assert.Equal(t, 3, len(logs))
	assert.Equal(t, mobilev1.Log_ERROR, logs[2].Level)
	assert.Equal(t, "error msg", logs[2].Message)

	logger.Info("info msg 2")
	assert.False(t, strings.Contains(logs[3].Message, "component"))

	assert.Nil(t, logger.Sync())
}

func TestLogCoreLevel(t *testing.T) {
	for _, tc := range []struct {
		level    mobilev1.Log_Level
		enabled  []zapcore.Level
		disabled []zapcore.Level
	}{
		{
			level:    mobilev1.Log_LEVEL_UNSPECIFIED,
			enabled:  []zapcore.Level{zapcore.InfoLevel, zapcore.WarnLevel, zapcore.ErrorLevel},
			disabled: []zapcore.Level{zapcore.DebugLevel},
		},
		{
			level:   mobilev1.Log_DEBUG,
			enabled: []zapcore.Level{zapcore.DebugLevel, zapcore.InfoLevel, zapcore.ErrorLevel},
		},
		{
			level:    mobilev1.Log_WARN,
			enabled:  []zapcore.Level{zapcore.WarnLevel, zapcore.ErrorLevel},
			disabled: []zapcore.Level{zapcore.DebugLevel, zapcore.InfoLevel},
		},
		{
			level:    mobilev1.Log_ERROR,
			enabled:  []zapcore.Level{zapcore.ErrorLevel},
			disabled: []zapcore.Level{zapcore.DebugLevel, zapcore.InfoLevel, zapcore.WarnLevel},
		},
	} {
		core := newLogCore(tc.level, func(log *mobilev1.Log) {})
		for _, level := range tc.enabled {
			assert.True(t, core.Enabled(level), "%s %s", tc.level, level)
		}
		for _, level := range tc.disabled {
			assert.False(t, core.Enabled(level), "%s %s", tc.level, level)
		}
	}

	assert.Equal(t, mobilev1.Log_DEBUG, getLogLevel(zapcore.DebugLevel))
	assert.Equal(t, mobilev1.Log_INFO, getLogLevel(zapcore.InfoLevel))
	assert.Equal(t, mobilev1.Log_WARN, getLogLevel(zapcore.WarnLevel))
	assert.Equal(t, mobilev1.Log_ERROR, getLogLevel(zapcore.ErrorLevel))
	assert.Equal(t, mobilev1.Log_ERROR, getLogLevel(zapcore.PanicLevel))
}
