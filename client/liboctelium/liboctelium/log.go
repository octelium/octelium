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

	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap/zapcore"
)

type logCore struct {
	zapcore.LevelEnabler
	enc    zapcore.Encoder
	sendFn func(log *mobilev1.Log)
}

func newLogCore(level mobilev1.Log_Level, sendFn func(log *mobilev1.Log)) *logCore {
	return &logCore{
		LevelEnabler: getZapLevel(level),
		enc: zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
			MessageKey:       "msg",
			NameKey:          "logger",
			ConsoleSeparator: " ",
		}),
		sendFn: sendFn,
	}
}

func (c *logCore) With(fields []zapcore.Field) zapcore.Core {
	enc := c.enc.Clone()
	for _, field := range fields {
		field.AddTo(enc)
	}

	return &logCore{
		LevelEnabler: c.LevelEnabler,
		enc:          enc,
		sendFn:       c.sendFn,
	}
}

func (c *logCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}

	return ce
}

func (c *logCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	buf, err := c.enc.EncodeEntry(ent, fields)
	if err != nil {
		return err
	}
	defer buf.Free()

	c.sendFn(&mobilev1.Log{
		Level:     getLogLevel(ent.Level),
		CreatedAt: pbutils.Timestamp(ent.Time),
		Message:   strings.TrimSpace(buf.String()),
	})

	return nil
}

func (c *logCore) Sync() error {
	return nil
}

func getZapLevel(level mobilev1.Log_Level) zapcore.Level {
	switch level {
	case mobilev1.Log_DEBUG:
		return zapcore.DebugLevel
	case mobilev1.Log_WARN:
		return zapcore.WarnLevel
	case mobilev1.Log_ERROR:
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

func getLogLevel(level zapcore.Level) mobilev1.Log_Level {
	switch level {
	case zapcore.DebugLevel:
		return mobilev1.Log_DEBUG
	case zapcore.InfoLevel:
		return mobilev1.Log_INFO
	case zapcore.WarnLevel:
		return mobilev1.Log_WARN
	default:
		return mobilev1.Log_ERROR
	}
}
