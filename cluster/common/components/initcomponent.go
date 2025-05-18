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

package components

import (
	"context"
	"time"

	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	startedAt = time.Now()
	runtimeID = utilrand.GetRandomStringCanonical(6)
}

type InitComponentOpts struct {
}

func InitComponent(ctx context.Context, opts *InitComponentOpts) error {

	if myComponentNS == "" {
		myComponentNS = ComponentNamespaceOctelium
	}

	level := func() zapcore.Level {
		if ldflags.IsDev() {
			return zap.DebugLevel
		}
		return zap.InfoLevel
	}()

	zapCfg := zap.Config{
		Level:       zap.NewAtomicLevelAt(level),
		Development: ldflags.IsDev(),
		Encoding: func() string {
			if ldflags.IsDev() {
				return "console"
			}
			return "json"
		}(),

		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},

		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			FunctionKey:    zapcore.OmitKey,
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.RFC3339NanoTimeEncoder,
			EncodeDuration: zapcore.MillisDurationEncoder,
			EncodeCaller:   zapcore.FullCallerEncoder,
		},
	}

	stdoutLogger, err := zapCfg.Build()
	if err != nil {
		return err
	}

	stdoutLogger = stdoutLogger.With(zap.String("uid", MyComponentUID()))
	// otelLogger := otelzap.New(stdoutLogger, otelzap.WithMinLevel(level))

	// logger := zap.New(zapcore.NewTee(stdoutLogger.Core(), otelLogger.Core()))

	zap.ReplaceGlobals(stdoutLogger)
	// otelzap.ReplaceGlobals(otelLogger)

	zap.L().Info("labels",
		zap.String("componentType", myComponentType),
		zap.String("componentUID", MyComponentUID()),
		zap.String("componentNamespace", MyComponentNamespace()),
		zap.String("gitCommit", ldflags.GitCommit),
		zap.String("gitBranch", ldflags.GitBranch),
		zap.String("gitTag", ldflags.GitTag),
		zap.Bool("productionMode", ldflags.IsProduction()),
		zap.Bool("devMode", ldflags.IsDev()),
		zap.String("region", ldflags.GetRegion()),
		zap.String("startedAt", startedAt.Format(time.RFC3339Nano)),
	)

	return nil
}
