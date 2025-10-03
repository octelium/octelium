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
	"os"
	"os/signal"
	"runtime"
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

type initComponentOpts struct {
}

func initComponent(ctx context.Context, opts *initComponentOpts) error {

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

	zap.ReplaceGlobals(stdoutLogger)

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
		zap.String("goVersion", runtime.Version()),
	)

	return nil
}

type RunComponentOpts struct {
}

func RunComponent(runFn func(ctx context.Context) error, o *RunComponentOpts) {
	if runFn == nil {
		zap.L().Fatal("No runFunc")
	}

	ctx, cancelFn := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancelFn()

	if err := initComponent(context.Background(), nil); err != nil {
		zap.L().Fatal("init component err", zap.Error(err))
	}

	err := runFn(ctx)
	if err != nil {
		zap.L().Fatal("main err", zap.Error(err))
	}
}
