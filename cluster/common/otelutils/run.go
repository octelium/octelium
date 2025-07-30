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

	"github.com/octelium/octelium/cluster/common/components/otelcore"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/global"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type otelErrorHandler struct {
}

func (h *otelErrorHandler) Handle(err error) {
	switch {
	case grpcerr.IsUnavailable(err):
		return
	}
	zap.L().Debug("OTEL error", zap.Error(err))
}

func RunOTEL(ctx context.Context) error {

	logProvider, err := CreateLoggerProvider(ctx, "")
	if err != nil {
		return err
	}
	metricProvider, err := CreateMetricsProvider(ctx, "")
	if err != nil {
		return err
	}
	global.SetLoggerProvider(logProvider)
	otel.SetMeterProvider(metricProvider)

	zapLogger := otelcore.NewOTELCore(GetLogger())

	otel.SetErrorHandler(&otelErrorHandler{})

	zap.ReplaceGlobals(zap.New(zapcore.NewTee(zap.L().Core(), zapLogger)))

	return nil
}
