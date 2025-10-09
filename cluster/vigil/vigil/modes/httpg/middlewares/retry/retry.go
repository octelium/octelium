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

package retry

import (
	"bufio"
	"context"
	"maps"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type middleware struct {
	next http.Handler
}

func New(ctx context.Context, next http.Handler) (http.Handler, error) {
	return &middleware{
		next: next,
	}, nil
}

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqCtx := middlewares.GetCtxRequestContext(req.Context())
	svcCfg := reqCtx.ServiceConfig

	if svcCfg == nil || svcCfg.GetHttp() == nil ||
		svcCfg.GetHttp().Retry == nil {
		m.next.ServeHTTP(rw, req)
		return
	}

	retryCfg := svcCfg.GetHttp().Retry

	backOff := backoff.NewExponentialBackOff()

	if val := umetav1.ToDuration(retryCfg.InitialInterval).ToGo(); val > 0 {
		backOff.InitialInterval = val
	}
	if val := umetav1.ToDuration(retryCfg.MaxInterval).ToGo(); val > 0 {
		backOff.MaxInterval = val
	}
	if retryCfg.Multiplier > 0 {
		backOff.Multiplier = float64(retryCfg.Multiplier)
	} else {
		backOff.Multiplier = 1.5
	}

	maxRetries := 12

	if val := retryCfg.MaxRetries; val > 0 {
		maxRetries = int(val)
	}

	var maxElapsedTime time.Duration
	if val := umetav1.ToDuration(retryCfg.MaxElapsedTime).ToGo(); val > 0 {
		maxElapsedTime = val
	} else {
		maxElapsedTime = 10 * time.Second
	}

	ctx := req.Context()

	timer := &defaultTimer{}

	defer timer.Stop()

	startedAt := time.Now()
	backOff.Reset()
	for attempts := 1; ; attempts++ {
		crw := &responseWriter{
			ResponseWriter: rw,
			req:            req,
			cfg:            retryCfg,
			headers:        make(http.Header),
			statusCode:     http.StatusOK,
			maxRetries:     maxRetries,
			attempts:       attempts,
			backOff:        backOff,
			startedAt:      startedAt,
			maxElapsedTime: maxElapsedTime,
		}

		m.next.ServeHTTP(crw, req)

		if !crw.isRetry {
			return
		}
		zap.L().Debug("Retrying request",
			zap.Int("attempt", attempts),
			zap.Duration("duration", crw.nextDuration))
		timer.Start(crw.nextDuration)
		select {
		case <-timer.C():
		case <-ctx.Done():
		}
	}

}

type responseWriter struct {
	http.ResponseWriter
	statusCode     int
	headers        http.Header
	cfg            *corev1.Service_Spec_Config_HTTP_Retry
	isRetry        bool
	isWritten      bool
	attempts       int
	maxRetries     int
	backOff        *backoff.ExponentialBackOff
	startedAt      time.Time
	maxElapsedTime time.Duration
	nextDuration   time.Duration
	req            *http.Request
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode

	if w.isWritten || w.isRetry {
		return
	}

	w.setIsRetry()

	if w.isRetry {
		return
	}

	maps.Copy(w.ResponseWriter.Header(), w.headers)

	w.ResponseWriter.WriteHeader(statusCode)
	w.isWritten = true
}

func (w *responseWriter) Write(buf []byte) (int, error) {

	if w.isRetry {
		return len(buf), nil
	}

	if !w.isWritten {
		w.WriteHeader(w.statusCode)
	}

	return w.ResponseWriter.Write(buf)
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}

	return hj.Hijack()
}

func (w *responseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *responseWriter) Header() http.Header {
	if w.isWritten {
		return w.ResponseWriter.Header()
	}
	return w.headers
}

func (p *responseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := p.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *responseWriter) setIsRetry() {

	cfg := w.cfg

	if w.attempts >= w.maxRetries {
		w.isRetry = false
		return
	}

	if err := context.Cause(w.req.Context()); err != nil {
		w.isRetry = false
		return
	}

	w.nextDuration = w.backOff.NextBackOff()

	if w.nextDuration == backoff.Stop {
		w.isRetry = false
		return
	}

	if time.Since(w.startedAt)+w.nextDuration > w.maxElapsedTime {
		w.isRetry = false
		return
	}

	if cfg.RetryOnServerErrors && w.statusCode >= 500 && w.statusCode < 600 {
		w.isRetry = true
		return
	}

	if len(cfg.StatusCodes) > 0 && slices.Contains(cfg.StatusCodes, int32(w.statusCode)) {
		w.isRetry = true
		return
	}

	switch w.statusCode {
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		w.isRetry = true
		return
	}

	w.isRetry = false
}

type defaultTimer struct {
	timer *time.Timer
}

func (t *defaultTimer) C() <-chan time.Time {
	return t.timer.C
}

func (t *defaultTimer) Start(duration time.Duration) {
	if t.timer == nil {
		t.timer = time.NewTimer(duration)
	} else {
		t.timer.Reset(duration)
	}
}

func (t *defaultTimer) Stop() {
	if t.timer != nil {
		t.timer.Stop()
	}
}
