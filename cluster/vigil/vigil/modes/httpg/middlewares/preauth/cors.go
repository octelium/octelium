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

package preauth

import (
	"bufio"
	"net"
	"net/http"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/pkg/errors"
)

type corsResponseWriter struct {
	http.ResponseWriter

	cfg    *corev1.Service_Spec_Config_HTTP_CORS
	origin string
	domain string

	wroteHeader bool
	hijacked    bool
}

func newCORSResponseWriter(w http.ResponseWriter,
	cfg *corev1.Service_Spec_Config_HTTP_CORS, origin, domain string) *corsResponseWriter {
	return &corsResponseWriter{
		ResponseWriter: w,
		cfg:            cfg,
		origin:         origin,
		domain:         domain,
	}
}

func (w *corsResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *corsResponseWriter) commit() {
	if w.wroteHeader || w.hijacked {
		return
	}
	w.wroteHeader = true
	httputils.SetCORSResponseHeaders(w.ResponseWriter.Header(), w.cfg,
		w.origin, w.domain)
}

func (w *corsResponseWriter) WriteHeader(statusCode int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		httputils.SetCORSResponseHeaders(w.ResponseWriter.Header(), w.cfg,
			w.origin, w.domain)
	}

	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *corsResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}

	return w.ResponseWriter.Write(b)
}

func (w *corsResponseWriter) Flush() {
	if !w.wroteHeader && !w.hijacked {
		w.WriteHeader(http.StatusOK)
	}

	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *corsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}

	conn, brw, err := hj.Hijack()
	if err == nil {
		w.hijacked = true
	}

	return conn, brw, err
}

func (w *corsResponseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}

	return http.ErrNotSupported
}
