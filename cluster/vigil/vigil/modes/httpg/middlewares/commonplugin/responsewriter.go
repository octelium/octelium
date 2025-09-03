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

package commonplugin

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

type ResponseWriter struct {
	w          http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	capturing  bool
}

func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{
		w:          w,
		body:       &bytes.Buffer{},
		statusCode: http.StatusOK,
		capturing:  true,
	}
}

func (rw *ResponseWriter) Write(b []byte) (int, error) {
	if rw.capturing {
		return rw.body.Write(b)
	}
	return rw.w.Write(b)
}

func (rw *ResponseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode

	h := rw.Header()
	if strings.EqualFold(h.Get("Transfer-Encoding"), "chunked") ||
		strings.Contains(h.Get("Content-Type"), "text/event-stream") ||
		strings.HasPrefix(h.Get("Content-Type"), "application/grpc") {
		rw.capturing = false
	}

	if !rw.capturing {
		rw.w.WriteHeader(statusCode)
	}
}

func (rw *ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}

	return hj.Hijack()
}

func (w *ResponseWriter) Flush() {
	if f, ok := w.w.(http.Flusher); ok {
		f.Flush()
	}
}

func (p *ResponseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := p.w.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *ResponseWriter) GetBuffer() *bytes.Buffer {
	return w.body
}

func (w *ResponseWriter) GetStatusCode() int {
	return w.statusCode
}

func (w *ResponseWriter) SetStatusCode(n int) {
	w.statusCode = n
}

func (w *ResponseWriter) Header() http.Header {
	return w.w.Header()
}

func (w *ResponseWriter) Commit() error {
	// w.Header().Del("Content-Encoding")
	if !w.capturing {
		return nil
	}
	w.w.WriteHeader(w.statusCode)
	_, err := w.w.Write(w.body.Bytes())
	return err
}
