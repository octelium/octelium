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
	"strconv"
	"strings"

	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/pkg/errors"
)

type ResponseWriter struct {
	w           http.ResponseWriter
	body        *bytes.Buffer
	statusCode  int
	reqCtx      *middlewares.RequestContext
	isStreaming bool
	wBodySize   int
}

type NewResponseWriterOpts struct {
	ResponseWriter http.ResponseWriter
	ReqCtx         *middlewares.RequestContext
}

func NewResponseWriter(o *NewResponseWriterOpts) *ResponseWriter {
	if o == nil {
		return &ResponseWriter{
			body:       &bytes.Buffer{},
			statusCode: http.StatusOK,
		}
	}

	return &ResponseWriter{
		w:          o.ResponseWriter,
		body:       &bytes.Buffer{},
		statusCode: http.StatusOK,
		reqCtx:     o.ReqCtx,
	}
}

func (rw *ResponseWriter) Write(b []byte) (int, error) {

	if rw.isStreaming {
		n, err := rw.w.Write(b)
		rw.wBodySize = n
		return n, err
	}

	return rw.body.Write(b)
}

func (rw *ResponseWriter) GetBodySize() int {
	if rw.isStreaming {
		return rw.wBodySize
	}

	return rw.body.Len()
}

func (rw *ResponseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode

	h := rw.Header()
	if strings.EqualFold(h.Get("Transfer-Encoding"), "chunked") ||
		strings.Contains(h.Get("Content-Type"), "text/event-stream") ||
		strings.HasPrefix(h.Get("Content-Type"), "application/grpc") {
		rw.isStreaming = true
	} else if strings.ToLower(h.Get("Connection")) == "upgrade" &&
		strings.ToLower(h.Get("Upgrade")) == "websocket" {
		rw.isStreaming = true
	}

	if rw.isStreaming {
		rw.w.WriteHeader(statusCode)
	}
}

func (rw *ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.w.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}

	rw.isStreaming = true

	return hj.Hijack()
}

func (w *ResponseWriter) Flush() {
	if w.isStreaming {
		if f, ok := w.w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func (p *ResponseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := p.w.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (w *ResponseWriter) GetBody() []byte {
	return w.body.Bytes()
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

func (w *ResponseWriter) SetBody(b []byte) {
	if w.isStreaming {
		return
	}

	rwBody := w.body
	rwBody.Reset()
	rwBody.Write(b)
	w.w.Header().Set("Content-Length", strconv.Itoa(len(b)))
}

func (w *ResponseWriter) ResetBody() {
	if w.isStreaming {
		return
	}

	rwBody := w.body
	rwBody.Reset()
	w.w.Header().Del("Content-Length")
}

func (w *ResponseWriter) Commit() error {
	if w.isStreaming {
		return nil
	}

	w.w.Header().Set("Server", "octelium")
	w.w.WriteHeader(w.statusCode)
	if w.body.Len() > 0 {
		w.w.Header().Set("Content-Length", strconv.Itoa(w.body.Len()))
		_, err := w.w.Write(w.body.Bytes())
		return err
	}

	return nil
}
