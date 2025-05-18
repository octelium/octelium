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

package accesslog

import (
	"bufio"
	"net"
	"net/http"

	"github.com/pkg/errors"
)

type capturer interface {
	http.ResponseWriter
	Size() int64
	Status() int
}

func newCaptureResponseWriter(rw http.ResponseWriter) capturer {
	capt := &captureResponseWriter{rw: rw}
	if _, ok := rw.(http.CloseNotifier); !ok {
		return capt
	}
	return &captureResponseWriterWithCloseNotify{capt}
}

type captureResponseWriter struct {
	rw     http.ResponseWriter
	status int
	size   int64
}

type captureResponseWriterWithCloseNotify struct {
	*captureResponseWriter
}

func (r *captureResponseWriterWithCloseNotify) CloseNotify() <-chan bool {
	return r.rw.(http.CloseNotifier).CloseNotify()
}

func (crw *captureResponseWriter) Header() http.Header {
	return crw.rw.Header()
}

func (crw *captureResponseWriter) Write(b []byte) (int, error) {
	if crw.status == 0 {
		crw.status = http.StatusOK
	}
	size, err := crw.rw.Write(b)
	crw.size += int64(size)
	return size, err
}

func (crw *captureResponseWriter) WriteHeader(s int) {
	crw.rw.WriteHeader(s)
	crw.status = s
}

func (crw *captureResponseWriter) Flush() {
	if f, ok := crw.rw.(http.Flusher); ok {
		f.Flush()
	}
}

func (crw *captureResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := crw.rw.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.Errorf("not a hijacker: %T", crw.rw)
}

func (crw *captureResponseWriter) Status() int {
	return crw.status
}

func (crw *captureResponseWriter) Size() int64 {
	return crw.size
}
