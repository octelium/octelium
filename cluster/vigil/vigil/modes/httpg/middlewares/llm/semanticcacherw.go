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

package llm

import (
	"bytes"
	"net/http"
	"sync"
)

type cacheResponseWriter struct {
	http.ResponseWriter

	mu sync.Mutex

	statusCode  int
	contentType string
	hdrWritten  bool
	isStorable  bool
	maxSize     int

	buf bytes.Buffer
}

func (rw *cacheResponseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func (rw *cacheResponseWriter) WriteHeader(statusCode int) {
	if statusCode >= 100 && statusCode < 200 {
		rw.ResponseWriter.WriteHeader(statusCode)
		return
	}

	rw.mu.Lock()
	if !rw.hdrWritten {
		rw.hdrWritten = true
		rw.statusCode = statusCode
		rw.contentType = rw.Header().Get("Content-Type")
		rw.isStorable = rw.isStorable && statusCode >= 200 && statusCode <= 299
	}
	rw.mu.Unlock()

	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *cacheResponseWriter) Write(b []byte) (int, error) {
	if !rw.isHeaderWritten() {
		rw.WriteHeader(http.StatusOK)
	}

	rw.mu.Lock()
	if rw.isStorable {
		if rw.buf.Len()+len(b) > rw.maxSize {
			rw.isStorable = false
			rw.buf.Reset()
		} else {
			rw.buf.Write(b)
		}
	}
	rw.mu.Unlock()

	return rw.ResponseWriter.Write(b)
}

func (rw *cacheResponseWriter) Flush() {
	if !rw.isHeaderWritten() {
		rw.WriteHeader(http.StatusOK)
	}

	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *cacheResponseWriter) isHeaderWritten() bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.hdrWritten
}

func (rw *cacheResponseWriter) stored() (int, string, []byte) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if !rw.isStorable {
		return 0, "", nil
	}

	return rw.statusCode, rw.contentType, rw.buf.Bytes()
}
