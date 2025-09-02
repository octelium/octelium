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

package metrics

/*
import (
	"bufio"
	"net"
	"net/http"
)

type recorder interface {
	http.ResponseWriter
	http.Flusher
	getCode() int
}

func newResponseRecorder(rw http.ResponseWriter) recorder {
	rec := &responseRecorder{
		ResponseWriter: rw,
		statusCode:     http.StatusOK,
	}
	if _, ok := rw.(http.CloseNotifier); !ok {
		return rec
	}
	return &responseRecorderWithCloseNotify{rec}
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

type responseRecorderWithCloseNotify struct {
	*responseRecorder
}

func (r *responseRecorderWithCloseNotify) CloseNotify() <-chan bool {
	return r.ResponseWriter.(http.CloseNotifier).CloseNotify()
}

func (r *responseRecorder) getCode() int {
	return r.statusCode
}

func (r *responseRecorder) WriteHeader(status int) {
	r.ResponseWriter.WriteHeader(status)
	r.statusCode = status
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return r.ResponseWriter.(http.Hijacker).Hijack()
}

func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

*/
