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

package headers

/*
type responseWriter struct {
	http.ResponseWriter
	headers http.Header
	isSet   bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		headers:        make(http.Header),
	}
}

func (rw *responseWriter) Header() http.Header {
	return rw.headers
}
*/
/*
type responseModifier struct {
	req *http.Request
	rw  http.ResponseWriter

	headersSent bool // whether headers have already been sent
	code        int  // status code, must default to 200

	modifier    func(*http.Response) error // can be nil
	modified    bool                       // whether modifier has already been called for the current request
	modifierErr error                      // returned by modifier call
}

// modifier can be nil.
func newResponseModifier(w http.ResponseWriter, r *http.Request, modifier func(*http.Response) error) http.ResponseWriter {
	rm := &responseModifier{
		req:      r,
		rw:       w,
		modifier: modifier,
		code:     http.StatusOK,
	}

	if _, ok := w.(http.CloseNotifier); ok {
		return responseModifierWithCloseNotify{responseModifier: rm}
	}
	return rm
}

func (r *responseModifier) WriteHeader(code int) {
	if r.headersSent {
		return
	}
	defer func() {
		r.code = code
		r.headersSent = true
	}()

	if r.modifier == nil || r.modified {
		r.rw.WriteHeader(code)
		return
	}

	resp := http.Response{
		Header:  r.rw.Header(),
		Request: r.req,
	}

	if err := r.modifier(&resp); err != nil {
		r.modifierErr = err
		r.rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	r.modified = true
	r.rw.WriteHeader(code)
}

func (r *responseModifier) Header() http.Header {
	return r.rw.Header()
}

func (r *responseModifier) Write(b []byte) (int, error) {
	r.WriteHeader(r.code)
	if r.modifierErr != nil {
		return 0, r.modifierErr
	}

	return r.rw.Write(b)
}

func (r *responseModifier) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.rw.(http.Hijacker); ok {
		return h.Hijack()
	}

	return nil, nil, errors.Errorf("not a hijacker: %T", r.rw)
}

func (r *responseModifier) Flush() {
	if flusher, ok := r.rw.(http.Flusher); ok {
		flusher.Flush()
	}
}

type responseModifierWithCloseNotify struct {
	*responseModifier
}

func (r *responseModifierWithCloseNotify) CloseNotify() <-chan bool {
	return r.responseModifier.rw.(http.CloseNotifier).CloseNotify()
}
*/
