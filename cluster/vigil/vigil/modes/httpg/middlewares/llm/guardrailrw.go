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
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonguardrail"
	"go.uber.org/zap"
)

type guardResponseWriter struct {
	http.ResponseWriter

	reqCtx  *middlewares.RequestContext
	actives []*activeGuardrail

	mu sync.Mutex

	statusCode int
	hdrWritten bool

	isPassthrough bool
	isResolved    bool
	isSSE         bool
	isEventStream bool
	isOverflowed  bool

	buf bytes.Buffer
}

func newGuardResponseWriter(w http.ResponseWriter, reqCtx *middlewares.RequestContext,
	actives []*activeGuardrail) *guardResponseWriter {
	return &guardResponseWriter{
		ResponseWriter: w,
		reqCtx:         reqCtx,
		actives:        actives,
		statusCode:     http.StatusOK,
	}
}

func (rw *guardResponseWriter) WriteHeader(statusCode int) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if statusCode >= 100 && statusCode < 200 {
		rw.ResponseWriter.WriteHeader(statusCode)
		return
	}

	if rw.hdrWritten || rw.isResolved {
		return
	}
	rw.statusCode = statusCode

	rw.resolve()

	if rw.isPassthrough {
		rw.hdrWritten = true
		rw.ResponseWriter.WriteHeader(statusCode)
	}
}

func (rw *guardResponseWriter) resolve() {
	if rw.isResolved {
		return
	}
	rw.isResolved = true

	if rw.statusCode < 200 || rw.statusCode > 299 {
		rw.isPassthrough = true
		return
	}

	mediaType := strings.TrimSpace(
		strings.Split(rw.Header().Get("Content-Type"), ";")[0])
	rw.isSSE = strings.EqualFold(mediaType, "text/event-stream")
	rw.isEventStream = strings.EqualFold(mediaType, httputils.LLMEventStreamMediaType)

	rw.Header().Del("Content-Length")
}

func (rw *guardResponseWriter) Write(b []byte) (int, error) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if !rw.isResolved {
		rw.resolve()
	}

	if rw.isPassthrough {
		if !rw.hdrWritten {
			rw.hdrWritten = true
			rw.ResponseWriter.WriteHeader(rw.statusCode)
		}
		return rw.ResponseWriter.Write(b)
	}

	if rw.isOverflowed {
		return len(b), nil
	}

	rw.buf.Write(b)

	if rw.buf.Len() > commonguardrail.MaxResponseBytes {
		rw.isOverflowed = true
		rw.buf.Reset()
	}

	return len(b), nil
}

func (rw *guardResponseWriter) Flush() {
	rw.mu.Lock()
	isPassthrough := rw.isPassthrough
	rw.mu.Unlock()

	if !isPassthrough {
		return
	}

	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *guardResponseWriter) finish() {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.isPassthrough {
		if !rw.hdrWritten {
			rw.hdrWritten = true
			rw.ResponseWriter.WriteHeader(rw.statusCode)
		}
		return
	}

	if rw.isOverflowed {
		zap.L().Warn("The LLM response is too large to be inspected by a Guardrail")
		rw.writeBlocked(rw.actives[0])
		return
	}

	body := rw.buf.Bytes()

	text, isValid := rw.responseText(body)
	if !isValid {
		zap.L().Warn("The LLM response could not be decoded by a Guardrail")
		rw.writeBlocked(rw.actives[0])
		return
	}

	if active := rw.inspectText(text); active != nil {
		rw.writeBlocked(active)
		return
	}

	if !rw.hdrWritten {
		rw.hdrWritten = true
		rw.ResponseWriter.WriteHeader(rw.statusCode)
	}
	rw.ResponseWriter.Write(body)
}

func (rw *guardResponseWriter) responseText(body []byte) (string, bool) {
	switch {
	case rw.isSSE:
		return extractSSEText(body), true
	case rw.isEventStream:
		return extractEventStreamText(body)
	default:
		return extractResponseText(body), true
	}
}

func (rw *guardResponseWriter) inspectText(text string) *activeGuardrail {
	for _, active := range rw.actives {
		findings, err := active.set.Inspect(text)
		if err != nil {
			zap.L().Warn("The LLM Guardrail could not inspect the response",
				zap.String("plugin", active.name()), zap.Error(err))
			return active
		}

		if commonguardrail.DeniedFinding(findings) != nil {
			return active
		}
	}

	return nil
}

func (rw *guardResponseWriter) writeBlocked(active *activeGuardrail) {
	if rw.hdrWritten {
		zap.L().Warn("An LLM Guardrail matched a response that was already committed")
		return
	}

	rw.hdrWritten = true

	var cfg *corev1.Service_Spec_Config_LLM_Plugin_Guardrail
	if active != nil {
		cfg = active.cfg
	}

	hdr := rw.Header()
	hdr.Del("Content-Length")
	hdr.Del("Transfer-Encoding")

	WriteError(rw.ResponseWriter, &WriteErrorOpts{
		Protocol:   rw.reqCtx.LLM.GetProtocol(),
		HTTPStatus: http.StatusForbidden,
		Type:       ErrTypePermission,
		Code:       ErrCodeGuardrail,
		Message:    guardrailDenyMessage(cfg),
	})
}

func extractSSEText(body []byte) string {
	var out strings.Builder

	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}

		data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(data) == 0 || httputils.IsLLMStreamDone(data) {
			continue
		}

		if text := extractResponseText(data); text != "" {
			out.WriteString(text)
		}
	}

	return out.String()
}

func extractEventStreamText(body []byte) (string, bool) {
	var out strings.Builder

	for len(body) > 0 {
		payload, n := httputils.NextLLMEventStreamMessage(body)
		if n <= 0 {
			return out.String(), false
		}
		body = body[n:]

		if len(payload) == 0 {
			continue
		}

		out.WriteString(extractResponseText(payload))

		if out.Len() > commonguardrail.MaxResponseBytes {
			break
		}
	}

	return out.String(), true
}

func extractResponseText(body []byte) string {
	var val any
	if err := json.Unmarshal(body, &val); err != nil {
		return ""
	}

	var out strings.Builder
	walkResponseText(val, 0, &out)
	return out.String()
}

const maxResponseTextDepth = 24

func walkResponseText(val any, depth int, out *strings.Builder) {
	if depth > maxResponseTextDepth || out.Len() > commonguardrail.MaxResponseBytes {
		return
	}

	switch cur := val.(type) {
	case map[string]any:
		for _, key := range []string{"text", "content", "output_text", "reasoning", "refusal"} {
			switch arg := cur[key].(type) {
			case string:
				out.WriteString(arg)
			case map[string]any, []any:
				walkResponseText(arg, depth+1, out)
			}
		}
		for _, key := range []string{"choices", "delta", "message", "output", "arguments",
			"candidates", "parts", "functionCall", "args"} {
			if arg, ok := cur[key]; ok {
				walkResponseText(arg, depth+1, out)
			}
		}
	case []any:
		for _, arg := range cur {
			walkResponseText(arg, depth+1, out)
		}
	}
}
