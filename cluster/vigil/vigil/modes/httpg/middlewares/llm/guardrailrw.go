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

	if rw.hdrWritten {
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

	rw.Header().Del("Content-Length")
}

func (rw *guardResponseWriter) maxBytes() int {
	ret := maxGuardrailMaxBytes
	for _, active := range rw.actives {
		ret = min(ret, guardrailMaxBytes(active.cfg.GetMaxBytes()))
	}
	return ret
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

	if rw.buf.Len() > rw.maxBytes() {
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
		rw.writeBlocked(rw.overflowedGuardrail())
		return
	}

	body := rw.buf.Bytes()

	var text string
	if rw.isSSE {
		text = extractSSEText(body)
	} else {
		text = extractResponseText(body)
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

func (rw *guardResponseWriter) overflowedGuardrail() *activeGuardrail {
	var ret *activeGuardrail
	for _, active := range rw.actives {
		if ret == nil ||
			guardrailMaxBytes(active.cfg.GetMaxBytes()) <
				guardrailMaxBytes(ret.cfg.GetMaxBytes()) {
			ret = active
		}
	}

	if ret != nil {
		appendPluginRecord(rw.reqCtx, &pluginRecord{
			name:    ret.name(),
			typ:     corev1.AccessLog_Entry_Info_LLM_Plugin_GUARDRAIL,
			outcome: corev1.AccessLog_Entry_Info_LLM_Plugin_BLOCKED,
		})
	}

	return ret
}

func (rw *guardResponseWriter) inspectText(text string) *activeGuardrail {
	for _, active := range rw.actives {
		rec := &pluginRecord{
			name:    active.name(),
			typ:     corev1.AccessLog_Entry_Info_LLM_Plugin_GUARDRAIL,
			outcome: corev1.AccessLog_Entry_Info_LLM_Plugin_NO_MATCH,
		}

		findings := active.set.inspect(text)
		if len(findings) == 0 {
			appendPluginRecord(rw.reqCtx, rec)
			continue
		}

		rec.rules = findingRuleNames(findings)
		rec.matchCount = uint32(len(findings))

		if deniedFinding(findings) == nil {
			rec.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_LOGGED
			appendPluginRecord(rw.reqCtx, rec)
			continue
		}

		rec.outcome = corev1.AccessLog_Entry_Info_LLM_Plugin_BLOCKED
		appendPluginRecord(rw.reqCtx, rec)
		return active
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
	if depth > maxResponseTextDepth || out.Len() > maxGuardrailMaxBytes {
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
		for _, key := range []string{"choices", "delta", "message", "output", "arguments"} {
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
