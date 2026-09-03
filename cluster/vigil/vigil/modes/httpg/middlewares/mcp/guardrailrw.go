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

package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"

	"github.com/octelium/octelium/apis/main/corev1"
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
		zap.L().Warn("The MCP response is too large to be inspected by a Guardrail")
		rw.writeBlocked(rw.actives[0])
		return
	}

	body := rw.buf.Bytes()

	var messages [][]byte
	if rw.isSSE {
		messages = extractSSEMessages(body)
	} else {
		messages = [][]byte{body}
	}

	if active := rw.inspect(messages); active != nil {
		rw.writeBlocked(active)
		return
	}

	if !rw.hdrWritten {
		rw.hdrWritten = true
		rw.ResponseWriter.WriteHeader(rw.statusCode)
	}
	rw.ResponseWriter.Write(body)
}

func (rw *guardResponseWriter) inspect(messages [][]byte) *activeGuardrail {
	for _, active := range rw.actives {
		var out strings.Builder
		for _, message := range messages {
			writeResultText(message, active.cfg.GetScopes(), &out)
		}

		text := out.String()
		if text == "" {
			continue
		}

		findings, err := active.set.Inspect(text)
		if err != nil {
			zap.L().Warn("The MCP Guardrail could not inspect the response",
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
		zap.L().Warn("An MCP Guardrail matched a response that was already committed")
		return
	}

	rw.hdrWritten = true

	var cfg *corev1.Service_Spec_Config_MCP_Plugin_Guardrail
	if active != nil {
		cfg = active.cfg
	}

	hdr := rw.Header()
	hdr.Del("Content-Length")
	hdr.Del("Transfer-Encoding")

	WriteError(rw.ResponseWriter, &WriteErrorOpts{
		HTTPStatus: http.StatusForbidden,
		Code:       ErrCodeGuardrail,
		Message:    guardrailDenyMessage(cfg),
		RequestID:  rw.reqCtx.MCP.GetRequestIDRaw(),
	})
}

func extractSSEMessages(body []byte) [][]byte {
	var ret [][]byte

	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}

		data := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(data) == 0 {
			continue
		}

		ret = append(ret, data)
	}

	return ret
}

func writeResultText(body []byte,
	scopes []corev1.Service_Spec_Config_MCP_Plugin_Guardrail_Scope,
	out *strings.Builder) {

	root := make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &root); err != nil {
		return
	}

	raw, ok := root[resultKey]
	if !ok {
		return
	}

	result := make(map[string]json.RawMessage)
	if err := json.Unmarshal(raw, &result); err != nil {
		return
	}

	if hasScope(scopes,
		corev1.Service_Spec_Config_MCP_Plugin_Guardrail_TOOL_RESULTS, true) {
		writeBlockText(result["content"], out)
		writeAllText(result["structuredContent"], out)
	}

	if hasScope(scopes,
		corev1.Service_Spec_Config_MCP_Plugin_Guardrail_RESOURCE_CONTENTS, true) {
		writeBlockText(result["contents"], out)
	}

	if hasScope(scopes,
		corev1.Service_Spec_Config_MCP_Plugin_Guardrail_PROMPT_MESSAGES, true) {
		writeBlockText(result["messages"], out)
	}

	if hasScope(scopes,
		corev1.Service_Spec_Config_MCP_Plugin_Guardrail_TOOL_DEFINITIONS, true) {
		if tools, ok := result["tools"]; ok {
			out.Write(tools)
		}
	}
}

func writeBlockText(raw json.RawMessage, out *strings.Builder) {
	var val any
	if err := json.Unmarshal(raw, &val); err != nil {
		return
	}
	walkBlockText(val, 0, out)
}

func writeAllText(raw json.RawMessage, out *strings.Builder) {
	var val any
	if err := json.Unmarshal(raw, &val); err != nil {
		return
	}
	walkAllText(val, 0, out)
}

func walkBlockText(val any, depth int, out *strings.Builder) {
	if depth > maxDocDepth || out.Len() > commonguardrail.MaxResponseBytes {
		return
	}

	switch cur := val.(type) {
	case map[string]any:
		if arg, ok := cur["text"].(string); ok {
			out.WriteString(arg)
		}
		for _, key := range []string{"resource", "content", "contents"} {
			if arg, ok := cur[key]; ok {
				walkBlockText(arg, depth+1, out)
			}
		}
	case []any:
		for _, arg := range cur {
			walkBlockText(arg, depth+1, out)
		}
	}
}

func walkAllText(val any, depth int, out *strings.Builder) {
	if depth > maxDocDepth || out.Len() > commonguardrail.MaxResponseBytes {
		return
	}

	switch cur := val.(type) {
	case string:
		out.WriteString(cur)
	case map[string]any:
		keys := make([]string, 0, len(cur))
		for key := range cur {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			walkAllText(cur[key], depth+1, out)
		}
	case []any:
		for _, arg := range cur {
			walkAllText(arg, depth+1, out)
		}
	}
}
