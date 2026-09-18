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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonguardrail"
	"go.uber.org/zap"
)

const (
	defaultMaxTransStreamEventBytes = 256 * 1024
	maxTransStreamEventBytes        = 4 * 1024 * 1024

	maxTransUpstreamErrorLen = 1024
)

type transResponseWriter struct {
	http.ResponseWriter

	ctx    context.Context
	reqCtx *middlewares.RequestContext
	plan   *transPlan

	mu sync.Mutex

	statusCode int

	isResolved    bool
	isStream      bool
	isEventStream bool
	isError       bool
	isFailed      bool
	isOverflowed  bool

	buf bytes.Buffer

	lineBuf  []byte
	maxEvent int

	isFinished bool

	dec transStreamDecoder
	enc transStreamEncoder

	continuation *transContinuation

	obs transObserver
}

func newTransResponseWriter(ctx context.Context, w http.ResponseWriter,
	reqCtx *middlewares.RequestContext, plan *transPlan) *transResponseWriter {

	return &transResponseWriter{
		ResponseWriter: w,
		ctx:            ctx,
		reqCtx:         reqCtx,
		plan:           plan,
		statusCode:     http.StatusOK,
		maxEvent:       getMaxTransStreamEventBytes(reqCtx),
	}
}

func getMaxTransStreamEventBytes(reqCtx *middlewares.RequestContext) int {
	configured := reqCtx.ServiceConfig.GetLlm().GetLimits().GetMaxStreamEventBytes()
	if configured == 0 || int(configured) > maxTransStreamEventBytes {
		return defaultMaxTransStreamEventBytes
	}

	return int(configured)
}

func (rw *transResponseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func (rw *transResponseWriter) WriteHeader(statusCode int) {
	if statusCode >= 100 && statusCode < 200 {
		rw.ResponseWriter.WriteHeader(statusCode)
		return
	}

	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.isResolved {
		return
	}

	rw.statusCode = statusCode
	rw.resolve()
}

func (rw *transResponseWriter) resolve() {
	if rw.isResolved {
		return
	}
	rw.isResolved = true

	hdr := rw.Header()
	hdr.Del("Content-Length")

	if rw.statusCode < 200 || rw.statusCode > 299 {
		rw.isError = true
		return
	}

	mediaType := strings.TrimSpace(strings.Split(hdr.Get("Content-Type"), ";")[0])

	switch {
	case strings.EqualFold(mediaType, transSSEMediaType):
	case strings.EqualFold(mediaType, transEventStreamMediaType):
		rw.isEventStream = true
	default:
		return
	}

	rw.isStream = true
	rw.dec = rw.plan.to.newStreamDecoder()
	rw.enc = rw.plan.from.newStreamEncoder(&transEncodeOpts{
		model:       rw.plan.model,
		streamUsage: rw.plan.streamUsage,
	})

	hdr.Set("Content-Type", rw.plan.from.streamMediaType())
	hdr.Del("Content-Encoding")

	rw.ResponseWriter.WriteHeader(rw.statusCode)
}

func (rw *transResponseWriter) Write(b []byte) (int, error) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if !rw.isResolved {
		rw.resolve()
	}

	if rw.isStream {
		rw.writeStream(b)
		return len(b), nil
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

func (rw *transResponseWriter) Flush() {
	rw.mu.Lock()
	isStream := rw.isStream
	rw.mu.Unlock()

	if !isStream {
		return
	}

	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *transResponseWriter) writeStream(b []byte) {
	if rw.isFailed {
		return
	}

	rw.lineBuf = append(rw.lineBuf, b...)

	if rw.isEventStream {
		rw.writeEventStream()
		return
	}

	for {
		idx, sep := indexTransSSEDelimiter(rw.lineBuf)
		if idx == -1 {
			break
		}

		event := rw.lineBuf[:idx]
		rw.lineBuf = rw.lineBuf[idx+sep:]

		if idx > rw.maxEvent {
			rw.failStream(transInvalidResponse(
				"the inference upstream sent an event that is too large"))
			return
		}

		data := httputils.GetSSEEventData(event)
		if len(data) == 0 {
			continue
		}

		if !rw.writeStreamEvent(httputils.GetSSEEventName(event), data) {
			return
		}
	}

	if len(rw.lineBuf) > rw.maxEvent {
		rw.failStream(transInvalidResponse(
			"the inference upstream sent an event that is too large"))
	}
}

func (rw *transResponseWriter) writeEventStream() {
	for {
		eventType, payload, n := httputils.NextLLMEventStreamEvent(rw.lineBuf)
		if n == 0 {
			break
		}
		if n < 0 {
			rw.failStream(transInvalidResponse(
				"the inference upstream sent a malformed event stream"))
			return
		}

		rw.lineBuf = rw.lineBuf[n:]

		if len(payload) == 0 {
			continue
		}

		if !rw.writeStreamEvent(eventType, payload) {
			return
		}
	}

	if len(rw.lineBuf) > rw.maxEvent {
		rw.failStream(transInvalidResponse(
			"the inference upstream sent an event that is too large"))
	}
}

func (rw *transResponseWriter) writeStreamEvent(eventType string, data []byte) bool {
	rw.obs.observe(data)

	evs, err := rw.dec.decode(eventType, data)
	if err != nil {
		rw.failStream(err)
		return false
	}

	rw.storeEvents(evs)

	return rw.encodeEvents(evs)
}

func (rw *transResponseWriter) encodeEvents(evs []*transEvent) bool {
	for _, ev := range evs {
		out, err := rw.enc.encode(ev)
		if err != nil {
			rw.failStream(err)
			return false
		}
		if len(out) == 0 {
			continue
		}
		rw.ResponseWriter.Write(out)
	}

	if len(evs) > 0 {
		if f, ok := rw.ResponseWriter.(http.Flusher); ok {
			f.Flush()
		}
	}

	return true
}

func (rw *transResponseWriter) failStream(err error) {
	if rw.isFailed {
		return
	}
	rw.isFailed = true
	rw.lineBuf = nil

	cur := toTransError(err)

	zap.L().Warn("Could not translate the LLM upstream stream",
		zap.String("message", cur.message))

	if out := rw.enc.encodeError(cur.text()); len(out) > 0 {
		rw.ResponseWriter.Write(out)
	}

	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *transResponseWriter) finish() {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.isFinished {
		return
	}
	rw.isFinished = true

	if !rw.isResolved {
		rw.resolve()
	}

	defer rw.obs.apply(rw.reqCtx)

	switch {
	case rw.isStream:
		rw.finishStream()
	case rw.isError:
		rw.finishError()
	default:
		rw.finishBody()
	}
}

func (rw *transResponseWriter) finishStream() {
	if rw.isFailed {
		return
	}

	rw.encodeEvents(rw.dec.finish())
}

func (rw *transResponseWriter) finishError() {
	cur := &transError{
		status: rw.statusCode,
		message: fmt.Sprintf("the inference upstream returned a %d status code",
			rw.statusCode),
	}
	if message := parseTransUpstreamError(rw.buf.Bytes()); message != "" {
		cur.message = fmt.Sprintf("the inference upstream returned an error: %s", message)
	}

	hdr := rw.Header()
	hdr.Del("Content-Length")
	hdr.Del("Content-Encoding")

	WriteError(rw.ResponseWriter, &WriteErrorOpts{
		Protocol:   rw.plan.fromProtocol,
		HTTPStatus: rw.statusCode,
		Type:       transErrorType(rw.statusCode),
		Code:       ErrCodeTranslation,
		Message:    cur.text(),
	})
}

func (rw *transResponseWriter) finishBody() {
	body, err := rw.translateBody()
	if err != nil {
		cur := toTransError(err)
		zap.L().Warn("Could not translate the LLM upstream response",
			zap.String("message", cur.message))

		rw.Header().Del("Content-Length")
		rw.Header().Del("Content-Encoding")

		WriteError(rw.ResponseWriter, &WriteErrorOpts{
			Protocol:   rw.plan.fromProtocol,
			HTTPStatus: cur.status,
			Type:       transErrorType(cur.status),
			Code:       ErrCodeTranslation,
			Message:    cur.text(),
		})
		return
	}

	hdr := rw.Header()
	hdr.Set("Content-Type", "application/json")
	hdr.Del("Content-Encoding")
	hdr.Set("Content-Length", strconv.Itoa(len(body)))

	rw.ResponseWriter.WriteHeader(rw.statusCode)
	rw.ResponseWriter.Write(body)
}

func (rw *transResponseWriter) translateBody() ([]byte, error) {
	if rw.isOverflowed {
		return nil, transInvalidResponse(
			"the inference upstream response is too large to be translated")
	}

	body := rw.buf.Bytes()
	if len(body) == 0 {
		return nil, transInvalidResponse(
			"the inference upstream returned an empty response")
	}

	rw.obs.observe(body)

	resp, err := rw.plan.to.decodeResponse(body)
	if err != nil {
		return nil, err
	}

	rw.continuation.store(rw.ctx, rw.reqCtx, rw.plan, resp.blocks)

	return rw.plan.from.encodeResponse(resp, &transEncodeOpts{
		model: rw.plan.model,
	})
}

type transUpstreamError struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`

	Message string `json:"message"`
}

func parseTransUpstreamError(body []byte) string {
	env := &transUpstreamError{}
	if err := json.Unmarshal(body, env); err != nil {
		return ""
	}

	ret := env.Message
	if env.Error != nil && env.Error.Message != "" {
		ret = env.Error.Message
	}

	if ret == "" {
		return ""
	}

	if len(ret) > maxTransUpstreamErrorLen {
		ret = ret[:maxTransUpstreamErrorLen]
	}

	return ret
}

func indexTransSSEDelimiter(arg []byte) (int, int) {
	best, sep := -1, 0

	for _, delim := range [][]byte{
		[]byte("\r\n\r\n"), []byte("\n\n"), []byte("\r\r"),
	} {
		idx := bytes.Index(arg, delim)
		if idx == -1 {
			continue
		}
		if best == -1 || idx < best || (idx == best && len(delim) > sep) {
			best, sep = idx, len(delim)
		}
	}

	return best, sep
}

func (rw *transResponseWriter) storeEvents(evs []*transEvent) {
	var blocks []*transBlock

	for _, ev := range evs {
		if ev.kind != transEventToolCallStart || ev.toolSignature == "" {
			continue
		}
		blocks = append(blocks, &transBlock{
			kind:          transBlockToolCall,
			toolCallID:    ev.toolCallID,
			toolSignature: ev.toolSignature,
		})
	}

	if len(blocks) == 0 {
		return
	}

	rw.continuation.store(rw.ctx, rw.reqCtx, rw.plan, blocks)
}
