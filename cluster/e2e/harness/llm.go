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

package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

type LLMSrv struct {
	Port int

	lis net.Listener
	srv *http.Server

	mu                 sync.Mutex
	reqCount           int
	requestCountByPath map[string]int
	lastBodyByPath     map[string]map[string]any
	lastPath           string
	lastModel          string
	lastAuth           string
	lastHeader         http.Header
	lastBody           map[string]any
	completionContent  string
}

func (s *LLMSrv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	reqMap := map[string]any{}
	json.Unmarshal(body, &reqMap)

	model, _ := reqMap["model"].(string)
	isStream, _ := reqMap["stream"].(bool)

	s.mu.Lock()
	s.reqCount++
	if s.requestCountByPath == nil {
		s.requestCountByPath = map[string]int{}
	}
	if s.lastBodyByPath == nil {
		s.lastBodyByPath = map[string]map[string]any{}
	}
	s.requestCountByPath[r.URL.Path]++
	s.lastBodyByPath[r.URL.Path] = reqMap
	s.lastPath = r.URL.Path
	s.lastModel = model
	s.lastAuth = r.Header.Get("Authorization")
	s.lastHeader = r.Header.Clone()
	s.lastBody = reqMap
	content := s.completionContent
	s.mu.Unlock()
	if content == "" {
		content = "octelium"
	}

	zap.L().Debug("New LLMSrv req", zap.String("path", r.URL.Path),
		zap.String("model", model), zap.Bool("stream", isStream))

	if r.Method == http.MethodGet {
		if strings.Contains(r.URL.Path, "/models/") {
			s.writeJSON(w, map[string]any{
				"id": modelFromPath(r.URL.Path), "object": "model",
				"created": 0, "owned_by": "octelium",
			})
			return
		}
		s.writeJSON(w, map[string]any{
			"object": "list",
			"data": []any{
				map[string]any{
					"id": "e2e", "object": "model", "created": 0, "owned_by": "octelium",
				},
			},
		})
		return
	}

	if r.URL.Path == "/embeddings" || r.URL.Path == "/v1/embeddings" {
		s.serveOpenAIEmbeddings(w, reqMap)
		return
	}

	if strings.HasSuffix(r.URL.Path, ":embedContent") ||
		strings.HasSuffix(r.URL.Path, ":batchEmbedContents") {
		s.serveGeminiEmbeddings(w, r.URL.Path, reqMap)
		return
	}

	if strings.HasSuffix(r.URL.Path, ":countTokens") ||
		r.URL.Path == "/v1/messages/count_tokens" {
		s.writeJSON(w, map[string]any{"input_tokens": 10, "totalTokens": 10})
		return
	}

	if isStream {
		s.serveStream(w, model)
		return
	}

	if r.URL.Path == "/v1/messages" || strings.HasSuffix(r.URL.Path, "/invoke") {
		s.writeJSON(w, map[string]any{
			"id": "msg-e2e", "type": "message", "role": "assistant",
			"model":       model,
			"content":     []any{map[string]any{"type": "text", "text": content}},
			"stop_reason": "end_turn",
			"usage":       map[string]any{"input_tokens": 10, "output_tokens": 5},
		})
		return
	}

	if strings.HasSuffix(r.URL.Path, ":generateContent") {
		s.writeJSON(w, map[string]any{
			"candidates": []any{map[string]any{
				"content": map[string]any{"role": "model", "parts": []any{
					map[string]any{"text": content},
				}},
				"finishReason": "STOP",
			}},
			"usageMetadata": map[string]any{
				"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15,
			},
		})
		return
	}

	if strings.HasSuffix(r.URL.Path, "/converse") {
		s.writeJSON(w, map[string]any{
			"output": map[string]any{"message": map[string]any{
				"role": "assistant", "content": []any{map[string]any{"text": content}},
			}},
			"stopReason": "end_turn",
			"usage":      map[string]any{"inputTokens": 10, "outputTokens": 5, "totalTokens": 15},
		})
		return
	}

	if r.URL.Path == "/v1/responses" {
		s.writeJSON(w, map[string]any{
			"id": "resp-e2e", "object": "response", "status": "completed", "model": model,
			"output": []any{map[string]any{
				"type": "message", "role": "assistant", "status": "completed",
				"content": []any{map[string]any{"type": "output_text", "text": content}},
			}},
			"usage": map[string]any{"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
		})
		return
	}

	if r.URL.Path == "/v1/moderations" {
		s.writeJSON(w, map[string]any{
			"id": "modr-e2e", "model": model,
			"results": []any{map[string]any{"flagged": false}},
		})
		return
	}

	s.writeJSON(w, map[string]any{
		"id":      "chatcmpl-e2e",
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []any{
			map[string]any{
				"index":         0,
				"finish_reason": "stop",
				"message": map[string]any{
					"role":    "assistant",
					"content": content,
				},
			},
		},
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 5,
			"total_tokens":      15,
		},
	})
}

func modelFromPath(path string) string {
	ret := path[strings.LastIndex(path, "/")+1:]
	if idx := strings.IndexByte(ret, ':'); idx >= 0 {
		ret = ret[:idx]
	}
	return ret
}

func embeddingFor(arg string) []float64 {
	arg = strings.ToLower(arg)
	switch {
	case strings.Contains(arg, "invoice"), strings.Contains(arg, "billing"):
		return []float64{1, 0, 0, 0}
	case strings.Contains(arg, "deadlock"), strings.Contains(arg, "program"):
		return []float64{0, 1, 0, 0}
	case strings.Contains(arg, "octelium"), strings.Contains(arg, "zero trust"):
		return []float64{0, 0, 1, 0}
	default:
		return []float64{0, 0, 0, 1}
	}
}

func embeddingInputs(arg any) []string {
	switch cur := arg.(type) {
	case string:
		return []string{cur}
	case []any:
		ret := make([]string, 0, len(cur))
		for _, item := range cur {
			if val, ok := item.(string); ok {
				ret = append(ret, val)
			}
		}
		return ret
	default:
		body, _ := json.Marshal(cur)
		return []string{string(body)}
	}
}

func (s *LLMSrv) serveOpenAIEmbeddings(w http.ResponseWriter, req map[string]any) {
	inputs := embeddingInputs(req["input"])
	data := make([]any, 0, len(inputs))
	for i, input := range inputs {
		data = append(data, map[string]any{
			"object": "embedding", "index": i, "embedding": embeddingFor(input),
		})
	}
	s.writeJSON(w, map[string]any{
		"object": "list", "data": data, "model": req["model"],
		"usage": map[string]any{"prompt_tokens": len(inputs), "total_tokens": len(inputs)},
	})
}

func (s *LLMSrv) serveGeminiEmbeddings(w http.ResponseWriter,
	path string, req map[string]any) {
	body, _ := json.Marshal(req)
	vec := embeddingFor(string(body))
	if strings.HasSuffix(path, ":batchEmbedContents") {
		s.writeJSON(w, map[string]any{
			"embeddings": []any{map[string]any{"values": vec}},
		})
		return
	}
	s.writeJSON(w, map[string]any{"embedding": map[string]any{"values": vec}})
}

func (s *LLMSrv) writeJSON(w http.ResponseWriter, arg any) {
	body, err := json.Marshal(arg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (s *LLMSrv) serveStream(w http.ResponseWriter, model string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)

	writeEvent := func(arg any) {
		body, err := json.Marshal(arg)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", body)
		if flusher != nil {
			flusher.Flush()
		}
	}

	for i := range 16 {
		writeEvent(map[string]any{
			"id":      "chatcmpl-e2e",
			"object":  "chat.completion.chunk",
			"created": time.Now().Unix(),
			"model":   model,
			"choices": []any{
				map[string]any{
					"index": 0,
					"delta": map[string]any{"content": fmt.Sprintf("tok-%d ", i)},
				},
			},
		})
	}

	writeEvent(map[string]any{
		"id":      "chatcmpl-e2e",
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []any{
			map[string]any{
				"index":         0,
				"delta":         map[string]any{},
				"finish_reason": "stop",
			},
		},
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 16,
			"total_tokens":      26,
		},
	})

	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

func (s *LLMSrv) Run(ctx context.Context) error {
	addr := fmt.Sprintf("localhost:%d", s.Port)

	lis, err := listenWithRetry(addr, nil)
	if err != nil {
		return err
	}
	s.lis = lis

	s.srv = &http.Server{Addr: addr, Handler: s}
	go s.srv.Serve(s.lis)

	return WaitPortOpen(s.Port, 30*time.Second)
}

func (s *LLMSrv) Close() {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.lis != nil {
		s.lis.Close()
	}
}

func (s *LLMSrv) LastPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPath
}

func (s *LLMSrv) LastModel() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastModel
}

func (s *LLMSrv) LastAuthorization() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAuth
}

func (s *LLMSrv) ReqCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqCount
}

func (s *LLMSrv) ReqCountPath(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requestCountByPath[path]
}

func (s *LLMSrv) LastHeader(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastHeader.Get(key)
}

func (s *LLMSrv) LastBody() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	body, _ := json.Marshal(s.lastBody)
	ret := map[string]any{}
	json.Unmarshal(body, &ret)
	return ret
}

func (s *LLMSrv) BodyForPath(path string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	body, _ := json.Marshal(s.lastBodyByPath[path])
	ret := map[string]any{}
	json.Unmarshal(body, &ret)
	return ret
}

func (s *LLMSrv) SetCompletionContent(content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.completionContent = content
}

func (h *H) StartLLMUpstream(t *testing.T, srv *LLMSrv) *LLMSrv {
	t.Helper()

	if srv == nil {
		srv = &LLMSrv{}
	}
	if srv.Port == 0 {
		srv.Port = h.Port()
	}

	if err := srv.Run(t.Context()); err != nil {
		t.Fatalf("Could not start the local LLM upstream: %+v", err)
	}

	t.Cleanup(srv.Close)
	return srv
}
