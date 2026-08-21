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
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

type LLMSrv struct {
	Port int

	lis net.Listener
	srv *http.Server

	mu        sync.Mutex
	reqCount  int
	lastPath  string
	lastModel string
	lastAuth  string
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
	s.lastPath = r.URL.Path
	s.lastModel = model
	s.lastAuth = r.Header.Get("Authorization")
	s.mu.Unlock()

	zap.L().Debug("New LLMSrv req", zap.String("path", r.URL.Path),
		zap.String("model", model), zap.Bool("stream", isStream))

	if r.Method == http.MethodGet {
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

	if isStream {
		s.serveStream(w, model)
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
					"content": "octelium",
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
