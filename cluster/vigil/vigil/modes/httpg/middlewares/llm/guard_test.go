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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
)

const chatBody = `{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}`

func newService() *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "my-llm.default",
			Uid:  "d3d0d2a2-0000-0000-0000-000000000002",
		},
		Spec: &corev1.Service_Spec{
			Mode:     corev1.Service_Spec_LLM,
			IsPublic: true,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "default"},
		},
	}
}

type guardResult struct {
	isNext  bool
	code    int
	errType string
	errCode string
	body    string
}

func serveGuard(t *testing.T, method, path, body string,
	headers map[string]string, cfg *corev1.Service_Spec_Config_LLM) *guardResult {

	ctx := context.Background()
	ret := &guardResult{}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ret.isNext = true
	})

	mdlwr, err := NewGuard(ctx, next)
	assert.Nil(t, err)

	req := httptest.NewRequest(method, "http://my-llm.example.com"+path,
		strings.NewReader(body))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}

	svcCfg := &corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Llm{Llm: cfg},
	}

	req = req.WithContext(context.WithValue(ctx,
		middlewares.CtxRequestContext,
		&middlewares.RequestContext{
			CreatedAt:     time.Now(),
			Service:       newService(),
			ServiceConfig: svcCfg,
			Body:          []byte(body),
			LLM: httputils.ParseLLMRequest(req,
				cfg.GetProtocol(), []byte(body)),
		}))

	rw := httptest.NewRecorder()
	mdlwr.ServeHTTP(rw, req)

	resp := rw.Result()
	ret.code = resp.StatusCode
	ret.body = rw.Body.String()

	if ret.isNext {
		return ret
	}

	switch cfg.GetProtocol() {
	case corev1.Service_Spec_Config_LLM_ANTHROPIC:
		out := &anthropicErrorResponse{}
		assert.Nil(t, json.Unmarshal(rw.Body.Bytes(), out))
		assert.Equal(t, "error", out.Type)
		if out.Error != nil {
			ret.errType = out.Error.Type
		}
	default:
		out := &openAIErrorResponse{}
		assert.Nil(t, json.Unmarshal(rw.Body.Bytes(), out))
		if out.Error != nil {
			ret.errType = out.Error.Type
			ret.errCode = out.Error.Code
		}
	}

	return ret
}

func TestGuardRoutes(t *testing.T) {
	cfg := &corev1.Service_Spec_Config_LLM{}

	{
		res := serveGuard(t, http.MethodPost, "/v1/chat/completions", chatBody, nil, cfg)
		assert.True(t, res.isNext)
	}

	{
		res := serveGuard(t, http.MethodGet, "/v1/models", "", nil, cfg)
		assert.True(t, res.isNext)
	}

	{
		res := serveGuard(t, http.MethodGet, "/v1/models/gpt-4o", "", nil, cfg)
		assert.True(t, res.isNext)
	}

	{
		for _, path := range []string{
			"/v1/files", "/v1", "/v1/chat", "/v1/chat/completions/x", "/",
		} {
			res := serveGuard(t, http.MethodPost, path, chatBody, nil, cfg)
			assert.False(t, res.isNext, path)
			assert.Equal(t, http.StatusNotFound, res.code, path)
			assert.Equal(t, ErrCodeNotFound, res.errCode, path)
		}
	}

	{
		res := serveGuard(t, http.MethodGet, "/v1/chat/completions", "", nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusNotFound, res.code)
	}

	{
		res := serveGuard(t, http.MethodPost, "/v1/messages",
			`{"model":"claude-sonnet-4","max_tokens":16}`, nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusNotFound, res.code)
	}
}

func TestGuardContentType(t *testing.T) {
	cfg := &corev1.Service_Spec_Config_LLM{}

	{
		res := serveGuard(t, http.MethodPost, "/v1/chat/completions", chatBody,
			map[string]string{"Content-Type": ""}, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusUnsupportedMediaType, res.code)
	}

	{
		res := serveGuard(t, http.MethodPost, "/v1/chat/completions", chatBody,
			map[string]string{"Content-Type": "text/plain"}, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusUnsupportedMediaType, res.code)
	}

	{
		res := serveGuard(t, http.MethodPost, "/v1/chat/completions", chatBody,
			map[string]string{"Content-Type": "application/json; charset=utf-8"}, cfg)
		assert.True(t, res.isNext)
	}
}

func TestGuardBody(t *testing.T) {
	cfg := &corev1.Service_Spec_Config_LLM{}

	{
		res := serveGuard(t, http.MethodPost, "/v1/chat/completions", "", nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}

	{
		res := serveGuard(t, http.MethodPost, "/v1/chat/completions", "[]", nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}

	{
		res := serveGuard(t, http.MethodPost, "/v1/chat/completions", "not json", nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}
}

func TestGuardLimits(t *testing.T) {

	{
		cfg := &corev1.Service_Spec_Config_LLM{
			Limits: &corev1.Service_Spec_Config_LLM_Limits{
				MaxEstimatedInputTokens: 10,
			},
		}

		assert.True(t, serveGuard(t, http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`,
			nil, cfg).isNext)

		res := serveGuard(t, http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[{"role":"user","content":"`+
				strings.Repeat("a", 4096)+`"}]}`, nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusRequestEntityTooLarge, res.code)
		assert.Equal(t, ErrCodeLimitExceeded, res.errCode)
	}

	{
		cfg := &corev1.Service_Spec_Config_LLM{
			Limits: &corev1.Service_Spec_Config_LLM_Limits{
				MaxOutputTokens: 1024,
			},
		}

		assert.True(t, serveGuard(t, http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","max_tokens":512,"messages":[]}`, nil, cfg).isNext)

		res := serveGuard(t, http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","max_tokens":4096,"messages":[]}`, nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}

	{
		cfg := &corev1.Service_Spec_Config_LLM{
			Limits: &corev1.Service_Spec_Config_LLM_Limits{
				MaxTools: 1,
			},
		}

		res := serveGuard(t, http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","messages":[],"tools":[{"name":"a"},{"name":"b"}]}`,
			nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}
}

func TestGuardAnthropicErrors(t *testing.T) {
	cfg := &corev1.Service_Spec_Config_LLM{
		Protocol: corev1.Service_Spec_Config_LLM_ANTHROPIC,
		Limits: &corev1.Service_Spec_Config_LLM_Limits{
			MaxOutputTokens: 1024,
		},
	}

	{
		assert.True(t, serveGuard(t, http.MethodPost, "/v1/messages",
			`{"model":"claude-sonnet-4","max_tokens":16,"messages":[]}`,
			nil, cfg).isNext)
	}

	{
		res := serveGuard(t, http.MethodPost, "/v1/messages",
			`{"model":"claude-sonnet-4","max_tokens":4096,"messages":[]}`, nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
		assert.Equal(t, "invalid_request_error", res.errType)
	}

	{
		res := serveGuard(t, http.MethodPost, "/v1/files", "{}", nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusNotFound, res.code)
		assert.Equal(t, "not_found_error", res.errType)
	}
}

func TestGuardStream(t *testing.T) {
	cfg := &corev1.Service_Spec_Config_LLM{}

	{
		assert.True(t, serveGuard(t, http.MethodPost, "/v1/chat/completions",
			`{"model":"gpt-4o","stream":true,"messages":[]}`, nil, cfg).isNext)
	}

	{
		res := serveGuard(t, http.MethodPost, "/v1/embeddings",
			`{"model":"text-embedding-3-small","stream":true,"input":"a"}`, nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}
}

func TestGuardModelTooLong(t *testing.T) {
	cfg := &corev1.Service_Spec_Config_LLM{}

	{
		res := serveGuard(t, http.MethodPost, "/v1/chat/completions",
			`{"model":"`+strings.Repeat("a", 257)+`","messages":[]}`, nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
		assert.Equal(t, ErrCodeInvalidRequest, res.errCode)
	}

	{
		res := serveGuard(t, http.MethodGet,
			"/v1/models/"+strings.Repeat("a", 257), "", nil, cfg)
		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusBadRequest, res.code)
	}

	{
		assert.True(t, serveGuard(t, http.MethodPost, "/v1/chat/completions",
			`{"model":"`+strings.Repeat("a", 256)+`","messages":[]}`, nil, cfg).isNext)
	}
}
