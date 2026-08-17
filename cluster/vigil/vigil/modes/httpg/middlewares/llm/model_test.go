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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
)

type modelResult struct {
	isNext   bool
	code     int
	upstream map[string]any
	reqCtx   *middlewares.RequestContext
}

func serveModel(t *testing.T, method, path, body string,
	cfg *corev1.Service_Spec_Config_LLM, reqCtxMap map[string]any) *modelResult {

	ctx := context.Background()
	ret := &modelResult{}

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ret.isNext = true
		out, err := io.ReadAll(r.Body)
		assert.Nil(t, err)
		if len(out) > 0 {
			assert.Equal(t, int64(len(out)), r.ContentLength)
			assert.Nil(t, json.Unmarshal(out, &ret.upstream))
		}
	})

	mdlwr, err := NewModel(ctx, next, celEngine)
	assert.Nil(t, err)

	req := httptest.NewRequest(method, "http://my-llm.example.com"+path,
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	svcCfg := &corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Llm{Llm: cfg},
	}

	bodyMap := make(map[string]any)
	json.Unmarshal([]byte(body), &bodyMap)

	reqCtx := &middlewares.RequestContext{
		CreatedAt:     time.Now(),
		Service:       newService(),
		ServiceConfig: svcCfg,
		Body:          []byte(body),
		BodyJSONMap:   bodyMap,
		ReqCtxMap:     reqCtxMap,
		LLM: httputils.ParseLLMRequest(req,
			cfg.GetProtocol(), []byte(body)),
	}
	ret.reqCtx = reqCtx

	req = req.WithContext(context.WithValue(ctx,
		middlewares.CtxRequestContext, reqCtx))

	rw := httptest.NewRecorder()
	mdlwr.ServeHTTP(rw, req)

	ret.code = rw.Result().StatusCode

	return ret
}

func TestModelUnset(t *testing.T) {
	res := serveModel(t, http.MethodPost, "/v1/chat/completions", chatBody,
		&corev1.Service_Spec_Config_LLM{}, nil)

	assert.True(t, res.isNext)
	assert.Equal(t, "gpt-4o", res.upstream["model"])
	assert.Equal(t, chatBody, string(res.reqCtx.Body))
}

func TestModelValue(t *testing.T) {

	{
		res := serveModel(t, http.MethodPost, "/v1/chat/completions", chatBody,
			&corev1.Service_Spec_Config_LLM{
				Model: &corev1.Service_Spec_Config_LLM_Model{
					Type: &corev1.Service_Spec_Config_LLM_Model_Value{
						Value: "gpt-4o-mini",
					},
				},
			}, nil)

		assert.True(t, res.isNext)
		assert.Equal(t, "gpt-4o-mini", res.upstream["model"])
		assert.Equal(t, "gpt-4o", res.reqCtx.LLM.GetModel())
	}

	{
		body := `{"model":"gpt-4o","seed":9007199254740993,` +
			`"messages":[{"role":"user","content":"Hello"}]}`

		res := serveModel(t, http.MethodPost, "/v1/chat/completions", body,
			&corev1.Service_Spec_Config_LLM{
				Model: &corev1.Service_Spec_Config_LLM_Model{
					Type: &corev1.Service_Spec_Config_LLM_Model_Value{
						Value: "o3-mini",
					},
				},
			}, nil)

		assert.True(t, res.isNext)
		assert.Equal(t, "o3-mini", res.upstream["model"])
		assert.Contains(t, string(res.reqCtx.Body), `"seed":9007199254740993`)
	}
}

func TestModelEval(t *testing.T) {

	reqCtxMap := map[string]any{
		"ctx": map[string]any{
			"request": map[string]any{
				"llm": map[string]any{
					"model": "fast",
				},
			},
		},
	}

	{
		res := serveModel(t, http.MethodPost, "/v1/chat/completions",
			`{"model":"fast","messages":[]}`,
			&corev1.Service_Spec_Config_LLM{
				Model: &corev1.Service_Spec_Config_LLM_Model{
					Type: &corev1.Service_Spec_Config_LLM_Model_Eval{
						Eval: `ctx.request.llm.model == "fast" ? "gpt-4o-mini" : "gpt-4o"`,
					},
				},
			}, reqCtxMap)

		assert.True(t, res.isNext)
		assert.Equal(t, "gpt-4o-mini", res.upstream["model"])
	}

	{
		res := serveModel(t, http.MethodPost, "/v1/chat/completions",
			`{"model":"fast","messages":[]}`,
			&corev1.Service_Spec_Config_LLM{
				Model: &corev1.Service_Spec_Config_LLM_Model{
					Type: &corev1.Service_Spec_Config_LLM_Model_Eval{
						Eval: `""`,
					},
				},
			}, reqCtxMap)

		assert.True(t, res.isNext)
		assert.Equal(t, "fast", res.upstream["model"])
	}

	{
		res := serveModel(t, http.MethodPost, "/v1/chat/completions",
			`{"model":"fast","messages":[]}`,
			&corev1.Service_Spec_Config_LLM{
				Model: &corev1.Service_Spec_Config_LLM_Model{
					Type: &corev1.Service_Spec_Config_LLM_Model_Eval{
						Eval: `ctx.doesNotExist.at.all`,
					},
				},
			}, reqCtxMap)

		assert.False(t, res.isNext)
		assert.Equal(t, http.StatusInternalServerError, res.code)
	}
}

func TestModelBodylessOperations(t *testing.T) {
	cfg := &corev1.Service_Spec_Config_LLM{
		Model: &corev1.Service_Spec_Config_LLM_Model{
			Type: &corev1.Service_Spec_Config_LLM_Model_Value{
				Value: "gpt-4o-mini",
			},
		},
	}

	{
		res := serveModel(t, http.MethodGet, "/v1/models", "", cfg, nil)
		assert.True(t, res.isNext)
		assert.Nil(t, res.upstream)
	}

	{
		res := serveModel(t, http.MethodGet, "/v1/models/gpt-4o", "", cfg, nil)
		assert.True(t, res.isNext)
		assert.Equal(t, "gpt-4o", res.reqCtx.LLM.GetModel())
	}
}
