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

package httpg

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

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type tstSrvLLM struct {
	port int
	srv  *http.Server
	lis  net.Listener

	bearerToken string

	mu         sync.Mutex
	reqCount   int
	lastPath   string
	lastMethod string
	lastBody   []byte
	lastHeader http.Header
}

type tstLLMErrResp struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

func newSrvLLM(t *testing.T, port int) *tstSrvLLM {
	return &tstSrvLLM{
		port: port,
	}
}

func (s *tstSrvLLM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	s.mu.Lock()
	s.reqCount++
	s.lastPath = r.URL.Path
	s.lastMethod = r.Method
	s.lastBody = body
	s.lastHeader = r.Header.Clone()
	s.mu.Unlock()

	if s.bearerToken != "" &&
		r.Header.Get("Authorization") != fmt.Sprintf("Bearer %s", s.bearerToken) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(map[string]any{
			"object": "list",
			"data": []any{
				map[string]any{"id": "gpt-4o", "object": "model"},
			},
		})
		w.Write(resp)
		return
	}

	reqMap := map[string]any{}
	json.Unmarshal(body, &reqMap)

	model, _ := reqMap["model"].(string)
	isStream, _ := reqMap["stream"].(bool)

	if isStream {
		s.serveStream(w, model)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	resp, err := json.Marshal(map[string]any{
		"id":     "chatcmpl-octelium",
		"object": "chat.completion",
		"model":  model,
		"choices": []any{
			map[string]any{
				"index":         0,
				"finish_reason": "stop",
				"message": map[string]any{
					"role":    "assistant",
					"content": "hello",
				},
			},
		},
		"usage": map[string]any{
			"prompt_tokens":     10,
			"completion_tokens": 5,
			"total_tokens":      15,
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(resp)
}

func (s *tstSrvLLM) serveStream(w http.ResponseWriter, model string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)

	for _, ev := range []string{
		fmt.Sprintf(`{"id":"chatcmpl-octelium","object":"chat.completion.chunk",`+
			`"model":%q,"choices":[{"index":0,"delta":{"content":"hello"}}]}`, model),
		fmt.Sprintf(`{"id":"chatcmpl-octelium","object":"chat.completion.chunk",`+
			`"model":%q,"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],`+
			`"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`, model),
		"[DONE]",
	} {
		fmt.Fprintf(w, "data: %s\n\n", ev)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func (s *tstSrvLLM) run(t *testing.T) {
	addr := fmt.Sprintf("localhost:%d", s.port)
	var err error

	s.srv = &http.Server{
		Addr:    addr,
		Handler: s,
	}

	s.lis, err = func() (net.Listener, error) {
		for range 100 {
			ret, err := net.Listen("tcp", addr)
			if err == nil {
				return ret, nil
			}
			time.Sleep(1 * time.Second)
		}
		return nil, errors.Errorf("Could not listen tstSrvLLM")
	}()
	assert.Nil(t, err)

	go s.srv.Serve(s.lis)
}

func (s *tstSrvLLM) close() {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.lis != nil {
		s.lis.Close()
	}
}

func (s *tstSrvLLM) getLastPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPath
}

func (s *tstSrvLLM) getLastBodyMap() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	ret := map[string]any{}
	json.Unmarshal(s.lastBody, &ret)
	return ret
}

func (s *tstSrvLLM) getLastHeader(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastHeader == nil {
		return ""
	}
	return s.lastHeader.Get(k)
}

func (s *tstSrvLLM) getReqCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqCount
}

type tstLLMEnv struct {
	fakeC      *tests.FakeClient
	adminSrv   *admin.Server
	usrSrv     *user.Server
	vCache     *vcache.Cache
	octovigilC *octovigilc.Client
	srv        *Server
	svcV       *corev1.Service
	usr        *tstuser.User
	upstream   *tstSrvLLM
	authz      *corev1.Service_Spec_Authorization
}

func newLLMEnv(t *testing.T, ctx context.Context) *tstLLMEnv {
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	upstreamSrv := newSrvLLM(t, tests.GetPort())
	upstreamSrv.run(t)
	t.Cleanup(func() {
		upstreamSrv.close()
	})

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	return &tstLLMEnv{
		fakeC: fakeC,
		adminSrv: admin.NewServer(&admin.Opts{
			OcteliumC:  fakeC.OcteliumC,
			IsEmbedded: true,
		}),
		usrSrv:   user.NewServer(fakeC.OcteliumC),
		upstream: upstreamSrv,
	}
}

func (e *tstLLMEnv) start(t *testing.T, ctx context.Context,
	llmCfg *corev1.Service_Spec_Config_LLM, upstreamPath string) {

	svc, err := e.adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_LLM,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d%s",
							e.upstream.port, upstreamPath),
					},
				},
				Type: &corev1.Service_Spec_Config_Llm{
					Llm: llmCfg,
				},
			},
			Authorization: func() *corev1.Service_Spec_Authorization {
				if e.authz != nil {
					return e.authz
				}
				return &corev1.Service_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Effect: corev1.Policy_Spec_Rule_ALLOW,
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
									},
								},
							},
						},
					},
				}
			}(),
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := e.fakeC.OcteliumC.CoreC().GetService(ctx,
		&rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: e.fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, e.fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  e.fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(e.fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		srv.Close()
	})

	usr, err := tstuser.NewUser(e.fakeC.OcteliumC, e.adminSrv, e.usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = e.fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	e.vCache = vCache
	e.octovigilC = octovigilC
	e.srv = srv
	e.svcV = svcV
	e.usr = usr
}

func (e *tstLLMEnv) getURL(path string) string {
	return fmt.Sprintf("http://localhost:%d%s",
		ucorev1.ToService(e.svcV).RealPort(), path)
}

func (e *tstLLMEnv) newChatBody(model string) map[string]any {
	return map[string]any{
		"model": model,
		"messages": []any{
			map[string]any{"role": "user", "content": "hello"},
		},
	}
}

func TestServerLLM(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{}, "")

	{
		resp, err := resty.New().SetDebug(true).R().
			SetBody(env.newChatBody("gpt-4o")).
			Post(env.getURL("/v1/chat/completions"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())

		assert.Equal(t, "/v1/chat/completions", env.upstream.getLastPath())
		assert.Equal(t, "gpt-4o", env.upstream.getLastBodyMap()["model"])

		res := map[string]any{}
		assert.Nil(t, json.Unmarshal(resp.Body(), &res))
		assert.Equal(t, "gpt-4o", res["model"])
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(env.getURL("/v1/models"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
		assert.Equal(t, "/v1/models", env.upstream.getLastPath())
	}
}

func TestServerLLMUnknownRoute(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{}, "")

	for _, arg := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/unknown"},
		{http.MethodPost, "/"},
		{http.MethodGet, "/v1/chat/completions"},
		{http.MethodPost, "/v1/messages"},
	} {
		cnt := env.upstream.getReqCount()

		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetBody(env.newChatBody("gpt-4o")).
			Execute(arg.method, env.getURL(arg.path))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode(), arg.path)

		errResp := &tstLLMErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, "not_found_error", errResp.Error.Type, arg.path)
		assert.Equal(t, "octelium_not_found", errResp.Error.Code, arg.path)

		assert.Equal(t, cnt, env.upstream.getReqCount(), arg.path)
	}
}

func TestServerLLMContentType(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{}, "")

	cnt := env.upstream.getReqCount()

	resp, err := resty.New().R().
		SetHeader("Content-Type", "text/plain").
		SetBody(`{"model":"gpt-4o","messages":[]}`).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode())
	assert.Equal(t, cnt, env.upstream.getReqCount())

	resp, err = resty.New().R().
		SetHeader("Content-Type", "application/json").
		SetBody(`not a json object`).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode())

	errResp := &tstLLMErrResp{}
	assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
	assert.Equal(t, "octelium_invalid_request", errResp.Error.Code)
}

func TestServerLLMModel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Model: &corev1.Service_Spec_Config_LLM_Model{
			Type: &corev1.Service_Spec_Config_LLM_Model_Value{
				Value: "octelium-model",
			},
		},
	}, "")

	resp, err := resty.New().SetDebug(true).R().
		SetBody(env.newChatBody("gpt-4o")).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), resp.String())

	assert.Equal(t, "octelium-model", env.upstream.getLastBodyMap()["model"])
	assert.NotNil(t, env.upstream.getLastBodyMap()["messages"])
}

func TestServerLLMModelEval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Model: &corev1.Service_Spec_Config_LLM_Model{
			Type: &corev1.Service_Spec_Config_LLM_Model_Eval{
				Eval: `ctx.request.llm.model + "-rewritten"`,
			},
		},
	}, "")

	resp, err := resty.New().SetDebug(true).R().
		SetBody(env.newChatBody("gpt-4o")).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), resp.String())

	assert.Equal(t, "gpt-4o-rewritten", env.upstream.getLastBodyMap()["model"])
}

func TestServerLLMUpstreamBasePath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{}, "/api/v1")

	{
		resp, err := resty.New().SetDebug(true).R().
			SetBody(env.newChatBody("gpt-4o")).
			Post(env.getURL("/v1/chat/completions"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
		assert.Equal(t, "/api/v1/chat/completions", env.upstream.getLastPath())
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(env.getURL("/v1/models"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
		assert.Equal(t, "/api/v1/models", env.upstream.getLastPath())
	}
}

func TestServerLLMUpstreamAuth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)

	tkn := utilrand.GetRandomString(32)
	env.upstream.bearerToken = tkn

	sec, err := env.adminSrv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: tkn,
			},
		},
	})
	assert.Nil(t, err)

	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Auth: &corev1.Service_Spec_Config_HTTP_Auth{
			Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_{
				Bearer: &corev1.Service_Spec_Config_HTTP_Auth_Bearer{
					Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_FromSecret{
						FromSecret: sec.Metadata.Name,
					},
				},
			},
		},
	}, "")

	downstreamTkn := utilrand.GetRandomString(32)

	resp, err := resty.New().SetDebug(true).R().
		SetHeader("Authorization", fmt.Sprintf("Bearer %s", downstreamTkn)).
		SetHeader("X-Api-Key", downstreamTkn).
		SetBody(env.newChatBody("gpt-4o")).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), resp.String())

	assert.Equal(t, fmt.Sprintf("Bearer %s", tkn),
		env.upstream.getLastHeader("Authorization"))
	assert.Empty(t, env.upstream.getLastHeader("X-Api-Key"))
}

func TestServerLLMStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{}, "")

	body := env.newChatBody("gpt-4o")
	body["stream"] = true

	resp, err := resty.New().R().
		SetBody(body).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), resp.String())

	assert.True(t, strings.HasPrefix(
		resp.Header().Get("Content-Type"), "text/event-stream"),
		resp.Header().Get("Content-Type"))

	assert.True(t, strings.Contains(resp.String(), `"delta":{"content":"hello"}`),
		resp.String())
	assert.True(t, strings.Contains(resp.String(), "data: [DONE]"), resp.String())
	assert.Equal(t, true, env.upstream.getLastBodyMap()["stream"])
}

func TestServerLLMLimits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Limits: &corev1.Service_Spec_Config_LLM_Limits{
			MaxOutputTokens: 100,
			MaxTools:        1,
		},
	}, "")

	{
		body := env.newChatBody("gpt-4o")
		body["max_tokens"] = 1000

		cnt := env.upstream.getReqCount()

		resp, err := resty.New().R().
			SetBody(body).
			Post(env.getURL("/v1/chat/completions"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())

		errResp := &tstLLMErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, "octelium_limit_exceeded", errResp.Error.Code)

		assert.Equal(t, cnt, env.upstream.getReqCount())
	}

	{
		body := env.newChatBody("gpt-4o")
		body["tools"] = []any{
			map[string]any{"type": "function",
				"function": map[string]any{"name": "a"}},
			map[string]any{"type": "function",
				"function": map[string]any{"name": "b"}},
		}

		resp, err := resty.New().R().
			SetBody(body).
			Post(env.getURL("/v1/chat/completions"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())

		errResp := &tstLLMErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, "octelium_limit_exceeded", errResp.Error.Code)
	}

	{
		body := env.newChatBody("gpt-4o")
		body["max_tokens"] = 10

		resp, err := resty.New().R().
			SetBody(body).
			Post(env.getURL("/v1/chat/completions"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
	}
}

func TestServerLLMMaxRequestBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Limits: &corev1.Service_Spec_Config_LLM_Limits{
			MaxRequestBytes: 128,
		},
	}, "")

	cnt := env.upstream.getReqCount()

	body := env.newChatBody("gpt-4o")
	body["messages"] = []any{
		map[string]any{"role": "user", "content": strings.Repeat("x", 4096)},
	}

	resp, err := resty.New().R().
		SetBody(body).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode())
	assert.Equal(t, cnt, env.upstream.getReqCount())
}

func TestServerLLMCORS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const origin = "https://console.example.com"

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Cors: &corev1.Service_Spec_Config_HTTP_CORS{
			AllowOriginStringMatch: []string{origin},
			AllowCredentials:       true,
		},
	}, "")

	{
		resp, err := resty.New().SetDebug(true).R().
			SetHeader("Origin", origin).
			SetHeader("Access-Control-Request-Method", http.MethodPost).
			SetHeader("Access-Control-Request-Headers", "content-type,authorization").
			Options(env.getURL("/v1/chat/completions"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusNoContent, resp.StatusCode())
		assert.Equal(t, origin, resp.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", resp.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, http.MethodPost,
			resp.Header().Get("Access-Control-Allow-Methods"))
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			SetHeader("Origin", origin).
			SetBody(env.newChatBody("gpt-4o")).
			Post(env.getURL("/v1/chat/completions"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
		assert.Equal(t, origin, resp.Header().Get("Access-Control-Allow-Origin"))
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			SetHeader("Origin", "https://evil.example.com").
			SetHeader("Access-Control-Request-Method", http.MethodPost).
			Options(env.getURL("/v1/chat/completions"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode())
		assert.Empty(t, resp.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestServerLLMAnthropic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Protocol: corev1.Service_Spec_Config_LLM_ANTHROPIC,
	}, "")

	{
		resp, err := resty.New().SetDebug(true).R().
			SetBody(env.newChatBody("claude-sonnet-4")).
			Post(env.getURL("/v1/messages"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
		assert.Equal(t, "/v1/messages", env.upstream.getLastPath())
	}

	{
		cnt := env.upstream.getReqCount()

		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetBody(env.newChatBody("claude-sonnet-4")).
			Post(env.getURL("/v1/chat/completions"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode())

		errResp := &tstLLMErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, "error", func() string {
			ret := map[string]any{}
			json.Unmarshal(resp.Body(), &ret)
			val, _ := ret["type"].(string)
			return val
		}())

		assert.Equal(t, cnt, env.upstream.getReqCount())
	}
}

func newLuaPlugin(name string, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase,
	inline string) *corev1.Service_Spec_Config_HTTP_Plugin {
	return &corev1.Service_Spec_Config_HTTP_Plugin{
		Name:  name,
		Phase: phase,
		Condition: &corev1.Condition{
			Type: &corev1.Condition_MatchAny{
				MatchAny: true,
			},
		},
		Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
			Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
				Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
					Inline: inline,
				},
			},
		},
	}
}

func TestServerLLMLuaModel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
			newLuaPlugin("set-model", corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH, `
function onRequest(ctx)
  local body = json.decode(octelium.req.getRequestBody())
  body["model"] = "lua-model"
  octelium.req.setRequestBody(json.encode(body))
end
`),
		},
		Model: &corev1.Service_Spec_Config_LLM_Model{
			Type: &corev1.Service_Spec_Config_LLM_Model_Eval{
				Eval: `ctx.request.llm.model + "-fromctx"`,
			},
		},
	}, "")

	resp, err := resty.New().SetDebug(true).R().
		SetBody(env.newChatBody("gpt-4o")).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), resp.String())

	assert.Equal(t, "lua-model-fromctx", env.upstream.getLastBodyMap()["model"])
}

func TestServerLLMLuaMessages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
			newLuaPlugin("rewrite-prompt", corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH, `
function onRequest(ctx)
  local body = json.decode(octelium.req.getRequestBody())
  body["messages"] = {
    {role = "system", content = "octelium-guardrail"},
    {role = "user", content = "rewritten-prompt"},
  }
  octelium.req.setRequestBody(json.encode(body))
end
`),
		},
	}, "")

	resp, err := resty.New().SetDebug(true).R().
		SetBody(env.newChatBody("gpt-4o")).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), resp.String())

	messages := env.upstream.getLastBodyMap()["messages"].([]any)
	assert.Equal(t, 2, len(messages))

	assert.Equal(t, "system", messages[0].(map[string]any)["role"])
	assert.Equal(t, "octelium-guardrail", messages[0].(map[string]any)["content"])
	assert.Equal(t, "rewritten-prompt", messages[1].(map[string]any)["content"])
}

func TestServerLLMLuaReasoning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
			newLuaPlugin("set-reasoning", corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH, `
function onRequest(ctx)
  local body = json.decode(octelium.req.getRequestBody())
  body["reasoning_effort"] = "low"
  body["reasoning"] = {effort = "low", summary = "concise"}
  body["max_tokens"] = 64
  octelium.req.setRequestBody(json.encode(body))
end
`),
		},
		Limits: &corev1.Service_Spec_Config_LLM_Limits{
			MaxOutputTokens: 128,
		},
	}, "")

	body := env.newChatBody("gpt-4o")
	body["reasoning_effort"] = "high"

	resp, err := resty.New().SetDebug(true).R().
		SetBody(body).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), resp.String())

	upstreamBody := env.upstream.getLastBodyMap()
	assert.Equal(t, "low", upstreamBody["reasoning_effort"])
	assert.Equal(t, float64(64), upstreamBody["max_tokens"])

	reasoning := upstreamBody["reasoning"].(map[string]any)
	assert.Equal(t, "low", reasoning["effort"])
	assert.Equal(t, "concise", reasoning["summary"])
}

func TestServerLLMLuaModelOrdering(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
			newLuaPlugin("set-model", corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH, `
function onRequest(ctx)
  local body = json.decode(octelium.req.getRequestBody())
  body["model"] = "lua-post-model"
  body["messages"] = {{role = "user", content = "from-lua"}}
  octelium.req.setRequestBody(json.encode(body))
end
`),
		},
		Model: &corev1.Service_Spec_Config_LLM_Model{
			Type: &corev1.Service_Spec_Config_LLM_Model_Value{
				Value: "config-model",
			},
		},
	}, "")

	resp, err := resty.New().SetDebug(true).R().
		SetBody(env.newChatBody("gpt-4o")).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), resp.String())

	upstreamBody := env.upstream.getLastBodyMap()
	assert.Equal(t, "config-model", upstreamBody["model"])

	messages := upstreamBody["messages"].([]any)
	assert.Equal(t, "from-lua", messages[0].(map[string]any)["content"])
}

func TestServerLLMLuaAuthorization(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.authz = &corev1.Service_Spec_Authorization{
		InlinePolicies: []*corev1.InlinePolicy{
			{
				Spec: &corev1.Policy_Spec{
					Rules: []*corev1.Policy_Spec_Rule{
						{
							Name:     "deny-lua-model",
							Priority: 0,
							Effect:   corev1.Policy_Spec_Rule_DENY,
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `ctx.request.llm.model == "lua-model"`,
								},
							},
						},
						{
							Name:     "allow-rest",
							Priority: 1,
							Effect:   corev1.Policy_Spec_Rule_ALLOW,
							Condition: &corev1.Condition{
								Type: &corev1.Condition_MatchAny{
									MatchAny: true,
								},
							},
						},
					},
				},
			},
		},
	}

	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
			newLuaPlugin("set-model", corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH, `
function onRequest(ctx)
  local body = json.decode(octelium.req.getRequestBody())
  body["model"] = "lua-model"
  octelium.req.setRequestBody(json.encode(body))
end
`),
		},
	}, "")

	cnt := env.upstream.getReqCount()

	resp, err := resty.New().SetDebug(true).R().
		SetBody(env.newChatBody("gpt-4o")).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode(), resp.String())

	assert.Equal(t, cnt, env.upstream.getReqCount())
}

func TestServerLLMLuaResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newLLMEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_LLM{
		Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
			newLuaPlugin("rewrite-response", corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH, `
function onResponse(ctx)
  local body = json.decode(octelium.req.getResponseBody())
  body["choices"][1]["message"]["content"] = "redacted-by-octelium"
  octelium.req.setResponseBody(json.encode(body))
end
`),
		},
	}, "")

	resp, err := resty.New().SetDebug(true).R().
		SetBody(env.newChatBody("gpt-4o")).
		Post(env.getURL("/v1/chat/completions"))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), resp.String())

	res := map[string]any{}
	assert.Nil(t, json.Unmarshal(resp.Body(), &res))

	choices := res["choices"].([]any)
	message := choices[0].(map[string]any)["message"].(map[string]any)
	assert.Equal(t, "redacted-by-octelium", message["content"])
}
