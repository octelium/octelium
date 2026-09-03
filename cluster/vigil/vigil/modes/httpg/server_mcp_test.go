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
	"encoding/base64"
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

type tstSrvMCP struct {
	port int
	srv  *http.Server
	lis  net.Listener

	mu         sync.Mutex
	reqCount   int
	lastPath   string
	lastMethod string
	lastBody   []byte
	lastHeader http.Header
}

type tstMCPErrResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    any    `json:"data"`
	} `json:"error"`
}

func newSrvMCP(t *testing.T, port int) *tstSrvMCP {
	return &tstSrvMCP{
		port: port,
	}
}

func (s *tstSrvMCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	reqMap := map[string]any{}
	json.Unmarshal(body, &reqMap)

	name := func() string {
		params, ok := reqMap["params"].(map[string]any)
		if !ok {
			return ""
		}
		ret, _ := params["name"].(string)
		return ret
	}()

	w.Header().Set("Content-Type", "application/json")
	resp, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      reqMap["id"],
		"result": map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": name},
			},
		},
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(resp)
}

func (s *tstSrvMCP) run(t *testing.T) {
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
		return nil, errors.Errorf("Could not listen tstSrvMCP")
	}()
	assert.Nil(t, err)

	go s.srv.Serve(s.lis)
}

func (s *tstSrvMCP) close() {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.lis != nil {
		s.lis.Close()
	}
}

func (s *tstSrvMCP) getLastPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPath
}

func (s *tstSrvMCP) getLastBodyMap() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	ret := map[string]any{}
	json.Unmarshal(s.lastBody, &ret)
	return ret
}

func (s *tstSrvMCP) getReqCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqCount
}

type tstMCPEnv struct {
	fakeC      *tests.FakeClient
	adminSrv   *admin.Server
	usrSrv     *user.Server
	vCache     *vcache.Cache
	octovigilC *octovigilc.Client
	srv        *Server
	svcV       *corev1.Service
	usr        *tstuser.User
	upstream   *tstSrvMCP
	authz      *corev1.Service_Spec_Authorization
	domain     string
}

func newMCPEnv(t *testing.T, ctx context.Context) *tstMCPEnv {
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	upstreamSrv := newSrvMCP(t, tests.GetPort())
	upstreamSrv.run(t)
	t.Cleanup(func() {
		upstreamSrv.close()
	})

	cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
		V4: "127.0.0.0/8",
		V6: "::1/128",
	}
	_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	assert.Nil(t, err)

	return &tstMCPEnv{
		fakeC: fakeC,
		adminSrv: admin.NewServer(&admin.Opts{
			OcteliumC:  fakeC.OcteliumC,
			IsEmbedded: true,
		}),
		usrSrv:   user.NewServer(fakeC.OcteliumC),
		upstream: upstreamSrv,
		domain:   cc.Status.Domain,
	}
}

func (e *tstMCPEnv) start(t *testing.T, ctx context.Context,
	mcpCfg *corev1.Service_Spec_Config_MCP, upstreamPath string) {

	svc, err := e.adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_MCP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d%s",
							e.upstream.port, upstreamPath),
					},
				},
				Type: &corev1.Service_Spec_Config_Mcp{
					Mcp: mcpCfg,
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

func (e *tstMCPEnv) getURL(path string) string {
	return fmt.Sprintf("http://localhost:%d%s",
		ucorev1.ToService(e.svcV).RealPort(), path)
}

func (e *tstMCPEnv) getHost() string {
	return fmt.Sprintf("localhost:%d", ucorev1.ToService(e.svcV).RealPort())
}

func newMCPLuaPlugin(name string, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase,
	inline string) *corev1.Service_Spec_Config_MCP_Plugin {
	return &corev1.Service_Spec_Config_MCP_Plugin{
		Name:  name,
		Phase: phase,
		Condition: &corev1.Condition{
			Type: &corev1.Condition_MatchAny{
				MatchAny: true,
			},
		},
		Type: &corev1.Service_Spec_Config_MCP_Plugin_Lua{
			Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
				Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
					Inline: inline,
				},
			},
		},
	}
}

func newMCPToolCallBody(name string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      name,
			"arguments": map[string]any{"environment": "staging"},
		},
	}
}

func (e *tstMCPEnv) postMCP(t *testing.T, body any) *resty.Response {
	resp, err := resty.New().R().
		SetHeader("Content-Type", "application/json").
		SetBody(body).
		Post(e.getURL("/mcp"))
	assert.Nil(t, err, "%+v", err)
	return resp
}

func TestServerMCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{}, "")

	resp := env.postMCP(t, newMCPToolCallBody("read-report"))
	assert.True(t, resp.IsSuccess(), resp.String())

	assert.Equal(t, "/mcp", env.upstream.getLastPath())

	params := env.upstream.getLastBodyMap()["params"].(map[string]any)
	assert.Equal(t, "read-report", params["name"])

	res := map[string]any{}
	assert.Nil(t, json.Unmarshal(resp.Body(), &res))
	assert.Equal(t, "2.0", res["jsonrpc"])
}

func TestServerMCPTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{}, "")

	for _, method := range []string{
		http.MethodGet,
		http.MethodDelete,
		http.MethodPut,
	} {
		cnt := env.upstream.getReqCount()

		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			Execute(method, env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode(), method)

		errResp := &tstMCPErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, -40003, errResp.Error.Code, method)
		assert.Equal(t, "2.0", errResp.JSONRPC, method)

		assert.Equal(t, cnt, env.upstream.getReqCount(), method)
	}
}

func TestServerMCPEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{
		Endpoint: "/mcp",
	}, "")

	{
		resp := env.postMCP(t, newMCPToolCallBody("read-report"))
		assert.True(t, resp.IsSuccess(), resp.String())
	}

	{
		cnt := env.upstream.getReqCount()

		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetBody(newMCPToolCallBody("read-report")).
			Post(env.getURL("/other"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode())

		errResp := &tstMCPErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, -40003, errResp.Error.Code)

		assert.Equal(t, cnt, env.upstream.getReqCount())
	}
}

func TestServerMCPContentType(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{}, "")

	cnt := env.upstream.getReqCount()

	resp, err := resty.New().R().
		SetHeader("Content-Type", "text/plain").
		SetBody(`{"jsonrpc":"2.0","id":1,"method":"ping"}`).
		Post(env.getURL("/mcp"))
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode())
	assert.Equal(t, cnt, env.upstream.getReqCount())
}

func TestServerMCPEnvelope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{}, "")

	for _, arg := range []struct {
		body string
		code int
	}{
		{`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, -32600},
		{`"not an object"`, -32700},
		{`{"jsonrpc":"1.0","id":1,"method":"ping"}`, -32600},
		{`{"jsonrpc":"2.0","id":1}`, -32600},
		{`{"jsonrpc":"2.0","id":1,"method":""}`, -32600},
		{`{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}`, -32600},
	} {
		cnt := env.upstream.getReqCount()

		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetBody(arg.body).
			Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode(), arg.body)

		errResp := &tstMCPErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, arg.code, errResp.Error.Code, arg.body)

		assert.Equal(t, cnt, env.upstream.getReqCount(), arg.body)
	}
}

func TestServerMCPProtocolVersion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{
		Protocol: &corev1.Service_Spec_Config_MCP_Protocol{
			Versions:       []string{"2025-06-18"},
			RequireVersion: true,
		},
	}, "")

	{
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetHeader("MCP-Protocol-Version", "2025-06-18").
			SetBody(newMCPToolCallBody("read-report")).
			Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
	}

	{
		resp := env.postMCP(t, newMCPToolCallBody("read-report"))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())

		errResp := &tstMCPErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, -32020, errResp.Error.Code)
	}

	{
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetHeader("MCP-Protocol-Version", "2024-11-05").
			SetBody(newMCPToolCallBody("read-report")).
			Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())

		errResp := &tstMCPErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, -32022, errResp.Error.Code)
		assert.NotNil(t, errResp.Error.Data)
	}

	{
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetHeader("MCP-Protocol-Version", "2025-06-18").
			SetBody(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "initialize",
				"params": map[string]any{
					"protocolVersion": "2024-11-05",
				},
			}).
			Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())

		errResp := &tstMCPErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, -32020, errResp.Error.Code)
	}

	{
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetBody(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "tools/call",
				"params": map[string]any{
					"name": "read-report",
					"_meta": map[string]any{
						"io.modelcontextprotocol/protocolVersion": "2024-11-05",
					},
				},
			}).
			Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode())

		errResp := &tstMCPErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, -32022, errResp.Error.Code)
	}

	{
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetBody(map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"method":  "initialize",
				"params": map[string]any{
					"protocolVersion": "2025-06-18",
				},
			}).
			Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
	}
}

func TestServerMCPMirroredHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{}, "")

	{
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetHeader("Mcp-Method", "tools/call").
			SetHeader("Mcp-Name", "read-report").
			SetBody(newMCPToolCallBody("read-report")).
			Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
	}

	for _, arg := range []map[string]string{
		{"Mcp-Method": "tools/list"},
		{"Mcp-Name": "delete-production"},
		{"Mcp-Name": fmt.Sprintf("=?base64?%s?=", "!!!not-base64!!!")},
	} {
		cnt := env.upstream.getReqCount()

		req := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetBody(newMCPToolCallBody("read-report"))
		for k, v := range arg {
			req.SetHeader(k, v)
		}

		resp, err := req.Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode(), arg)

		errResp := &tstMCPErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, -32020, errResp.Error.Code, arg)

		assert.Equal(t, cnt, env.upstream.getReqCount(), arg)
	}

	{
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetHeader("Mcp-Name", fmt.Sprintf("=?base64?%s?=",
				base64.StdEncoding.EncodeToString([]byte("read-report")))).
			SetBody(newMCPToolCallBody("read-report")).
			Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
	}
}

func TestServerMCPSingletonHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{}, "")

	cnt := env.upstream.getReqCount()

	req := resty.New().R().
		SetHeader("Content-Type", "application/json").
		SetBody(newMCPToolCallBody("read-report"))
	req.Header.Add("Mcp-Session-Id", "sess-a")
	req.Header.Add("Mcp-Session-Id", "sess-b")

	resp, err := req.Post(env.getURL("/mcp"))
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode())

	errResp := &tstMCPErrResp{}
	assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
	assert.Equal(t, -32020, errResp.Error.Code)

	assert.Equal(t, cnt, env.upstream.getReqCount())
}

func TestServerMCPRejectUnknownMethods(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{
		Protocol: &corev1.Service_Spec_Config_MCP_Protocol{
			RejectUnknownMethods: true,
		},
	}, "")

	{
		resp := env.postMCP(t, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "ping",
		})
		assert.True(t, resp.IsSuccess(), resp.String())
	}

	{
		cnt := env.upstream.getReqCount()

		resp := env.postMCP(t, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "octelium/unknown",
		})
		assert.Equal(t, http.StatusNotFound, resp.StatusCode())

		errResp := &tstMCPErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, -32601, errResp.Error.Code)

		assert.Equal(t, cnt, env.upstream.getReqCount())
	}
}

func TestServerMCPOrigin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{}, "")

	{
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetHeader("Origin", fmt.Sprintf("http://%s", env.getHost())).
			SetBody(newMCPToolCallBody("read-report")).
			Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
	}

	{
		cnt := env.upstream.getReqCount()

		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetHeader("Origin", "https://evil.example.com").
			SetBody(newMCPToolCallBody("read-report")).
			Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode())

		errResp := &tstMCPErrResp{}
		assert.Nil(t, json.Unmarshal(resp.Body(), errResp))
		assert.Equal(t, -40004, errResp.Error.Code)

		assert.Equal(t, cnt, env.upstream.getReqCount())
	}
}

func TestServerMCPOriginDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{
		DisableOriginCheck: true,
	}, "")

	resp, err := resty.New().R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Origin", "https://evil.example.com").
		SetBody(newMCPToolCallBody("read-report")).
		Post(env.getURL("/mcp"))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), resp.String())
}

func TestServerMCPOriginCors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const origin = "https://console.example.com"

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{
		Cors: &corev1.Service_Spec_Config_HTTP_CORS{
			AllowOriginStringMatch: []string{origin},
			AllowCredentials:       true,
		},
	}, "")

	{
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetHeader("Origin", origin).
			SetBody(newMCPToolCallBody("read-report")).
			Post(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
		assert.Equal(t, origin, resp.Header().Get("Access-Control-Allow-Origin"))
	}

	{
		resp, err := resty.New().R().
			SetHeader("Origin", origin).
			SetHeader("Access-Control-Request-Method", http.MethodPost).
			SetHeader("Access-Control-Request-Headers", "content-type,mcp-session-id").
			Options(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusNoContent, resp.StatusCode())
		assert.Equal(t, origin, resp.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", resp.Header().Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "content-type,mcp-session-id",
			resp.Header().Get("Access-Control-Allow-Headers"))
	}

	{
		resp, err := resty.New().R().
			SetHeader("Origin", "https://evil.example.com").
			SetHeader("Access-Control-Request-Method", http.MethodPost).
			Options(env.getURL("/mcp"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode())
		assert.Empty(t, resp.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestServerMCPUpstreamPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{}, "/api/mcp")

	{
		resp := env.postMCP(t, newMCPToolCallBody("read-report"))
		assert.True(t, resp.IsSuccess(), resp.String())
		assert.Equal(t, "/api/mcp", env.upstream.getLastPath())
	}

	{
		resp, err := resty.New().R().
			SetHeader("Content-Type", "application/json").
			SetBody(newMCPToolCallBody("read-report")).
			Post(env.getURL("/"))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess(), resp.String())
		assert.Equal(t, "/api/mcp", env.upstream.getLastPath())
	}
}

func TestServerMCPMaxRequestBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{
		Limits: &corev1.Service_Spec_Config_MCP_Limits{
			MaxRequestBytes: 128,
		},
	}, "")

	cnt := env.upstream.getReqCount()

	body := newMCPToolCallBody("read-report")
	body["params"] = map[string]any{
		"name":      "read-report",
		"arguments": map[string]any{"data": strings.Repeat("x", 4096)},
	}

	resp := env.postMCP(t, body)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode())
	assert.Equal(t, cnt, env.upstream.getReqCount())
}

func TestServerMCPWellKnown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{}, "")

	cnt := env.upstream.getReqCount()

	resp, err := resty.New().R().
		Get(env.getURL("/.well-known/oauth-protected-resource"))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), resp.String())

	res := map[string]any{}
	assert.Nil(t, json.Unmarshal(resp.Body(), &res))

	assert.Equal(t, []any{fmt.Sprintf("https://%s", env.domain)},
		res["authorization_servers"])
	assert.Equal(t, []any{"header"}, res["bearer_methods_supported"])
	assert.True(t, strings.HasSuffix(res["resource"].(string), env.domain+"/"),
		res["resource"])

	assert.Equal(t, cnt, env.upstream.getReqCount())
}

func TestServerMCPLuaToolName(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{
		Plugins: []*corev1.Service_Spec_Config_MCP_Plugin{
			newMCPLuaPlugin("rewrite-name", corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH, `
function onRequest(ctx)
  local body = json.decode(octelium.req.getRequestBody())
  body["params"]["name"] = "delete-production"
  octelium.req.setRequestBody(json.encode(body))
end
`),
		},
	}, "")

	resp := env.postMCP(t, newMCPToolCallBody("read-report"))
	assert.True(t, resp.IsSuccess(), resp.String())

	params := env.upstream.getLastBodyMap()["params"].(map[string]any)
	assert.Equal(t, "delete-production", params["name"])

	res := map[string]any{}
	assert.Nil(t, json.Unmarshal(resp.Body(), &res))

	content := res["result"].(map[string]any)["content"].([]any)
	assert.Equal(t, "delete-production", content[0].(map[string]any)["text"])
}

func TestServerMCPLuaArguments(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{
		Plugins: []*corev1.Service_Spec_Config_MCP_Plugin{
			newMCPLuaPlugin("rewrite-args", corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH, `
function onRequest(ctx)
  local body = json.decode(octelium.req.getRequestBody())
  body["params"]["arguments"]["environment"] = "sandbox"
  body["params"]["arguments"]["injected"] = "octelium"
  octelium.req.setRequestBody(json.encode(body))
end
`),
		},
	}, "")

	resp := env.postMCP(t, newMCPToolCallBody("read-report"))
	assert.True(t, resp.IsSuccess(), resp.String())

	params := env.upstream.getLastBodyMap()["params"].(map[string]any)
	assert.Equal(t, "read-report", params["name"])

	args := params["arguments"].(map[string]any)
	assert.Equal(t, "sandbox", args["environment"])
	assert.Equal(t, "octelium", args["injected"])
}

func TestServerMCPLuaAuthorization(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.authz = &corev1.Service_Spec_Authorization{
		InlinePolicies: []*corev1.InlinePolicy{
			{
				Spec: &corev1.Policy_Spec{
					Rules: []*corev1.Policy_Spec_Rule{
						{
							Name:     "deny-delete-production",
							Priority: 0,
							Effect:   corev1.Policy_Spec_Rule_DENY,
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `ctx.request.mcp.method == "tools/call" && ctx.request.mcp.name == "delete-production"`,
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

	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{
		Plugins: []*corev1.Service_Spec_Config_MCP_Plugin{
			newMCPLuaPlugin("rewrite-name", corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH, `
function onRequest(ctx)
  local body = json.decode(octelium.req.getRequestBody())
  if body["params"] ~= nil then
    body["params"]["name"] = "delete-production"
    octelium.req.setRequestBody(json.encode(body))
  end
end
`),
		},
	}, "")

	{
		cnt := env.upstream.getReqCount()

		resp := env.postMCP(t, newMCPToolCallBody("read-report"))
		assert.Equal(t, http.StatusForbidden, resp.StatusCode(), resp.String())

		assert.Equal(t, cnt, env.upstream.getReqCount())
	}

	{
		resp := env.postMCP(t, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "tools/list",
		})
		assert.True(t, resp.IsSuccess(), resp.String())
	}
}

func TestServerMCPLuaPostAuth(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.authz = &corev1.Service_Spec_Authorization{
		InlinePolicies: []*corev1.InlinePolicy{
			{
				Spec: &corev1.Policy_Spec{
					Rules: []*corev1.Policy_Spec_Rule{
						{
							Name:     "deny-delete-production",
							Priority: 0,
							Effect:   corev1.Policy_Spec_Rule_DENY,
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `ctx.request.mcp.name == "delete-production"`,
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

	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{
		Plugins: []*corev1.Service_Spec_Config_MCP_Plugin{
			newMCPLuaPlugin("rewrite-name", corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH, `
function onRequest(ctx)
  local body = json.decode(octelium.req.getRequestBody())
  body["params"]["name"] = "delete-production"
  octelium.req.setRequestBody(json.encode(body))
end
`),
		},
	}, "")

	resp := env.postMCP(t, newMCPToolCallBody("read-report"))
	assert.True(t, resp.IsSuccess(), resp.String())

	params := env.upstream.getLastBodyMap()["params"].(map[string]any)
	assert.Equal(t, "delete-production", params["name"])
}

func TestServerMCPLuaResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env := newMCPEnv(t, ctx)
	env.start(t, ctx, &corev1.Service_Spec_Config_MCP{
		Plugins: []*corev1.Service_Spec_Config_MCP_Plugin{
			newMCPLuaPlugin("rewrite-response", corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH, `
function onResponse(ctx)
  local body = json.decode(octelium.req.getResponseBody())
  body["result"]["content"][1]["text"] = "redacted-by-octelium"
  octelium.req.setResponseBody(json.encode(body))
end
`),
		},
	}, "")

	resp := env.postMCP(t, newMCPToolCallBody("read-report"))
	assert.True(t, resp.IsSuccess(), resp.String())

	res := map[string]any{}
	assert.Nil(t, json.Unmarshal(resp.Body(), &res))

	content := res["result"].(map[string]any)["content"].([]any)
	assert.Equal(t, "redacted-by-octelium", content[0].(map[string]any)["text"])
}
