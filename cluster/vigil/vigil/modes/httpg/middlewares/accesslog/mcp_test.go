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

package accesslog

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
)

const mcpReqBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
	`"params":{"name":"add","arguments":{"secret":"s3cr3t"}}}`

const mcpRespBody = `{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete"}}`

func newMCPReqCtx(t *testing.T,
	cfg *corev1.Service_Spec_Config_MCP) *middlewares.RequestContext {

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "my-mcp.default",
			Uid:  "d3d0d2a2-0000-0000-0000-000000000001",
		},
		Spec: &corev1.Service_Spec{
			Mode:     corev1.Service_Spec_MCP,
			IsPublic: true,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "default"},
		},
	}

	return &middlewares.RequestContext{
		CreatedAt: time.Now(),
		Service:   svc,
		ServiceConfig: &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Mcp{Mcp: cfg},
		},
		Body: []byte(mcpReqBody),
		MCP:  httputils.ParseMCPRequest(nil, []byte(mcpReqBody)),
		DownstreamInfo: &corev1.RequestContext{
			Service: svc,
		},
		DownstreamRequest: &coctovigilv1.DownstreamRequest{
			Source: &coctovigilv1.DownstreamRequest_Source{
				Address: "127.0.0.1",
				Port:    12345,
			},
			Request: &corev1.RequestContext_Request{
				Type: &corev1.RequestContext_Request_Mcp{
					Mcp: &corev1.RequestContext_Request_MCP{},
				},
			},
		},
	}
}

func serveMCPLog(t *testing.T,
	cfg *corev1.Service_Spec_Config_MCP) *corev1.AccessLog_Entry_Info_HTTP {

	reqCtx := newMCPReqCtx(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "http://my-mcp.example.com/mcp",
		strings.NewReader(mcpReqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-client/1.0")
	req.Header.Set("X-Secret-Thing", "s3cr3t")

	rw := httptest.NewRecorder()
	crw := newResponseWriter(rw, streamKindMCP)
	crw.Header().Set("Content-Type", "application/json")
	crw.Header().Set("X-Upstream-Thing", "value")
	_, err := crw.Write([]byte(mcpRespBody))
	assert.Nil(t, err)

	md := &middleware{}
	logE := md.getMCPAccessLog(req, crw, reqCtx, &mcpObserver{}, logPhaseComplete, "", 0)
	assert.NotNil(t, logE)

	return logE.Entry.Info.GetMcp().GetHttp()
}

func TestMCPVisibility(t *testing.T) {

	{
		httpC := serveMCPLog(t, &corev1.Service_Spec_Config_MCP{})

		assert.Equal(t, mcpReqBody, string(httpC.Request.Body))
		assert.NotNil(t, httpC.Request.BodyMap)
		assert.Equal(t, mcpRespBody, string(httpC.Response.Body))
		assert.NotNil(t, httpC.Response.BodyMap)

		assert.Empty(t, httpC.Request.Headers)
		assert.Empty(t, httpC.Response.Headers)
	}

	{
		httpC := serveMCPLog(t, &corev1.Service_Spec_Config_MCP{
			Visibility: &corev1.Service_Spec_Config_MCP_Visibility{
				DisableRequestBody: true,
			},
		})

		assert.Nil(t, httpC.Request.Body)
		assert.Nil(t, httpC.Request.BodyMap)
		assert.Equal(t, mcpRespBody, string(httpC.Response.Body))
		assert.NotNil(t, httpC.Response.BodyMap)
	}

	{
		httpC := serveMCPLog(t, &corev1.Service_Spec_Config_MCP{
			Visibility: &corev1.Service_Spec_Config_MCP_Visibility{
				DisableResponseBody: true,
			},
		})

		assert.Equal(t, mcpReqBody, string(httpC.Request.Body))
		assert.Nil(t, httpC.Response.Body)
		assert.Nil(t, httpC.Response.BodyMap)
	}

	{
		httpC := serveMCPLog(t, &corev1.Service_Spec_Config_MCP{
			Visibility: &corev1.Service_Spec_Config_MCP_Visibility{
				DisableRequestBody:  true,
				DisableResponseBody: true,
			},
		})

		assert.Nil(t, httpC.Request.Body)
		assert.Nil(t, httpC.Request.BodyMap)
		assert.Nil(t, httpC.Response.Body)
		assert.Nil(t, httpC.Response.BodyMap)
	}

	{
		httpC := serveMCPLog(t, &corev1.Service_Spec_Config_MCP{
			Visibility: &corev1.Service_Spec_Config_MCP_Visibility{
				IncludeRequestHeaders:  []string{"User-Agent"},
				IncludeResponseHeaders: []string{"X-Upstream-Thing"},
			},
		})

		assert.Equal(t, "test-client/1.0", httpC.Request.Headers["User-Agent"])
		assert.Empty(t, httpC.Request.Headers["X-Secret-Thing"])
		assert.Equal(t, "value", httpC.Response.Headers["X-Upstream-Thing"])
	}

	{
		httpC := serveMCPLog(t, &corev1.Service_Spec_Config_MCP{
			Visibility: &corev1.Service_Spec_Config_MCP_Visibility{
				IncludeAllRequestHeaders: true,
				ExcludeRequestHeaders:    []string{"X-Secret-Thing"},
			},
		})

		assert.Equal(t, "test-client/1.0", httpC.Request.Headers["user-agent"])
		assert.Empty(t, httpC.Request.Headers["x-secret-thing"])
	}
}

func TestMCPErrorMessageVisibility(t *testing.T) {

	getErrMsg := func(cfg *corev1.Service_Spec_Config_MCP) string {
		reqCtx := newMCPReqCtx(t, cfg)

		req := httptest.NewRequest(http.MethodPost, "http://my-mcp.example.com/mcp",
			strings.NewReader(mcpReqBody))

		crw := newResponseWriter(httptest.NewRecorder(), streamKindMCP)
		obs := &mcpObserver{}
		obs.onFinalBody([]byte(
			`{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"secret detail"}}`))

		md := &middleware{}
		logE := md.getMCPAccessLog(req, crw, reqCtx, obs, logPhaseComplete, "", 0)
		assert.NotNil(t, logE)

		return logE.Entry.Info.GetMcp().ErrorMessage
	}

	assert.Equal(t, "secret detail", getErrMsg(&corev1.Service_Spec_Config_MCP{}))

	assert.Equal(t, "", getErrMsg(&corev1.Service_Spec_Config_MCP{
		Visibility: &corev1.Service_Spec_Config_MCP_Visibility{
			DisableResponseBody: true,
		},
	}))
}
