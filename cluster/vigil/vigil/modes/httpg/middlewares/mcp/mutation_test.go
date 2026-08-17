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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

const readReportBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
	`"params":{"name":"read-report","arguments":{"environment":"staging"}}}`

const deleteProductionBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call",` +
	`"params":{"name":"delete-production","arguments":{"environment":"production"}}}`

func newMutationRequest(t *testing.T, body string) (*http.Request, *middlewares.RequestContext) {

	req := httptest.NewRequest(http.MethodPost, "http://my-mcp.example.com/mcp",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	mcpReq := httputils.ParseMCPRequest(req, []byte(body))

	bodyMap := map[string]any{}
	assert.Nil(t, json.Unmarshal([]byte(body), &bodyMap))

	httpC := &corev1.RequestContext_Request_HTTP{
		Method: http.MethodPost,
		Path:   "/mcp",
		Body:   []byte(body),
	}
	httpC.BodyMap, _ = pbutils.MapToStruct(bodyMap)

	reqCtx := &middlewares.RequestContext{
		CreatedAt:     time.Now(),
		Service:       newService(),
		ServiceConfig: &corev1.Service_Spec_Config{},
		Body:          []byte(body),
		BodyJSONMap:   bodyMap,
		MCP:           mcpReq,
		DownstreamRequest: &coctovigilv1.DownstreamRequest{
			Request: &corev1.RequestContext_Request{
				Type: &corev1.RequestContext_Request_Mcp{
					Mcp: middlewares.GetMCPRequestContext(mcpReq, httpC),
				},
			},
		},
	}
	reqCtx.DownstreamInfo = &corev1.RequestContext{
		Request: reqCtx.DownstreamRequest.Request,
		Service: reqCtx.Service,
	}
	reqCtx.SetBodyDigest()

	req = req.WithContext(context.WithValue(req.Context(),
		middlewares.CtxRequestContext, reqCtx))

	return req, reqCtx
}

func setRequestBody(req *http.Request, reqCtx *middlewares.RequestContext, body string) {
	reqCtx.Body = []byte(body)
	req.Body = io.NopCloser(bytes.NewReader([]byte(body)))
	req.ContentLength = int64(len(body))
}

func TestRebuild(t *testing.T) {

	ctx := context.Background()

	{
		var isNext bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			isNext = true
		})

		mdlwr, err := NewRebuild(ctx, next)
		assert.Nil(t, err)

		req, reqCtx := newMutationRequest(t, readReportBody)
		assert.Equal(t, "read-report", reqCtx.MCP.GetName())

		setRequestBody(req, reqCtx, deleteProductionBody)

		mdlwr.ServeHTTP(httptest.NewRecorder(), req)

		assert.True(t, isNext)
		assert.Equal(t, "delete-production", reqCtx.MCP.GetName())

		mcpI := reqCtx.DownstreamRequest.Request.GetMcp()
		assert.Equal(t, "delete-production", mcpI.Name)
		assert.Equal(t, "tools/call", mcpI.Method)
		assert.Equal(t, deleteProductionBody, string(mcpI.Http.Body))

		params := mcpI.Http.BodyMap.Fields["params"].GetStructValue()
		assert.Equal(t, "delete-production", params.Fields["name"].GetStringValue())
		assert.Equal(t, "production",
			params.Fields["arguments"].GetStructValue().Fields["environment"].GetStringValue())

		reqCtxMap := reqCtx.ReqCtxMap["request"].(map[string]any)["mcp"].(map[string]any)
		assert.Equal(t, "delete-production", reqCtxMap["name"])
		assert.Equal(t, "tools/call", reqCtxMap["method"])

		assert.False(t, reqCtx.IsBodyChanged())
	}

	{
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		mdlwr, err := NewRebuild(ctx, next)
		assert.Nil(t, err)

		req, reqCtx := newMutationRequest(t, readReportBody)
		mcpI := reqCtx.DownstreamRequest.Request.GetMcp()

		mdlwr.ServeHTTP(httptest.NewRecorder(), req)

		assert.Same(t, mcpI, reqCtx.DownstreamRequest.Request.GetMcp())
		assert.Equal(t, "read-report", reqCtx.MCP.GetName())
	}
}

func TestMutationNonMCP(t *testing.T) {

	ctx := context.Background()

	var isNext bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isNext = true
	})

	mdlwr, err := NewRebuild(ctx, next)
	assert.Nil(t, err)

	req, reqCtx := newMutationRequest(t, readReportBody)
	reqCtx.Service.Spec.Mode = corev1.Service_Spec_HTTP
	setRequestBody(req, reqCtx, deleteProductionBody)

	mdlwr.ServeHTTP(httptest.NewRecorder(), req)

	assert.True(t, isNext)
	assert.Equal(t, "read-report", reqCtx.MCP.GetName())
}
