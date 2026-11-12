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

package commonplugin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestShouldEnforcePlugin(t *testing.T) {

	ctx := context.Background()

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	newCtx := func(meta string) context.Context {
		return context.WithValue(ctx, middlewares.CtxRequestContext, &middlewares.RequestContext{
			CreatedAt: time.Now(),
			ReqCtxMap: map[string]any{
				"request": map[string]any{
					"http": map[string]any{
						"headers": map[string]any{
							"x-meta": meta,
						},
					},
				},
			},
		})
	}

	newPlugin := func(isDisabled bool, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) *corev1.Service_Spec_Config_HTTP_Plugin {
		return &corev1.Service_Spec_Config_HTTP_Plugin{
			Name:       "plugin",
			IsDisabled: isDisabled,
			Phase:      phase,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: `json.parse(ctx.request.http.headers["x-meta"]).priority > 5.0`,
				},
			},
		}
	}

	for _, tst := range []struct {
		meta       string
		plugin     *corev1.Service_Spec_Config_HTTP_Plugin
		isEnforced bool
		ok         bool
	}{
		{`{"priority": 10}`, newPlugin(false, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH), true, true},
		{`{"priority": 1}`, newPlugin(false, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH), false, true},
		{"abc", newPlugin(false, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH), false, false},
		{"abc", newPlugin(false, corev1.Service_Spec_Config_HTTP_Plugin_PHASE_UNSET), false, false},
		{"abc", newPlugin(true, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH), false, true},
		{"abc", newPlugin(false, corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH), false, true},
	} {
		rw := httptest.NewRecorder()

		isEnforced, ok := ShouldEnforcePlugin(newCtx(tst.meta), rw, &ShouldEnforcePluginOpts{
			Plugin:    tst.plugin,
			CELEngine: celEngine,
			Phase:     corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH,
		})

		assert.Equal(t, tst.isEnforced, isEnforced, tst.meta)
		assert.Equal(t, tst.ok, ok, tst.meta)

		if tst.ok {
			assert.False(t, rw.Flushed)
			assert.Equal(t, 0, rw.Body.Len())
		} else {
			assert.Equal(t, http.StatusInternalServerError, rw.Code)
			assert.Equal(t, "octelium", rw.Header().Get("Server"))
			assert.Contains(t, rw.Body.String(), "could not evaluate the Plugins")
		}
	}
}

func TestShouldEnforcePluginBodyOmitted(t *testing.T) {

	ctx := context.Background()

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	bodyMap, err := structpb.NewStruct(map[string]any{"action": "delete"})
	assert.Nil(t, err)

	newCtx := func(isBodyOmitted bool, typ string) context.Context {
		httpC := &corev1.RequestContext_Request_HTTP{Path: "/", IsBodyOmitted: isBodyOmitted}
		if !isBodyOmitted {
			httpC.BodyMap = bodyMap
		}

		req := &corev1.RequestContext_Request{}
		switch typ {
		case "llm":
			req.Type = &corev1.RequestContext_Request_Llm{Llm: &corev1.RequestContext_Request_LLM{Http: httpC}}
		case "mcp":
			req.Type = &corev1.RequestContext_Request_Mcp{Mcp: &corev1.RequestContext_Request_MCP{Http: httpC}}
		default:
			req.Type = &corev1.RequestContext_Request_Http{Http: httpC}
		}

		return context.WithValue(ctx, middlewares.CtxRequestContext, &middlewares.RequestContext{
			CreatedAt:      time.Now(),
			DownstreamInfo: &corev1.RequestContext{Request: req},
		})
	}

	newPlugin := func(isDisabled bool, condition string) *corev1.Service_Spec_Config_HTTP_Plugin {
		return &corev1.Service_Spec_Config_HTTP_Plugin{
			Name:       "plugin",
			IsDisabled: isDisabled,
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: condition,
				},
			},
		}
	}

	for _, tst := range []struct {
		isBodyOmitted bool
		typ           string
		plugin        *corev1.Service_Spec_Config_HTTP_Plugin
		isEnforced    bool
		ok            bool
	}{
		{false, "http", newPlugin(false, `ctx.request.http.bodyMap.action == "delete"`), true, true},
		{true, "http", newPlugin(false, `ctx.request.http.bodyMap.action == "delete"`), false, false},
		{false, "http", newPlugin(false, `ctx.request.http.bodyMap.action != "delete"`), false, true},
		{true, "http", newPlugin(false, `ctx.request.http.bodyMap.action != "delete"`), false, false},
		{true, "http", newPlugin(false, `has(ctx.request.http.body)`), false, false},
		{false, "llm", newPlugin(false, `ctx.request.llm.http.bodyMap.action == "delete"`), true, true},
		{true, "llm", newPlugin(false, `ctx.request.llm.http.bodyMap.action == "delete"`), false, false},
		{false, "mcp", newPlugin(false, `ctx.request.mcp.http.bodyMap.action == "delete"`), true, true},
		{true, "mcp", newPlugin(false, `ctx.request.mcp.http.bodyMap.action == "delete"`), false, false},
		{true, "http", newPlugin(false, `ctx.request.http.path == "/"`), true, true},
		{true, "http", newPlugin(false, `ctx.request.http.isBodyOmitted`), true, true},
		{true, "http", newPlugin(true, `ctx.request.http.bodyMap.action == "delete"`), false, true},
	} {
		rw := httptest.NewRecorder()

		isEnforced, ok := ShouldEnforcePlugin(newCtx(tst.isBodyOmitted, tst.typ), rw, &ShouldEnforcePluginOpts{
			Plugin:    tst.plugin,
			CELEngine: celEngine,
			Phase:     corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH,
		})

		assert.Equal(t, tst.isEnforced, isEnforced, "%+v", tst)
		assert.Equal(t, tst.ok, ok, "%+v", tst)

		if tst.ok {
			assert.Equal(t, 0, rw.Body.Len())
		} else {
			assert.Equal(t, http.StatusInternalServerError, rw.Code)
			assert.Contains(t, rw.Body.String(), "could not evaluate the Plugins")
		}
	}
}
