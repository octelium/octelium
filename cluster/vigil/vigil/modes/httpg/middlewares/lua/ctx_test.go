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

package lua

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	lua "github.com/yuin/gopher-lua"
)

func TestLuaCtx(t *testing.T) {

	// ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})

	mdlwr := &middleware{
		next: next,
		cMap: make(map[string]*lua.FunctionProto),
	}

	fnProto, err := mdlwr.doGetAndSetLuaFnProto(`
function onRequest(ctx)
  octelium.req.setRequestHeader("X-Lua-Header", "octelium")
  octelium.req.setRequestHeader("X-User-Uid", ctx.user.metadata.uid)
  octelium.req.setRequestBody("octelium:"..octelium.req.getRequestBody())
  octelium.req.deleteRequestHeader("X-Delete")
  if octelium.req.getQueryParam("type") == "octelium" then
    octelium.req.setPath("/users/"..ctx.user.metadata.uid)
    octelium.req.setQueryParam("user", ctx.user.metadata.uid)
    octelium.req.deleteQueryParam("type")
  end
end

function onResponse(ctx)
  octelium.req.setResponseHeader("X-Resp", ctx.user.metadata.uid)
  octelium.req.setResponseBody("octelium:"..octelium.req.getResponseBody())
  octelium.req.setStatusCode(205)
end
`)
	assert.Nil(t, err)

	reqCtx := &corev1.RequestContext{
		User: &corev1.User{
			Metadata: &metav1.Metadata{
				Uid: vutils.UUIDv4(),
			},
		},
	}
	reqCtxMap := pbutils.MustConvertToMap(reqCtx)

	bodyReq := utilrand.GetRandomString(32)
	bodyResp := utilrand.GetRandomString(32)

	rw := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost,
		"http://localhost/prefix/v1?type=octelium", bytes.NewBuffer([]byte(bodyReq)))
	req.Header.Set("X-Delete", "octelium")

	req = req.WithContext(context.WithValue(context.Background(),
		middlewares.CtxRequestContext, &middlewares.RequestContext{
			CreatedAt: time.Now()}))

	luaCtx, err := newCtx(&newCtxOpts{
		req:       req,
		fnProto:   fnProto,
		reqCtxMap: reqCtxMap,
		rw:        newResponseWriter(rw),
	})
	assert.Nil(t, err)

	luaCtx.rw.body.Write([]byte(bodyResp))

	{
		globalTable := luaCtx.state.Get(lua.GlobalsIndex).(*lua.LTable)

		globalTable.ForEach(func(key, value lua.LValue) {
			keyStr := key.String()
			valueStr := value.String()
			fmt.Printf("  Key: %-20s Value: %s (Type: %s)\n", keyStr, valueStr, value.Type().String())
		})
	}

	{
		err = luaCtx.callOnRequest()
		assert.Nil(t, err)

		assert.Equal(t, reqCtx.User.Metadata.Uid, luaCtx.req.Header.Get("X-User-Uid"))
		defer luaCtx.req.Body.Close()
		reqBody, err := io.ReadAll(luaCtx.req.Body)
		assert.Nil(t, err)

		expectedBody := fmt.Sprintf("octelium:%s", bodyReq)
		assert.Equal(t, expectedBody, string(reqBody))
		assert.Equal(t, int64(len([]byte(expectedBody))), luaCtx.req.ContentLength)
		assert.Equal(t, fmt.Sprintf("/users/%s", reqCtx.User.Metadata.Uid), luaCtx.req.URL.Path)
		assert.Equal(t, reqCtx.User.Metadata.Uid, luaCtx.req.URL.Query().Get("user"))
		assert.Equal(t, "", luaCtx.req.URL.Query().Get("type"))
		assert.Equal(t, "", luaCtx.req.Header.Get("X-Delete"))

		assert.Equal(t,
			fmt.Sprintf("/users/%s?user=%s", reqCtx.User.Metadata.Uid, reqCtx.User.Metadata.Uid),
			luaCtx.req.URL.RequestURI())
	}

	{
		err = luaCtx.callOnResponse()
		assert.Nil(t, err)

		assert.Equal(t, reqCtx.User.Metadata.Uid, luaCtx.rw.Header().Get("X-Resp"))

		expectedBody := fmt.Sprintf("octelium:%s", bodyResp)
		assert.Equal(t, expectedBody, luaCtx.rw.body.String())
		assert.Equal(t, 205, luaCtx.rw.statusCode)
	}

}

func TestLuaModuleBindings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
		fail   bool
	}{
		{"Base64", `assert(base64.decode(base64.encode("hello\000world")) == "hello\000world")`, false},
		{"Base64URL", `assert(base64.encodeURL("\255\255") == "__8="); assert(base64.decodeURL("__8=") == "\255\255")`, false},
		{"StringCase", `assert(strings.upper("café") == "CAFÉ"); assert(strings.lower("CAFÉ") == "café"); assert(strings.toUpper("a") == "A"); assert(strings.toLower("A") == "a")`, false},
		{"StringPredicates", `assert(strings.hasPrefix("abc", "a")); assert(strings.hasSuffix("abc", "c")); assert(strings.contains("abc", "b")); assert(strings.containsAny("abc", "xzbc")); assert(strings.count("banana", "an") == 2)`, false},
		{"StringTrimming", `assert(strings.trimSpace("  value\n") == "value"); assert(strings.trim("-value-", "-") == "value"); assert(strings.trimPrefix("prefix-value", "prefix-") == "value"); assert(strings.trimSuffix("value.txt", ".txt") == "value")`, false},
		{"StringReplacement", `assert(strings.replace("aaa", "a", "b", 2) == "bba"); assert(strings.replaceAll("aaa", "a", "b") == "bbb")`, false},
		{"StringSplitJoin", `assert(strings.join(strings.split("a,b,c", ","), ":") == "a:b:c"); assert(strings.compare("a", "b") == -1); assert(strings.index("abc", "b") == 1); assert(strings.index("abc", "z") == -1)`, false},
		{"StringUnicode", `assert(strings.len("é😀") == 6); assert(strings.lenUnicode("é😀") == 2); assert(strings.truncateUnicode("é😀x", 2) == "é😀"); assert(strings.truncate("abcdef", 3) == "abc"); assert(strings.truncate("abc", 10) == "abc")`, false},
		{"StringEmptyTruncate", `assert(strings.truncate("abc", 0) == ""); assert(strings.truncateUnicode("é", 0) == "")`, false},
		{"TableInsertRemove", `local t = {}; table.insert(t, "b"); table.insert(t, 1, "a"); table.insert(t, "c"); assert(table.remove(t) == "c"); assert(table.remove(t, 1) == "a"); assert(t[1] == "b"); assert(#t == 1)`, false},
		{"TableEmptyRemove", `local t = {}; assert(table.remove(t) == nil)`, false},
		{"TableMissingValue", `table.insert({})`, true},
		{"StringWrongType", `strings.upper({})`, true},
		{"StringNegativeTruncate", `strings.truncate("abc", -1)`, true},
		{"StringNegativeUnicodeTruncate", `strings.truncateUnicode("é", -1)`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &middleware{cMap: make(map[string]*lua.FunctionProto)}
			fnProto, err := m.doGetAndSetLuaFnProto(tc.script)
			require.Nil(t, err)
			c, err := newCtx(&newCtxOpts{
				req: httptest.NewRequest(http.MethodGet, "/", nil), rw: newResponseWriter(httptest.NewRecorder()), fnProto: fnProto,
			})
			if tc.fail {
				assert.NotNil(t, err)
				return
			}
			require.Nil(t, err)
			defer c.close()
		})
	}
}

func TestJSON(t *testing.T) {
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	mdlwr := &middleware{
		next: next,
		cMap: make(map[string]*lua.FunctionProto),
	}

	fnProto, err := mdlwr.doGetAndSetLuaFnProto(`
function onRequest(ctx)
  local body = octelium.req.getRequestBody()
  local map = json.decode(body)
  map.user.metadata.name = "octelium"
  octelium.req.setRequestBody(json.encode(map))
end
`)
	assert.Nil(t, err)

	reqCtx := &corev1.RequestContext{
		User: &corev1.User{
			Metadata: &metav1.Metadata{
				Name: "root",
				Uid:  vutils.UUIDv4(),
			},
		},
	}
	reqCtxMap := pbutils.MustConvertToMap(reqCtx)

	reqCtxJSON, err := pbutils.MarshalJSON(reqCtx, false)
	assert.Nil(t, err)

	rw := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, "http://localhost/prefix/v1", bytes.NewBuffer(reqCtxJSON))
	req = req.WithContext(context.WithValue(context.Background(),
		middlewares.CtxRequestContext, &middlewares.RequestContext{
			CreatedAt: time.Now()}))

	luaCtx, err := newCtx(&newCtxOpts{
		req:       req,
		fnProto:   fnProto,
		reqCtxMap: reqCtxMap,
		rw:        newResponseWriter(rw),
	})
	assert.Nil(t, err)

	{
		err = luaCtx.callOnRequest()
		assert.Nil(t, err)

		defer luaCtx.req.Body.Close()
		reqBody, err := io.ReadAll(luaCtx.req.Body)
		assert.Nil(t, err)

		reqCtx2 := &corev1.RequestContext{}
		err = pbutils.UnmarshalJSON(reqBody, reqCtx2)
		assert.Nil(t, err)

		assert.Equal(t, "octelium", reqCtx2.User.Metadata.Name)
	}
}
