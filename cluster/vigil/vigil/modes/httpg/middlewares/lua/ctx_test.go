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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/stretchr/testify/assert"
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
function on_request(ctx)
  set_request_header("X-Lua-Header", "octelium")
  set_request_header("X-User-Uid", ctx.user.metadata.uid)
  set_request_body(ctx.user.metadata.uid)
end`)
	assert.Nil(t, err)

	reqCtx := &corev1.RequestContext{
		User: &corev1.User{
			Metadata: &metav1.Metadata{
				Uid: vutils.UUIDv4(),
			},
		},
	}
	reqCtxLVal := mdlwr.getRequestContextLValue(reqCtx)

	luaCtx, err := newCtx(&newCtxOpts{
		req:          httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil),
		fnProto:      fnProto,
		reqCtxLValue: reqCtxLVal,
	})
	assert.Nil(t, err)

	{
		globalTable := luaCtx.state.Get(lua.GlobalsIndex).(*lua.LTable)

		globalTable.ForEach(func(key, value lua.LValue) {
			keyStr := key.String()
			valueStr := value.String()
			fmt.Printf("  Key: %-20s Value: %s (Type: %s)\n", keyStr, valueStr, value.Type().String())
		})
	}

	err = luaCtx.callOnRequest()
	assert.Nil(t, err)

	assert.Equal(t, "octelium", luaCtx.req.Header.Get("X-Lua-Header"))
	assert.Equal(t, reqCtx.User.Metadata.Uid, luaCtx.req.Header.Get("X-User-Uid"))
	defer luaCtx.req.Body.Close()
	reqBody, err := io.ReadAll(luaCtx.req.Body)
	assert.Nil(t, err)

	assert.Equal(t, reqCtx.User.Metadata.Uid, string(reqBody))
	assert.Equal(t, int64(len([]byte(reqBody))), luaCtx.req.ContentLength)
}
