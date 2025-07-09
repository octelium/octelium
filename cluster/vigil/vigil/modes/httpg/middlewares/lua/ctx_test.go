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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/octelium/octelium/cluster/common/tests"
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
function on_request()
  set_request_header("X-Lua-Header", "octelium")
end`)
	assert.Nil(t, err)

	luaCtx, err := newCtx(&newCtxOpts{
		req:     httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil),
		fnProto: fnProto,
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
}
