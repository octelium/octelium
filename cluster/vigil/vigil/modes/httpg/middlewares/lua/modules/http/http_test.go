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

package http

import (
	"testing"

	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
	lua "github.com/yuin/gopher-lua"
)

func TestHTTP(t *testing.T) {
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	L := lua.NewState(lua.Options{
		SkipOpenLibs: true,
	})

	{
		L.Push(L.NewFunction(Register))
		L.Push(lua.LString("http"))
		L.Call(1, 0)
	}

	err = L.DoString(`
local c = http.client()
local req = c:request()
local resp, err = req:get("https://www.google.com")
if err then
  error(err)
end

return resp:body(), resp:code()
`)

	assert.Nil(t, err)

	code := L.ToInt(-1)
	body := L.ToString(-2)

	assert.Equal(t, 200, code)
	assert.True(t, len(body) > 0)
}
