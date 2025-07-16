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

package regexp

import (
	"testing"

	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
	lua "github.com/yuin/gopher-lua"
)

func TestModule(t *testing.T) {
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
		L.Push(lua.LString("regexp"))
		L.Call(1, 0)
	}

	{
		err = L.DoString(`
local match, err = regexp.match("cai.*", "cairo")
if err then
  return 0
end

if not match then
  return 0
end

return 1
`)
		assert.Nil(t, err, "%+v", err)
		code := L.ToInt(-1)
		assert.Equal(t, 1, code)

	}

	{
		err = L.DoString(`
local rgx, err = regexp.compile("cai.*")
if err then
  return 0
end

if not rgx:match("cairo") then
  return 0
end

if rgx:match("new york") then
  return 0
end

local res = rgx:findAllStringSubmatch("cairo chai")

if #res ~= 1 then
  return 0
end

return 1
`)
		assert.Nil(t, err, "%+v", err)
		code := L.ToInt(-1)
		assert.Equal(t, 1, code)

	}
}
