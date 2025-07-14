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

package table

import (
	lua "github.com/yuin/gopher-lua"
)

func Register(L *lua.LState) int {
	mod := L.RegisterModule("table", fns).(*lua.LTable)

	L.Push(mod)
	return 1
}

var fns = map[string]lua.LGFunction{
	"insert": doInsert,
	"remove": doRemove,
}

func doRemove(L *lua.LState) int {
	tbl := L.CheckTable(1)
	if L.GetTop() == 1 {
		L.Push(tbl.Remove(-1))
	} else {
		L.Push(tbl.Remove(L.CheckInt(2)))
	}
	return 1
}

func doInsert(L *lua.LState) int {
	tbl := L.CheckTable(1)
	nargs := L.GetTop()
	if nargs == 1 {
		L.RaiseError("wrong number of arguments")
	}

	if L.GetTop() == 2 {
		tbl.Append(L.Get(2))
		return 0
	}
	tbl.Insert(int(L.CheckInt(2)), L.CheckAny(3))
	return 0
}
