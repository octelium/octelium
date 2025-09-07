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

	lua "github.com/yuin/gopher-lua"
)

// Most fns here are from github.com/yuin/gopher-lua/blob/master/baselib.go
// Without having to load the entire base module

func doGlobalFnAssert(L *lua.LState) int {
	if !L.ToBool(1) {
		L.RaiseError("assertion failed")
		return 0
	}
	return L.GetTop()
}

func doGlobalFnError(L *lua.LState) int {
	obj := L.CheckAny(1)
	level := L.OptInt(2, 1)
	L.Error(obj, level)
	return 0
}

func doGlobalFnPrint(L *lua.LState) int {
	top := L.GetTop()
	for i := 1; i <= top; i++ {
		fmt.Print(L.ToStringMeta(L.Get(i)).String())
		if i != top {
			fmt.Print("\t")
		}
	}
	fmt.Println("")
	return 0
}

func doIpairs(L *lua.LState) int {
	tb := L.CheckTable(1)
	L.Push(L.Get(lua.UpvalueIndex(1)))
	L.Push(tb)
	L.Push(lua.LNumber(0))
	return 3
}

func doPairs(L *lua.LState) int {
	tb := L.CheckTable(1)
	L.Push(L.Get(lua.UpvalueIndex(1)))
	L.Push(tb)
	L.Push(lua.LNil)
	return 3
}

func doGlobalFnType(L *lua.LState) int {
	L.Push(lua.LString(L.CheckAny(1).Type().String()))
	return 1
}

func ipairsaux(L *lua.LState) int {
	tb := L.CheckTable(1)
	i := L.CheckInt(2)
	i++
	v := tb.RawGetInt(i)
	if v == lua.LNil {
		return 0
	} else {
		L.Pop(1)
		L.Push(lua.LNumber(i))
		L.Push(lua.LNumber(i))
		L.Push(v)
		return 2
	}
}

func pairsaux(L *lua.LState) int {
	tb := L.CheckTable(1)
	key, value := tb.Next(L.Get(2))
	if key == lua.LNil {
		return 0
	} else {
		L.Pop(1)
		L.Push(key)
		L.Push(key)
		L.Push(value)
		return 2
	}
}
