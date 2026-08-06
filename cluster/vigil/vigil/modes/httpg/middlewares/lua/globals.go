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
	"strconv"
	"strings"

	lua "github.com/yuin/gopher-lua"
	"go.uber.org/zap"
)

// Most fns here are from github.com/yuin/gopher-lua/blob/master/baselib.go
// Without having to load the entire base module

const maxPrintLen = 1024

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
	parts := make([]string, 0, top)
	for i := 1; i <= top; i++ {
		parts = append(parts, L.ToStringMeta(L.Get(i)).String())
	}

	msg := strings.Join(parts, "\t")
	if len(msg) > maxPrintLen {
		msg = msg[:maxPrintLen] + "...[truncated]"
	}

	zap.L().Debug("lua print: " + msg)
	return 0
}

func doGlobalFnPCall(L *lua.LState) int {
	L.CheckAny(1)
	v := L.Get(1)
	if v.Type() != lua.LTFunction && L.GetMetaField(v, "__call").Type() != lua.LTFunction {
		L.Push(lua.LFalse)
		L.Push(lua.LString("attempt to call a " + v.Type().String() + " value"))
		return 2
	}

	nargs := L.GetTop() - 1
	if err := L.PCall(nargs, lua.MultRet, nil); err != nil {
		L.Push(lua.LFalse)
		if aerr, ok := err.(*lua.ApiError); ok {
			L.Push(aerr.Object)
		} else {
			L.Push(lua.LString(err.Error()))
		}
		return 2
	}

	L.Insert(lua.LTrue, 1)
	return L.GetTop()
}

func doGlobalFnToString(L *lua.LState) int {
	L.Push(L.ToStringMeta(L.CheckAny(1)))
	return 1
}

func doGlobalFnToNumber(L *lua.LState) int {
	base := L.OptInt(2, 10)
	noBase := L.Get(2) == lua.LNil

	switch lv := L.CheckAny(1).(type) {
	case lua.LNumber:
		L.Push(lv)
	case lua.LString:
		str := strings.Trim(string(lv), " \n\t")
		if strings.Contains(str, ".") {
			if v, err := strconv.ParseFloat(str, lua.LNumberBit); err != nil {
				L.Push(lua.LNil)
			} else {
				L.Push(lua.LNumber(v))
			}
		} else {
			if noBase && strings.HasPrefix(strings.ToLower(str), "0x") {
				base, str = 16, str[2:]
			}
			if v, err := strconv.ParseInt(str, base, lua.LNumberBit); err != nil {
				L.Push(lua.LNil)
			} else {
				L.Push(lua.LNumber(v))
			}
		}
	default:
		L.Push(lua.LNil)
	}

	return 1
}

func doGlobalFnSelect(L *lua.LState) int {
	L.CheckTypes(1, lua.LTNumber, lua.LTString)
	switch lv := L.Get(1).(type) {
	case lua.LNumber:
		idx := int(lv)
		num := L.GetTop()
		if idx < 0 {
			idx = num + idx
		} else if idx > num {
			idx = num
		}
		if 1 > idx {
			L.ArgError(1, "index out of range")
		}
		return num - idx
	case lua.LString:
		if string(lv) != "#" {
			L.ArgError(1, "invalid string '"+string(lv)+"'")
		}
		L.Push(lua.LNumber(L.GetTop() - 1))
		return 1
	}
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
	i := L.CheckInt(2) + 1
	v := tb.RawGetInt(i)
	if v == lua.LNil {
		return 0
	}
	L.Push(lua.LNumber(i))
	L.Push(v)
	return 2
}

func pairsaux(L *lua.LState) int {
	tb := L.CheckTable(1)
	key, value := tb.Next(L.Get(2))
	if key == lua.LNil {
		return 0
	}
	L.Push(key)
	L.Push(value)
	return 2
}
