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
	lua "github.com/yuin/gopher-lua"
)

func toLuaValue(L *lua.LState, goValue any) lua.LValue {
	switch v := goValue.(type) {
	case nil:
		return lua.LNil
	case bool:
		return lua.LBool(v)
	case int:
		return lua.LNumber(v)
	case int32:
		return lua.LNumber(v)
	case int64:
		return lua.LNumber(v)
	case uint32:
		return lua.LNumber(v)
	case uint64:
		return lua.LNumber(v)
	case float32:
		return lua.LNumber(v)
	case float64:
		return lua.LNumber(v)
	case string:
		return lua.LString(v)
	case []byte:
		return lua.LString(string(v))
	case byte:
		return lua.LString(string(v))
	case map[string]any:
		return convertMapToLuaTable(L, v)
	case []any:
		return convertSliceToLuaTable(L, v)
	default:
		return lua.LNil
	}
}

func convertMapToLuaTable(L *lua.LState, goMap map[string]any) *lua.LTable {
	luaTable := L.NewTable()
	for key, value := range goMap {
		luaTable.RawSetString(key, toLuaValue(L, value))
	}
	return luaTable
}

func convertSliceToLuaTable(L *lua.LState, goSlice []any) *lua.LTable {
	luaTable := L.NewTable()
	for i, value := range goSlice {
		luaTable.RawSetInt(i+1, toLuaValue(L, value))
	}
	return luaTable
}

func toGoValue(lv lua.LValue) any {
	switch lv.Type() {
	case lua.LTNil:
		return nil
	case lua.LTBool:
		return bool(lv.(lua.LBool))
	case lua.LTNumber:
		num := float64(lv.(lua.LNumber))
		if num == float64(int(num)) {
			return int(num)
		}

		return num
	case lua.LTString:
		return string(lv.(lua.LString))
	case lua.LTTable:
		return convertLuaTableToGoMapOrSlice(lv.(*lua.LTable))
	case lua.LTUserData:
		if ud, ok := lv.(*lua.LUserData); ok {
			return ud.Value
		}
		return nil
	default:
		return nil
	}
}

func convertLuaTableToGoMapOrSlice(lt *lua.LTable) any {
	isSlice := true
	maxIndex := 0
	lt.ForEach(func(key, value lua.LValue) {
		if numKey, ok := key.(lua.LNumber); ok {
			if int(numKey) > maxIndex {
				maxIndex = int(numKey)
			}
		} else {
			isSlice = false
		}
	})

	if lt.Len() < 1 {
		isSlice = false
	}

	if isSlice {
		sliceValues := make([]any, maxIndex)
		allConsecutive := true
		for i := 1; i <= maxIndex; i++ {
			val := lt.RawGetInt(i)
			if val.Type() == lua.LTNil {
				allConsecutive = false
				break
			}
			sliceValues[i-1] = toGoValue(val)
		}
		if allConsecutive {
			return sliceValues
		}
	}

	goMap := make(map[string]any)
	lt.ForEach(func(key, value lua.LValue) {
		if key.Type() == lua.LTString {
			goMap[key.String()] = toGoValue(value)
		}
	})

	return goMap
}
