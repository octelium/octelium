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
	"regexp"

	lua "github.com/yuin/gopher-lua"
)

func Register(L *lua.LState) int {
	mod := L.RegisterModule("regexp", fns).(*lua.LTable)

	regexp_regexp_ud := L.NewTypeMetatable(`regexp_regexp_ud`)
	L.SetGlobal(`regexp_regexp_ud`, regexp_regexp_ud)
	L.SetField(regexp_regexp_ud, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"match":                 doRegexpMatch,
		"findAllStringSubmatch": doFindAllStringSubmatch,
		"replaceAll":            doReplaceAll,
	}))

	L.Push(mod)

	return 1
}

var fns = map[string]lua.LGFunction{
	"compile": doCompile,
	"match":   doMatch,
}

func doCompile(L *lua.LState) int {
	rgx, err := regexp.Compile(L.CheckString(1))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	ud := L.NewUserData()
	ud.Value = rgx
	L.SetMetatable(ud, L.GetTypeMetatable("regexp_regexp_ud"))
	L.Push(ud)

	return 1
}

func doMatch(L *lua.LState) int {

	isMatched, err := regexp.MatchString(L.CheckString(1), L.CheckString(2))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LBool(isMatched))
	return 1
}

func checkRegexp(L *lua.LState) *regexp.Regexp {
	ud := L.CheckUserData(1)
	if v, ok := ud.Value.(*regexp.Regexp); ok {
		return v
	}
	L.ArgError(1, "invalid regexp")
	return nil
}

func doRegexpMatch(L *lua.LState) int {

	rgx := checkRegexp(L)

	L.Push(lua.LBool(rgx.MatchString(L.CheckString(2))))
	return 1
}

func doFindAllStringSubmatch(L *lua.LState) int {
	reg := checkRegexp(L)
	result := L.NewTable()

	for _, t := range reg.FindAllStringSubmatch(L.CheckString(2), -1) {
		row := L.NewTable()
		for _, v := range t {
			row.Append(lua.LString(v))
		}
		result.Append(row)
	}
	L.Push(result)
	return 1
}

func doReplaceAll(L *lua.LState) int {
	reg := checkRegexp(L)
	L.Push(lua.LString(reg.ReplaceAllString(L.CheckString(2), L.CheckString(3))))
	return 1
}
