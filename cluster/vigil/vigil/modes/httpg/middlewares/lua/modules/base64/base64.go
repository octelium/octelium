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

package base64

import (
	"encoding/base64"

	lua "github.com/yuin/gopher-lua"
)

func Register(L *lua.LState) int {
	mod := L.RegisterModule("base64", fns).(*lua.LTable)

	L.Push(mod)
	return 1
}

var fns = map[string]lua.LGFunction{
	"encode":    doEncode,
	"decode":    doDecode,
	"encodeURL": doEncodeURL,
	"decodeURL": doDecodeURL,
}

func doEncode(L *lua.LState) int {
	L.Push(lua.LString(base64.StdEncoding.EncodeToString([]byte(L.Get(1).String()))))
	return 1
}

func doDecode(L *lua.LState) int {
	res, _ := base64.StdEncoding.DecodeString(L.Get(1).String())
	L.Push(lua.LString(res))
	return 1
}

func doEncodeURL(L *lua.LState) int {
	L.Push(lua.LString(base64.URLEncoding.EncodeToString([]byte(L.Get(1).String()))))
	return 1
}

func doDecodeURL(L *lua.LState) int {
	res, _ := base64.URLEncoding.DecodeString(L.Get(1).String())
	L.Push(lua.LString(res))
	return 1
}
