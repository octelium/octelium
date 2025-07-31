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

package strings

import (
	"strings"
	"unicode/utf8"

	lua "github.com/yuin/gopher-lua"
)

func Register(L *lua.LState) int {
	mod := L.RegisterModule("strings", fns).(*lua.LTable)

	L.Push(mod)
	return 1
}

var fns = map[string]lua.LGFunction{
	"upper":           doUpper,
	"toUpper":         doUpper,
	"lower":           doLower,
	"toLower":         doLower,
	"hasSuffix":       doHasSuffix,
	"hasPrefix":       doHasPrefix,
	"trimSpace":       doTrimSpace,
	"contains":        doContains,
	"containsAny":     doContainsAny,
	"count":           doCount,
	"replace":         doReplace,
	"replaceAll":      doReplaceAll,
	"split":           doSplit,
	"trim":            doTrim,
	"trimPrefix":      doTrimPrefix,
	"trimSuffix":      doTrimSuffix,
	"join":            doJoin,
	"compare":         doCompare,
	"len":             doLen,
	"lenUnicode":      doLenUnicode,
	"index":           doIndex,
	"truncate":        doTruncate,
	"truncateUnicode": doTruncateUnicode,
}

func doUpper(L *lua.LState) int {
	L.Push(lua.LString(strings.ToUpper((L.CheckString(1)))))
	return 1
}

func doLower(L *lua.LState) int {

	L.Push(lua.LString(strings.ToLower((L.CheckString(1)))))
	return 1
}

func doHasSuffix(L *lua.LState) int {
	L.Push(lua.LBool(strings.HasSuffix(L.CheckString(1), L.CheckString(2))))
	return 1
}

func doHasPrefix(L *lua.LState) int {
	L.Push(lua.LBool(strings.HasPrefix(L.CheckString(1), L.CheckString(2))))
	return 1
}

func doTrimSpace(L *lua.LState) int {
	L.Push(lua.LString(strings.TrimSpace((L.CheckString(1)))))
	return 1
}

func doContains(L *lua.LState) int {
	L.Push(lua.LBool(strings.Contains(L.CheckString(1), L.CheckString(2))))
	return 1
}

func doContainsAny(L *lua.LState) int {
	L.Push(lua.LBool(strings.ContainsAny(L.CheckString(1), L.CheckString(2))))
	return 1
}

func doCount(L *lua.LState) int {
	L.Push(lua.LNumber(strings.Count(L.CheckString(1), L.CheckString(2))))
	return 1
}

func doReplace(L *lua.LState) int {
	L.Push(lua.LString(strings.Replace(L.CheckString(1), L.CheckString(2), L.CheckString(3), L.CheckInt(4))))
	return 1
}

func doReplaceAll(L *lua.LState) int {
	L.Push(lua.LString(strings.ReplaceAll(L.CheckString(1), L.CheckString(2), L.CheckString(3))))
	return 1
}

func doSplit(L *lua.LState) int {
	parts := strings.Split(L.CheckString(1), L.CheckString(2))

	tbl := L.NewTable()
	for i, part := range parts {
		tbl.RawSetInt(i+1, lua.LString(part))
	}

	L.Push(tbl)

	return 1
}

func doTrim(L *lua.LState) int {
	L.Push(lua.LString(strings.Trim(L.CheckString(1), L.CheckString(2))))
	return 1
}

func doTrimPrefix(L *lua.LState) int {
	L.Push(lua.LString(strings.TrimPrefix(L.CheckString(1), L.CheckString(2))))
	return 1
}

func doTrimSuffix(L *lua.LState) int {
	L.Push(lua.LString(strings.TrimSuffix(L.CheckString(1), L.CheckString(2))))
	return 1
}

func doCompare(L *lua.LState) int {
	L.Push(lua.LNumber(strings.Compare(L.CheckString(1), L.CheckString(2))))
	return 1
}

func doLen(L *lua.LState) int {
	L.Push(lua.LNumber(len(L.CheckString(1))))
	return 1
}

func doLenUnicode(L *lua.LState) int {
	L.Push(lua.LNumber(utf8.RuneCountInString(L.CheckString(1))))
	return 1
}

func doJoin(L *lua.LState) int {
	tbl := L.CheckTable(1)

	var parts []string

	tbl.ForEach(func(i lua.LValue, v lua.LValue) {
		if s, ok := v.(lua.LString); ok {
			parts = append(parts, string(s))
		}
	})

	L.Push(lua.LString(strings.Join(parts, L.CheckString(2))))

	return 1
}

func doIndex(L *lua.LState) int {
	L.Push(lua.LNumber(strings.Index(L.CheckString(1), L.CheckString(2))))
	return 1
}

func doTruncate(L *lua.LState) int {
	str := L.CheckString(1)
	truncateLen := L.CheckInt(2)

	L.Push(lua.LString(_doTruncate(str, truncateLen)))
	return 1
}

func doTruncateUnicode(L *lua.LState) int {
	str := L.CheckString(1)
	truncateLen := L.CheckInt(2)

	L.Push(lua.LString(_doTruncateUnicode(str, truncateLen)))
	return 1
}

func _doTruncate(s string, maxBytes int) string {
	if len(s) > maxBytes {
		return s[:maxBytes]
	}
	return s
}

func _doTruncateUnicode(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}

	return s
}
