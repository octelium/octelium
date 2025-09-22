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
	"bytes"
	"encoding/json"
	"io"
	"strconv"

	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	lua "github.com/yuin/gopher-lua"
)

func (c *luaCtx) setRequestHeader(L *lua.LState) int {
	name := L.Get(1)
	value := L.Get(2)

	if name.Type() != lua.LTString {
		L.Push(lua.LString("Header key is not a string"))
		return 1
	}

	if value.Type() != lua.LTString {
		L.Push(lua.LString("Header value is not a string"))
		return 1
	}

	c.req.Header.Set(name.String(), value.String())

	return 0
}

func (c *luaCtx) setRequestBody(L *lua.LState) int {

	body := L.Get(1)

	if body.Type() != lua.LTString {
		L.Push(lua.LString("Body is not a string"))
		return 1
	}

	bodyBytesI := toGoValue(body)
	bodyBytesStr, ok := bodyBytesI.(string)
	if !ok {
		return 1
	}

	bodyBytes := []byte(bodyBytesStr)

	c.req.Body = io.NopCloser(bytes.NewBuffer([]byte(bodyBytes)))
	c.req.ContentLength = int64(len(bodyBytes))

	if reqCtx := middlewares.GetCtxRequestContext(c.req.Context()); reqCtx != nil {
		reqCtx.Body = bodyBytes
		if reqCtx.BodyJSONMap != nil {
			json.Unmarshal(bodyBytes, &reqCtx.BodyJSONMap)
		}
	}

	return 0
}

func (c *luaCtx) setResponseHeader(L *lua.LState) int {
	name := L.Get(1)
	value := L.Get(2)

	if name.Type() != lua.LTString {
		L.Push(lua.LString("Header key is not a string"))
		return 1
	}

	if value.Type() != lua.LTString {
		L.Push(lua.LString("Header value is not a string"))
		return 1
	}

	c.rw.Header().Set(name.String(), value.String())

	return 0
}

func (c *luaCtx) deleteResponseHeader(L *lua.LState) int {
	name := L.Get(1)

	if name.Type() != lua.LTString {
		L.Push(lua.LString("Header key is not a string"))
		return 1
	}

	c.rw.Header().Del(name.String())

	return 0
}

func (c *luaCtx) setResponseBody(L *lua.LState) int {

	body := L.Get(1)

	if body.Type() != lua.LTString {
		L.Push(lua.LString("Body is not a string"))
		return 1
	}

	bodyBytesI := toGoValue(body)
	bodyBytesStr, ok := bodyBytesI.(string)
	if !ok {
		return 1
	}

	bodyBytes := []byte(bodyBytesStr)

	c.rw.body.Reset()
	c.rw.body.Write(bodyBytes)
	c.rw.isSet = true

	return 0
}
func (c *luaCtx) getRequestBody(L *lua.LState) int {
	bodyBytes, err := io.ReadAll(c.req.Body)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	defer c.req.Body.Close()
	body := string(bodyBytes)
	c.req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	L.Push(lua.LString(body))

	return 1
}

func (c *luaCtx) getResponseBody(L *lua.LState) int {
	L.Push(lua.LString(c.rw.body.String()))
	return 1
}

func (c *luaCtx) setQueryParam(L *lua.LState) int {
	name := L.Get(1)
	value := L.Get(2)

	if name.Type() != lua.LTString {
		L.Push(lua.LString("Query param is not a string"))
		return 1
	}

	if value.Type() != lua.LTString {
		L.Push(lua.LString("Query param is not a string"))
		return 1
	}

	qry := c.req.URL.Query()
	qry.Set(name.String(), value.String())
	c.req.URL.RawQuery = qry.Encode()

	return 0
}

func (c *luaCtx) deleteQueryParam(L *lua.LState) int {
	name := L.Get(1)

	if name.Type() != lua.LTString {
		L.Push(lua.LString("Query param is not a string"))
		return 1
	}

	qry := c.req.URL.Query()
	qry.Del(name.String())
	c.req.URL.RawQuery = qry.Encode()

	return 0
}

func (c *luaCtx) getQueryParam(L *lua.LState) int {
	name := L.Get(1)

	if name.Type() != lua.LTString {
		L.Push(lua.LString("Query param is not a string"))
		return 1
	}

	qry := c.req.URL.Query()

	L.Push(lua.LString(qry.Get(name.String())))

	return 1
}

func (c *luaCtx) setStatusCode(L *lua.LState) int {
	val := L.Get(1)

	if val.Type() != lua.LTNumber {
		L.Push(lua.LString("Query param is not a string"))
		return 1
	}

	code, err := strconv.Atoi(val.String())
	if err != nil {
		L.Push(lua.LString("Query param is not a string"))
		return 1
	}

	if code < 200 || code >= 600 {
		L.Push(lua.LString("Invalid code number"))
		return 1
	}

	c.rw.statusCode = code

	return 0
}

func (c *luaCtx) setPath(L *lua.LState) int {
	val := L.Get(1)

	if val.Type() != lua.LTString {
		L.Push(lua.LString("Path is not a string"))
		return 1
	}

	c.req.URL.Path = val.String()
	c.req.RequestURI = c.req.URL.RequestURI()

	return 0
}

func (c *luaCtx) exit(L *lua.LState) int {

	if ret := c.setStatusCode(L); ret != 0 {
		return ret
	}

	c.isExit = true

	return 0
}

func (c *luaCtx) deleteRequestHeader(L *lua.LState) int {
	name := L.Get(1)

	if name.Type() != lua.LTString {
		L.Push(lua.LString("Header key is not a string"))
		return 1
	}

	c.req.Header.Del(name.String())

	return 0
}
