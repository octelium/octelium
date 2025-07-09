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
	"net/http"

	"github.com/pkg/errors"
	lua "github.com/yuin/gopher-lua"
)

type luaCtx struct {
	req     *http.Request
	rw      http.ResponseWriter
	state   *lua.LState
	fnProto *lua.FunctionProto
}

type newCtxOpts struct {
	req     *http.Request
	rw      http.ResponseWriter
	fnProto *lua.FunctionProto
}

func newCtx(o *newCtxOpts) (*luaCtx, error) {

	ret := &luaCtx{
		req:     o.req,
		rw:      o.rw,
		fnProto: o.fnProto,
	}
	ret.state = lua.NewState(lua.Options{
		SkipOpenLibs: true,
	})
	ret.state.SetContext(o.req.Context())

	lua.OpenString(ret.state)
	lua.OpenMath(ret.state)

	ret.state.SetGlobal("set_request_header", ret.state.NewFunction(ret.setRequestHeader))
	ret.state.SetGlobal("set_response_header", ret.state.NewFunction(ret.setResponseHeader))

	if err := ret.compiledFile(); err != nil {
		return nil, err
	}

	return ret, nil
}

func (l *luaCtx) close() {

	if l.state != nil {
		l.state.Close()
	}
}

func (c *luaCtx) compiledFile() error {
	lfunc := c.state.NewFunctionFromProto(c.fnProto)
	c.state.Push(lfunc)
	return c.state.PCall(0, lua.MultRet, nil)
}

func (c *luaCtx) callOnRequest() error {
	f := c.state.GetGlobal("on_request")

	if f.Type() != lua.LTFunction {
		return errors.Errorf("on_request function is not defined")
	}

	c.state.Push(f)
	if err := c.state.PCall(0, 0, nil); err != nil {
		return err
	}

	return nil
}

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
