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
	"encoding/json"
	"net/http"
	"time"

	"github.com/pkg/errors"
	lua "github.com/yuin/gopher-lua"
	"go.uber.org/zap"
)

type luaCtx struct {
	req          *http.Request
	rw           *responseWriter
	state        *lua.LState
	fnProto      *lua.FunctionProto
	reqCtxLValue lua.LValue
}

type newCtxOpts struct {
	req          *http.Request
	rw           *responseWriter
	fnProto      *lua.FunctionProto
	reqCtxLValue lua.LValue
}

func newCtx(o *newCtxOpts) (*luaCtx, error) {

	ret := &luaCtx{
		req:          o.req,
		rw:           o.rw,
		fnProto:      o.fnProto,
		reqCtxLValue: o.reqCtxLValue,
	}
	ret.state = lua.NewState(lua.Options{
		SkipOpenLibs: true,
	})
	ret.state.SetContext(o.req.Context())

	lua.OpenString(ret.state)
	lua.OpenMath(ret.state)

	ret.state.SetGlobal("set_request_header", ret.state.NewFunction(ret.setRequestHeader))
	ret.state.SetGlobal("set_response_header", ret.state.NewFunction(ret.setResponseHeader))

	ret.state.SetGlobal("set_request_body", ret.state.NewFunction(ret.setRequestBody))
	ret.state.SetGlobal("set_response_body", ret.state.NewFunction(ret.setResponseBody))

	ret.state.SetGlobal("get_request_body", ret.state.NewFunction(ret.getRequestBody))
	ret.state.SetGlobal("get_response_body", ret.state.NewFunction(ret.getResponseBody))

	ret.state.SetGlobal("set_query_param", ret.state.NewFunction(ret.setQueryParam))
	ret.state.SetGlobal("delete_query_param", ret.state.NewFunction(ret.deleteQueryParam))
	ret.state.SetGlobal("get_query_param", ret.state.NewFunction(ret.getQueryParam))

	ret.loadModules()

	if err := ret.loadFromProto(); err != nil {
		return nil, err
	}

	return ret, nil
}

func (l *luaCtx) close() {
	if l.state != nil {
		l.state.Close()
	}
}

func (c *luaCtx) loadFromProto() error {
	lfunc := c.state.NewFunctionFromProto(c.fnProto)
	c.state.Push(lfunc)
	return c.state.PCall(0, lua.MultRet, nil)
}

func (c *luaCtx) callOnRequest() error {
	f := c.state.GetGlobal("on_request")

	if f.Type() != lua.LTFunction {
		return errors.Errorf("on_request function is not defined")
	}

	startedAt := time.Now()
	c.state.Push(f)
	c.state.Push(c.reqCtxLValue)

	if err := c.state.PCall(1, 0, nil); err != nil {
		return err
	}

	zap.L().Debug("on_request done",
		zap.Float32("timeMicroSec", float32(time.Since(startedAt).Nanoseconds())/1000))
	return nil
}

func (c *luaCtx) callOnResponse() error {
	f := c.state.GetGlobal("on_response")

	if f.Type() != lua.LTFunction {
		return errors.Errorf("on_response function is not defined")
	}

	startedAt := time.Now()
	c.state.Push(f)
	c.state.Push(c.reqCtxLValue)

	if err := c.state.PCall(1, 0, nil); err != nil {
		return err
	}

	zap.L().Debug("on_response done",
		zap.Float32("timeMicroSec", float32(time.Since(startedAt).Nanoseconds())/1000))
	return nil
}

func (c *luaCtx) jsonEncode(L *lua.LState) int {

	val := L.Get(1)

	res, err := json.Marshal(toGoValue(val))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LString(string(res)))

	return 1
}

func (c *luaCtx) jsonDecode(L *lua.LState) int {

	jsonVal := L.Get(1)

	if jsonVal.Type() != lua.LTString {
		L.Push(lua.LString("Input is not a string"))
		return 1
	}

	var goVal any

	if err := json.Unmarshal([]byte(jsonVal.String()), &goVal); err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(toLuaValue(L, goVal))

	return 1
}

func (c *luaCtx) loadModules() {
	L := c.state
	startedAt := time.Now()
	{
		L.Push(L.NewFunction(c.loadModuleJSON))
		L.Push(lua.LString("json"))
		L.Call(1, 0)
	}

	zap.L().Debug("loadModules done",
		zap.Float32("timeMicroSec", float32(time.Since(startedAt).Nanoseconds())/1000))
}

func (c *luaCtx) loadModuleJSON(L *lua.LState) int {

	fns := map[string]lua.LGFunction{
		"encode": c.jsonEncode,
		"decode": c.jsonDecode,
	}

	mod := L.RegisterModule("json", fns).(*lua.LTable)
	L.Push(mod)

	return 1
}
