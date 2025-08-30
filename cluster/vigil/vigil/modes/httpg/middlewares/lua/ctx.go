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

	"github.com/kaptinlin/jsonschema"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/lua/modules/base64"
	httpm "github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/lua/modules/http"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/lua/modules/regexp"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/lua/modules/strings"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/lua/modules/table"
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
	isExit       bool
}

type newCtxOpts struct {
	req          *http.Request
	rw           *responseWriter
	fnProto      *lua.FunctionProto
	reqCtxLValue lua.LValue
}

var jsonCompiler = jsonschema.NewCompiler()

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

	// lua.OpenString(ret.state)
	lua.OpenMath(ret.state)

	ret.loadGlobalFns()
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
	f := c.state.GetGlobal("onRequest")

	if f.Type() != lua.LTFunction {
		return errors.Errorf("onRequest function is not defined")
	}

	startedAt := time.Now()
	c.state.Push(f)
	c.state.Push(c.reqCtxLValue)

	if err := c.state.PCall(1, 0, nil); err != nil {
		return err
	}

	zap.L().Debug("onRequest done",
		zap.Float32("timeMicroSec", float32(time.Since(startedAt).Nanoseconds())/1000))
	return nil
}

func (c *luaCtx) callOnResponse() error {
	f := c.state.GetGlobal("onResponse")

	if f.Type() != lua.LTFunction {
		return errors.Errorf("onResponse function is not defined")
	}

	startedAt := time.Now()
	c.state.Push(f)
	c.state.Push(c.reqCtxLValue)

	if err := c.state.PCall(1, 0, nil); err != nil {
		return err
	}

	zap.L().Debug("onResponse done",
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

func (c *luaCtx) jsonIsSchemaValid(L *lua.LState) int {

	jsonSchema := L.CheckString(1)

	var goVal any

	if err := json.Unmarshal([]byte(L.CheckString(2)), &goVal); err != nil {
		L.Push(lua.LBool(false))
		return 1
	}

	schema, err := jsonCompiler.Compile([]byte(jsonSchema))
	if err != nil {
		L.Push(lua.LBool(false))
		return 1
	}

	res := schema.Validate(goVal)
	L.Push(lua.LBool(res != nil && res.IsValid()))
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

	{
		L.Push(L.NewFunction(c.loadModuleReq))
		L.Push(lua.LString("octelium.req"))
		L.Call(1, 0)
	}

	{
		L.Push(L.NewFunction(base64.Register))
		L.Push(lua.LString("base64"))
		L.Call(1, 0)
	}

	{
		L.Push(L.NewFunction(strings.Register))
		L.Push(lua.LString("strings"))
		L.Call(1, 0)
	}

	{
		L.Push(L.NewFunction(table.Register))
		L.Push(lua.LString("table"))
		L.Call(1, 0)
	}

	{
		L.Push(L.NewFunction(httpm.Register))
		L.Push(lua.LString("http"))
		L.Call(1, 0)
	}

	{
		L.Push(L.NewFunction(regexp.Register))
		L.Push(lua.LString("regexp"))
		L.Call(1, 0)
	}

	zap.L().Debug("loadModules done",
		zap.Float32("timeMicroSec", float32(time.Since(startedAt).Nanoseconds())/1000))
}

func (c *luaCtx) loadModuleJSON(L *lua.LState) int {

	fns := map[string]lua.LGFunction{
		"encode":        c.jsonEncode,
		"decode":        c.jsonDecode,
		"isSchemaValid": c.jsonIsSchemaValid,
	}

	mod := L.RegisterModule("json", fns).(*lua.LTable)
	L.Push(mod)

	return 1
}

func (c *luaCtx) loadModuleReq(L *lua.LState) int {

	fns := map[string]lua.LGFunction{
		"setRequestHeader":    c.setRequestHeader,
		"setRequestBody":      c.setRequestBody,
		"getRequestBody":      c.getRequestBody,
		"deleteRequestHeader": c.deleteRequestHeader,

		"setResponseHeader":    c.setResponseHeader,
		"setResponseBody":      c.setResponseBody,
		"getResponseBody":      c.getResponseBody,
		"deleteResponseHeader": c.deleteResponseHeader,

		"setQueryParam":    c.setQueryParam,
		"getQueryParam":    c.getQueryParam,
		"deleteQueryParam": c.deleteQueryParam,

		"setStatusCode": c.setStatusCode,
		"setPath":       c.setPath,
		"exit":          c.exit,
	}

	mod := L.RegisterModule("octelium.req", fns).(*lua.LTable)
	L.Push(mod)

	return 1
}

func (c *luaCtx) loadGlobalFns() {
	L := c.state

	L.SetGlobal("assert", L.NewFunction(doGlobalFnAssert))
	L.SetGlobal("type", L.NewFunction(doGlobalFnType))
	L.SetGlobal("error", L.NewFunction(doGlobalFnError))
	L.SetGlobal("print", L.NewFunction(doGlobalFnPrint))
	L.SetGlobal("ipairs", L.NewClosure(doIpairs, L.NewFunction(ipairsaux)))
	L.SetGlobal("pairs", L.NewClosure(doPairs, L.NewFunction(pairsaux)))
}
