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
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/octelium/octelium/cluster/common/jsonschemautils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/lua/modules/base64"
	httpm "github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/lua/modules/http"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/lua/modules/regexp"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/lua/modules/strings"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/lua/modules/table"
	lua "github.com/yuin/gopher-lua"
	"go.uber.org/zap"
)

const defaultPhaseTimeout = 10 * time.Second

var luaStateOptions = lua.Options{
	SkipOpenLibs:        true,
	MinimizeStackMemory: true,
	CallStackSize:       200,
	RegistrySize:        256,
	RegistryGrowStep:    256,
	RegistryMaxSize:     256 * 20,
}

type luaCtx struct {
	req          *http.Request
	rw           *responseWriter
	state        *lua.LState
	fnProto      *lua.FunctionProto
	reqCtxLValue lua.LValue
	isExit       bool

	pluginName string
	timeout    time.Duration

	hasOnRequest  bool
	hasOnResponse bool
	failed        bool
}

type newCtxOpts struct {
	req        *http.Request
	rw         *responseWriter
	fnProto    *lua.FunctionProto
	reqCtxMap  map[string]any
	pluginName string
	timeout    time.Duration
}

var schemaCache = jsonschemautils.NewCache()

func newCtx(o *newCtxOpts) (*luaCtx, error) {

	ret := &luaCtx{
		req:        o.req,
		rw:         o.rw,
		fnProto:    o.fnProto,
		pluginName: o.pluginName,
		timeout:    o.timeout,
	}
	if ret.timeout <= 0 {
		ret.timeout = defaultPhaseTimeout
	}

	ret.state = lua.NewState(luaStateOptions)

	// lua.OpenString(ret.state)
	lua.OpenMath(ret.state)

	ret.loadGlobalFns()
	ret.loadModules()

	ret.reqCtxLValue = toLuaValue(ret.state, o.reqCtxMap)

	if err := ret.withBudget(ret.loadFromProto); err != nil {
		ret.close()
		return nil, err
	}

	ret.hasOnRequest = ret.state.GetGlobal("onRequest").Type() == lua.LTFunction
	ret.hasOnResponse = ret.state.GetGlobal("onResponse").Type() == lua.LTFunction

	return ret, nil
}

func (c *luaCtx) withBudget(fn func() error) error {
	ctx, cancel := context.WithTimeout(c.req.Context(), c.timeout)
	defer cancel()

	c.state.SetContext(ctx)
	err := fn()
	c.state.RemoveContext()

	return err
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

func (c *luaCtx) callHook(name string) error {
	if c.failed {
		return nil
	}

	f := c.state.GetGlobal(name)
	if f.Type() != lua.LTFunction {
		return nil
	}

	startedAt := time.Now()

	err := c.withBudget(func() error {
		c.state.Push(f)
		c.state.Push(c.reqCtxLValue)
		return c.state.PCall(1, 0, nil)
	})
	if err != nil {
		c.failed = true
		return err
	}

	zap.L().Debug(name+" done",
		zap.Float32("timeMicroSec", float32(time.Since(startedAt).Nanoseconds())/1000))
	return nil
}

func (c *luaCtx) callOnRequest() error {
	return c.callHook("onRequest")
}

func (c *luaCtx) callOnResponse() error {
	return c.callHook("onResponse")
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

	schema, err := schemaCache.Compile([]byte(jsonSchema))
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
	L.SetGlobal("pcall", L.NewFunction(doGlobalFnPCall))
	L.SetGlobal("tostring", L.NewFunction(doGlobalFnToString))
	L.SetGlobal("tonumber", L.NewFunction(doGlobalFnToNumber))
	L.SetGlobal("select", L.NewFunction(doGlobalFnSelect))
}
