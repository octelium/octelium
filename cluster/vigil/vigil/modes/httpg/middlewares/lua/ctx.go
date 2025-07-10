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
	"io"
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
