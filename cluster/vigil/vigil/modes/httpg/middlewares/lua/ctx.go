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

	return &luaCtx{
		req:     o.req,
		rw:      o.rw,
		state:   lua.NewState(),
		fnProto: o.fnProto,
	}, nil
}

func (l *luaCtx) close() {

	if l.state != nil {
		l.state.Close()
	}
}

func (c *luaCtx) compiledFile(proto *lua.FunctionProto) error {
	lfunc := c.state.NewFunctionFromProto(proto)
	c.state.Push(lfunc)
	return c.state.PCall(0, lua.MultRet, nil)
}

func (c *luaCtx) callOnFunction(name string) error {
	f := c.state.GetGlobal(name)
	if f.Type() != lua.LTFunction {
		return errors.Errorf("Not a function: %s", name)
	}
	c.state.Push(f)
	if err := c.state.PCall(0, 0, nil); err != nil {
		return err
	}

	return nil
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
