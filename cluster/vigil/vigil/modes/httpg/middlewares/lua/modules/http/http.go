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

package http

import (
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	lua "github.com/yuin/gopher-lua"
)

func Register(L *lua.LState) int {
	mod := L.RegisterModule("http", fns).(*lua.LTable)

	http_client_ud := L.NewTypeMetatable(`http_client_ud`)
	L.SetGlobal(`http_client_ud`, http_client_ud)
	L.SetField(http_client_ud, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"request":    doRequestNew,
		"setHeader":  doClientSetHeader,
		"setBaseURL": doClientSetBaseURL,
	}))

	http_request_ud := L.NewTypeMetatable(`http_request_ud`)
	L.SetGlobal("http_request_ud", http_request_ud)
	L.SetField(http_request_ud, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"setHeader": doRequestSetHeader,
		"setBody":   doRequestSetBody,
		"get":       doRequestGet,
		"post":      doRequestPost,
		"put":       doRequestPut,
		"delete":    doRequestDelete,
	}))

	http_response_ud := L.NewTypeMetatable(`http_response_ud`)
	L.SetGlobal("http_response_ud", http_response_ud)
	L.SetField(http_response_ud, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"body": doResponseBody,
		"code": doResponseStatusCode,
	}))

	L.Push(mod)

	return 1
}

var fns = map[string]lua.LGFunction{
	"client": doClientNew,
}

func doClientNew(L *lua.LState) int {
	c := resty.New().
		SetHeader("User-Agent", "octelium").
		SetTimeout(6 * time.Second).
		SetDebug(ldflags.IsTest())

	ud := L.NewUserData()
	ud.Value = c
	L.SetMetatable(ud, L.GetTypeMetatable("http_client_ud"))
	L.Push(ud)

	return 1
}

func doClientSetHeader(L *lua.LState) int {

	c := checkClient(L)
	c.SetHeader(L.CheckString(2), L.CheckString(3))

	return 0
}

func doClientSetBaseURL(L *lua.LState) int {

	c := checkClient(L)
	c.SetBaseURL(L.CheckString(2))

	return 0
}

func doRequestNew(L *lua.LState) int {

	c := checkClient(L)

	ud := L.NewUserData()
	ud.Value = c.R().SetDebug(ldflags.IsTest())
	L.SetMetatable(ud, L.GetTypeMetatable("http_request_ud"))
	L.Push(ud)

	return 1
}

func checkClient(L *lua.LState) *resty.Client {
	ud := L.CheckUserData(1)
	if v, ok := ud.Value.(*resty.Client); ok {
		return v
	}
	L.ArgError(1, "invalid http client")
	return nil
}

func checkRequest(L *lua.LState) *resty.Request {
	ud := L.CheckUserData(1)
	if v, ok := ud.Value.(*resty.Request); ok {
		return v
	}
	L.ArgError(1, "invalid http request")
	return nil
}

func checkResponse(L *lua.LState) *resty.Response {
	ud := L.CheckUserData(1)
	if v, ok := ud.Value.(*resty.Response); ok {
		return v
	}
	L.ArgError(1, "invalid http request")
	return nil
}

func doRequestGet(L *lua.LState) int {
	return doRequestDo(L, "get")
}

func doRequestPost(L *lua.LState) int {
	return doRequestDo(L, "post")
}

func doRequestPut(L *lua.LState) int {
	return doRequestDo(L, "put")
}

func doRequestDelete(L *lua.LState) int {
	return doRequestDo(L, "delete")
}

func doRequestDo(L *lua.LState, method string) int {

	req := checkRequest(L)

	var resp *resty.Response
	var err error

	reqURL := L.CheckString(2)
	switch method {
	case "get":
		resp, err = req.Get(reqURL)
	case "post":
		resp, err = req.Post(reqURL)
	case "put":
		resp, err = req.Put(reqURL)
	case "delete":
		resp, err = req.Delete(reqURL)
	default:
		resp, err = req.Get(reqURL)
	}

	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	ud := L.NewUserData()
	ud.Value = resp
	L.SetMetatable(ud, L.GetTypeMetatable("http_response_ud"))
	L.Push(ud)

	return 1
}

func doRequestSetHeader(L *lua.LState) int {

	req := checkRequest(L)
	req.SetHeader(L.CheckString(2), L.CheckString(3))

	return 0
}

func doRequestSetBody(L *lua.LState) int {

	req := checkRequest(L)
	req.SetBody(L.CheckString(2))

	return 0
}

func doResponseBody(L *lua.LState) int {
	res := checkResponse(L)
	L.Push(lua.LString(string(res.Body())))
	return 1
}

func doResponseStatusCode(L *lua.LState) int {
	res := checkResponse(L)
	L.Push(lua.LNumber(res.StatusCode()))
	return 1
}
