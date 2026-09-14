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
	"context"
	stdhttp "net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/cluster/common/httputils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	lua "github.com/yuin/gopher-lua"
)

const (
	defaultRequestTimeout  = 6 * time.Second
	defaultMaxResponseBody = 4 * 1024 * 1024
	defaultMaxRedirects    = 5
)

var restrictedTransport = httputils.NewRestrictedTransport()

func Register(L *lua.LState) int {
	mod := L.RegisterModule("http", fns).(*lua.LTable)

	httpClientUD := L.NewTypeMetatable("http_client_ud")
	L.SetGlobal("http_client_ud", httpClientUD)
	L.SetField(httpClientUD, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"request":    doRequestNew,
		"setHeader":  doClientSetHeader,
		"setBaseURL": doClientSetBaseURL,
	}))

	httpRequestUD := L.NewTypeMetatable("http_request_ud")
	L.SetGlobal("http_request_ud", httpRequestUD)
	L.SetField(httpRequestUD, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"setHeader": doRequestSetHeader,
		"setBody":   doRequestSetBody,
		"get":       doRequestGet,
		"post":      doRequestPost,
		"put":       doRequestPut,
		"delete":    doRequestDelete,
	}))

	httpResponseUD := L.NewTypeMetatable("http_response_ud")
	L.SetGlobal("http_response_ud", httpResponseUD)
	L.SetField(httpResponseUD, "__index", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
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
	httpClient := &stdhttp.Client{
		Transport:     restrictedTransport,
		Timeout:       defaultRequestTimeout,
		CheckRedirect: checkRedirect,
	}

	c := resty.NewWithClient(httpClient).
		SetHeader("User-Agent", "octelium").
		SetResponseBodyLimit(defaultMaxResponseBody).
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
	L.ArgError(1, "invalid http response")
	return nil
}

func doRequestGet(L *lua.LState) int {
	return doRequestDo(L, stdhttp.MethodGet)
}

func doRequestPost(L *lua.LState) int {
	return doRequestDo(L, stdhttp.MethodPost)
}

func doRequestPut(L *lua.LState) int {
	return doRequestDo(L, stdhttp.MethodPut)
}

func doRequestDelete(L *lua.LState) int {
	return doRequestDo(L, stdhttp.MethodDelete)
}

func doRequestDo(L *lua.LState, method string) int {
	req := checkRequest(L)

	ctx := L.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	req.SetContext(ctx)

	reqURL := L.CheckString(2)

	var (
		resp *resty.Response
		err  error
	)

	switch method {
	case stdhttp.MethodGet:
		resp, err = req.Get(reqURL)
	case stdhttp.MethodPost:
		resp, err = req.Post(reqURL)
	case stdhttp.MethodPut:
		resp, err = req.Put(reqURL)
	case stdhttp.MethodDelete:
		resp, err = req.Delete(reqURL)
	default:
		L.Push(lua.LNil)
		L.Push(lua.LString("unsupported HTTP method"))
		return 2
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

func checkRedirect(req *stdhttp.Request, via []*stdhttp.Request) error {
	if len(via) >= defaultMaxRedirects {
		return errors.Errorf("stopped after %d redirects", defaultMaxRedirects)
	}

	if req == nil || req.URL == nil {
		return errors.Errorf("invalid redirect URL")
	}

	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return errors.Errorf("unsupported redirect scheme %q", req.URL.Scheme)
	}

	if req.URL.Hostname() == "" || req.URL.User != nil {
		return errors.Errorf("invalid redirect destination")
	}

	if len(via) > 0 && !sameOrigin(via[0].URL, req.URL) {
		for _, name := range []string{
			"Authorization",
			"Proxy-Authorization",
			"Cookie",
			"X-Api-Key",
			"X-Auth-Token",
		} {
			req.Header.Del(name)
		}
	}

	return nil
}

func sameOrigin(a *url.URL, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}

	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if u == nil {
		return ""
	}

	if port := u.Port(); port != "" {
		return port
	}

	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}
