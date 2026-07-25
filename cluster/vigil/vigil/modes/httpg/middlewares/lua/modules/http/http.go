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
	"crypto/tls"
	"net"
	stdhttp "net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	lua "github.com/yuin/gopher-lua"
)

const (
	defaultRequestTimeout      = 6 * time.Second
	defaultDialTimeout         = 5 * time.Second
	defaultTLSHandshakeTimeout = 5 * time.Second
	defaultResponseTimeout     = 5 * time.Second
	defaultIdleConnTimeout     = 30 * time.Second
	defaultMaxResponseBody     = 4 * 1024 * 1024
	defaultMaxRedirects        = 5
)

var (
	restrictedTransport = newRestrictedTransport()

	blockedDestinationPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),

		netip.MustParsePrefix("::/96"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParsePrefix("5f00::/16"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fec0::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

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

type publicOnlyDialer struct {
	dialer   net.Dialer
	resolver *net.Resolver
}

func newRestrictedTransport() *stdhttp.Transport {
	d := &publicOnlyDialer{
		dialer: net.Dialer{
			Timeout:   defaultDialTimeout,
			KeepAlive: 30 * time.Second,
		},
		resolver: net.DefaultResolver,
	}

	return &stdhttp.Transport{
		Proxy: nil,

		DialContext: d.DialContext,

		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		MaxConnsPerHost:       16,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: defaultResponseTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

func (d *publicOnlyDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.Errorf("unsupported outbound network %q", network)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.Errorf("invalid outbound address %q: %+v", address, err)
	}

	if err := validatePort(port); err != nil {
		return nil, err
	}

	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, errors.Errorf("empty outbound host")
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if err := validatePublicAddress(addr); err != nil {
			return nil, errors.Errorf("outbound destination %q is blocked: %+v", host, err)
		}

		return d.dialAddress(ctx, network, addr, port)
	}

	resolved, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.Errorf("could not resolve outbound host %q: %+v", host, err)
	}

	publicAddrs := make([]netip.Addr, 0, len(resolved))
	for _, addr := range resolved {
		addr = addr.Unmap()
		if validatePublicAddress(addr) == nil {
			publicAddrs = append(publicAddrs, addr)
		}
	}

	if len(publicAddrs) == 0 {
		return nil, errors.Errorf("outbound host %q resolved only to blocked addresses", host)
	}

	for _, addr := range publicAddrs {
		conn, err := d.dialAddress(ctx, network, addr, port)
		if err == nil {
			return conn, nil
		}
	}

	return nil, errors.Errorf("could not connect to any public address for %q", host)
}

func (d *publicOnlyDialer) dialAddress(ctx context.Context, network string, addr netip.Addr, port string) (net.Conn, error) {
	if network == "tcp4" && !addr.Is4() {
		return nil, errors.Errorf("address %s is not IPv4", addr)
	}
	if network == "tcp6" && !addr.Is6() {
		return nil, errors.Errorf("address %s is not IPv6", addr)
	}

	return d.dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
}

func validatePort(port string) error {
	val, err := strconv.ParseUint(port, 10, 16)
	if err != nil || val == 0 {
		return errors.Errorf("invalid outbound port %q", port)
	}
	return nil
}

func validatePublicAddress(addr netip.Addr) error {
	if !addr.IsValid() {
		return errors.Errorf("invalid IP address")
	}

	addr = addr.Unmap()

	if addr.Zone() != "" {
		return errors.Errorf("scoped IP addresses are not allowed")
	}

	if !addr.IsGlobalUnicast() ||
		addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return errors.Errorf("IP address is not publicly routable")
	}

	for _, prefix := range blockedDestinationPrefixes {
		if prefix.Contains(addr) {
			return errors.Errorf("IP address belongs to blocked range %s", prefix)
		}
	}

	return nil
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
