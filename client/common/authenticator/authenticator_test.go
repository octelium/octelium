// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authenticator

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/pkg/common/opkce"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGetArgMap(t *testing.T) {
	{
		res := getArgMap("env=JWT_KEY")
		assert.Equal(t, "JWT_KEY", res["env"])
	}
	{
		res := getArgMap("audience=https://example.com")
		assert.Equal(t, "https://example.com", res["audience"])
	}
}

func TestParseAssertion(t *testing.T) {
	{
		res, err := parseAssertion("k8s")
		assert.Nil(t, err)
		assert.Equal(t, "k8s", res.typ)
	}
	{
		res, err := parseAssertion("github-actions")
		assert.Nil(t, err)
		assert.Equal(t, "github-actions", res.typ)
	}
	{
		res, err := parseAssertion("gh01:github-actions")
		assert.Nil(t, err)
		assert.Equal(t, "github-actions", res.typ)
		assert.Equal(t, "gh01", res.identityProviderRef.Name)
	}
	{
		res, err := parseAssertion("github-actions:audience=custom-aud")
		assert.Nil(t, err)
		assert.Equal(t, "github-actions", res.typ)
		assert.Equal(t, "custom-aud", res.argMap["audience"])
	}
	{
		res, err := parseAssertion("gh01:github-actions:audience=custom-aud,extra=val")
		assert.Nil(t, err)
		assert.Equal(t, "github-actions", res.typ)
		assert.Equal(t, "gh01", res.identityProviderRef.Name)
		assert.Equal(t, "custom-aud", res.argMap["audience"])
		assert.Equal(t, "val", res.argMap["extra"])
	}
}

func TestWebAuthenticatorLoginURL(t *testing.T) {

	{
		_, err := NewWebAuthenticator(nil)
		assert.NotNil(t, err)
	}
	{
		_, err := NewWebAuthenticator(&WebAuthenticatorOpts{})
		assert.NotNil(t, err)
	}

	s, err := NewWebAuthenticator(&WebAuthenticatorOpts{
		Domain: "example.com",
	})
	assert.Nil(t, err)

	assert.Equal(t, opkce.VerifierLen, len(s.codeVerifier))
	assert.Equal(t, opkce.GetChallenge(s.codeVerifier), s.codeChallenge)

	assert.Equal(t, callbackSuffixLen, len(s.callbackSuffix))
	assert.LessOrEqual(t, callbackSuffixLen, 8)
	assert.Equal(t, fmt.Sprintf("/callback/success/%s", s.callbackSuffix), s.successCallbackPath)

	s.port = 12345

	u, err := url.Parse(s.GetLoginURL())
	assert.Nil(t, err)
	assert.Equal(t, "example.com", u.Host)
	assert.Equal(t, "/login", u.Path)

	arg := u.Query().Get("octelium_req")
	assert.NotEmpty(t, arg)

	assert.Less(t, len(arg), 512)

	reqBytes, err := base64.RawURLEncoding.DecodeString(arg)
	assert.Nil(t, err)

	req := &authv1.ClientLoginRequest{}
	assert.Nil(t, pbutils.Unmarshal(reqBytes, req))

	assert.Equal(t, authv1.ClientLoginRequest_V1, req.ApiVersion)
	assert.Equal(t, uint32(12345), req.CallbackPort)
	assert.Equal(t, s.callbackSuffix, req.CallbackSuffix)
	assert.Equal(t, s.codeChallenge, req.CodeChallenge)
}

func TestWebAuthenticatorListen(t *testing.T) {

	s, err := NewWebAuthenticator(&WebAuthenticatorOpts{
		Domain: "example.com",
	})
	assert.Nil(t, err)

	assert.Nil(t, s.listen())
	t.Cleanup(func() {
		for _, lis := range s.listeners {
			lis.Close()
		}
	})

	assert.NotZero(t, s.port)
	assert.NotEmpty(t, s.listeners)

	for _, lis := range s.listeners {
		addr := lis.Addr().(*net.TCPAddr)
		assert.True(t, addr.IP.IsLoopback(), "%s is not a loopback address", addr.IP)
		assert.Equal(t, s.port, addr.Port)
	}
}

func TestWebAuthenticatorGetLoginResponse(t *testing.T) {

	s, err := NewWebAuthenticator(&WebAuthenticatorOpts{
		Domain: "example.com",
	})
	assert.Nil(t, err)

	newReq := func(arg string) *http.Request {
		return httptest.NewRequest("GET",
			fmt.Sprintf("http://localhost:12345%s?octelium_response=%s",
				s.successCallbackPath, arg), nil)
	}

	encode := func(resp *authv1.ClientLoginResponse) string {
		b, err := pbutils.Marshal(resp)
		assert.Nil(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}

	{
		resp, err := s.getLoginResponse(newReq(encode(&authv1.ClientLoginResponse{
			AuthenticationToken: "token",
			CodeChallenge:       s.codeChallenge,
		})))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "token", resp.AuthenticationToken)
	}

	{
		_, err := s.getLoginResponse(newReq(encode(&authv1.ClientLoginResponse{})))
		assert.NotNil(t, err)
	}

	{
		_, err := s.getLoginResponse(newReq("not-base64-$$$"))
		assert.NotNil(t, err)
	}

	{
		_, err := s.getLoginResponse(
			httptest.NewRequest("GET", "http://localhost:12345"+s.successCallbackPath, nil))
		assert.NotNil(t, err)
	}
}

func TestWebAuthenticatorServeHTTP(t *testing.T) {

	s, err := NewWebAuthenticator(&WebAuthenticatorOpts{
		Domain: "example.com",
	})
	assert.Nil(t, err)

	isClosed := func() bool {
		select {
		case <-s.ch:
			return true
		default:
			return false
		}
	}

	{
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("POST",
			"http://localhost:12345"+s.successCallbackPath, nil))

		assert.Equal(t, http.StatusMethodNotAllowed, w.Result().StatusCode)
		assert.False(t, isClosed())
	}

	{
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET",
			"http://localhost:12345"+s.successCallbackPath, nil))

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.False(t, isClosed())
	}

	{
		b, err := pbutils.Marshal(&authv1.ClientLoginResponse{})
		assert.Nil(t, err)

		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET",
			fmt.Sprintf("http://localhost:12345%s?octelium_response=%s",
				s.successCallbackPath, base64.RawURLEncoding.EncodeToString(b)), nil))

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.False(t, isClosed())
	}
}

func TestGetAccessTokenRenewAt(t *testing.T) {
	setAt := time.Now().Add(-11 * time.Minute)

	{
		assert.True(t, GetAccessTokenRenewAt(nil).IsZero())
		assert.True(t, GetAccessTokenRenewAt(&cliconfigv1.State_Domain{}).IsZero())
		assert.True(t, NeedsNewAccessToken(nil))
		assert.True(t, NeedsNewAccessToken(&cliconfigv1.State_Domain{}))
	}

	{
		at := &cliconfigv1.State_Domain{
			SessionToken:      &authv1.SessionToken{},
			SessionTokenSetAt: pbutils.Timestamp(setAt),
		}
		assert.True(t, GetAccessTokenRenewAt(at).IsZero())
		assert.False(t, NeedsNewAccessToken(at))
	}

	{
		at := &cliconfigv1.State_Domain{
			SessionToken: &authv1.SessionToken{
				ExpiresIn: 7200,
			},
			SessionTokenSetAt: pbutils.Timestamp(setAt),
		}
		assert.True(t, setAt.Add(3600*time.Second).Equal(GetAccessTokenRenewAt(at)))
		assert.False(t, NeedsNewAccessToken(at))
	}

	{
		at := &cliconfigv1.State_Domain{
			SessionToken: &authv1.SessionToken{
				ExpiresIn: 1200,
			},
			SessionTokenSetAt: pbutils.Timestamp(setAt),
		}
		assert.True(t, setAt.Add(600*time.Second).Equal(GetAccessTokenRenewAt(at)))
		assert.True(t, NeedsNewAccessToken(at))
	}
}

func TestAuthenticatorNeedsNewAccessToken(t *testing.T) {
	at := &cliconfigv1.State_Domain{
		SessionToken: &authv1.SessionToken{
			ExpiresIn: 7200,
		},
		SessionTokenSetAt: pbutils.Timestamp(time.Now().Add(-10 * time.Minute)),
	}

	{
		a := &authenticator{
			at: at,
		}
		assert.False(t, a.needsNewAccessToken())
	}

	{
		a := &authenticator{
			at:      at,
			isRenew: true,
		}
		assert.True(t, a.needsNewAccessToken())
	}

	{
		a := &authenticator{}
		assert.True(t, a.needsNewAccessToken())
	}
}

func TestRenewAccessToken(t *testing.T) {
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "static")

	ret, err := RenewAccessToken(context.Background(), "example.com")
	assert.Nil(t, err)
	assert.Equal(t, "static", ret)
}

func TestGetRenewedSessionToken(t *testing.T) {
	const domain = "example.com"

	dbC, err := db.Open("mem")
	assert.Nil(t, err)
	ctx := cliutils.WithDB(context.Background(), dbC)

	setToken := func(idx int, expiresIn, refreshTokenExpiresIn int64) {
		assert.Nil(t, dbC.SetSessionToken(domain, &authv1.SessionToken{
			AccessToken:           fmt.Sprintf("access-%d", idx),
			RefreshToken:          fmt.Sprintf("refresh-%d", idx),
			ExpiresIn:             expiresIn,
			RefreshTokenExpiresIn: refreshTokenExpiresIn,
		}))
	}

	setToken(1, 7200, 86400)

	at, err := dbC.Get(domain)
	assert.Nil(t, err)

	a := &authenticator{
		domain: domain,
		at:     at,
	}

	assert.Nil(t, a.getRenewedSessionToken(ctx))

	setToken(2, 60, 86400)
	assert.Nil(t, a.getRenewedSessionToken(ctx))

	setToken(3, 7200, 0)
	assert.Nil(t, a.getRenewedSessionToken(ctx))

	setToken(4, 7200, 86400)
	assert.Equal(t, "access-4", a.getRenewedSessionToken(ctx).GetAccessToken())

	assert.Nil(t, dbC.DeleteSessionToken(domain))
	assert.Nil(t, a.getRenewedSessionToken(ctx))
}

func TestRefreshAccessTokenWaitsForRenewal(t *testing.T) {
	const domain = "example.com"

	dbC, err := db.Open("mem")
	assert.Nil(t, err)
	ctx := cliutils.WithDB(context.Background(), dbC)

	setToken := func(idx int, expiresIn int64) {
		assert.Nil(t, dbC.SetSessionToken(domain, &authv1.SessionToken{
			AccessToken:           fmt.Sprintf("access-%d", idx),
			RefreshToken:          fmt.Sprintf("refresh-%d", idx),
			ExpiresIn:             expiresIn,
			RefreshTokenExpiresIn: 86400,
		}))
	}

	setToken(1, 60)

	at, err := dbC.Get(domain)
	assert.Nil(t, err)

	a := &authenticator{
		domain:    domain,
		at:        at,
		isRefresh: true,
	}
	assert.True(t, a.needsNewAccessToken())

	unlock, err := dbC.LockRefresh(ctx)
	assert.Nil(t, err)

	type result struct {
		accessToken string
		err         error
	}

	resCh := make(chan result, 1)
	go func() {
		accessToken, err := a.refreshAccessToken(ctx)
		resCh <- result{accessToken: accessToken, err: err}
	}()

	select {
	case <-resCh:
		t.Fatal("The access token was refreshed while another refresh was in progress")
	case <-time.After(100 * time.Millisecond):
	}

	setToken(2, 7200)
	unlock()

	select {
	case res := <-resCh:
		assert.Nil(t, res.err)
		assert.Equal(t, "access-2", res.accessToken)
	case <-time.After(5 * time.Second):
		t.Fatal("The access token was not returned after the refresh lock was released")
	}

	unlock, err = dbC.LockRefresh(ctx)
	assert.Nil(t, err)
	unlock()
}

func TestTokenExpiration(t *testing.T) {
	setAt := time.Now().Add(-time.Hour)
	for _, at := range []*cliconfigv1.State_Domain{
		nil, {}, {SessionToken: &authv1.SessionToken{}},
		{SessionToken: &authv1.SessionToken{}, SessionTokenSetAt: &timestamppb.Timestamp{Seconds: 253402300800}},
	} {
		assert.True(t, GetAccessTokenExpiresAt(at).IsZero())
		assert.True(t, GetRefreshTokenExpiresAt(at).IsZero())
		assert.False(t, HasValidRefreshToken(at))
		assert.True(t, NeedsNewAccessToken(at))
	}
	at := &cliconfigv1.State_Domain{SessionToken: &authv1.SessionToken{}, SessionTokenSetAt: pbutils.Timestamp(setAt)}
	assert.True(t, GetAccessTokenExpiresAt(at).IsZero())
	assert.True(t, GetRefreshTokenExpiresAt(at).IsZero())
	for _, itm := range []struct {
		expires int64
		gap     time.Duration
	}{
		{300, -10 * time.Minute}, {3599, -10 * time.Minute}, {3600, -30 * time.Minute}, {7201, -3600 * time.Second},
	} {
		at.SessionToken.ExpiresIn = itm.expires
		assert.Equal(t, itm.gap, getExpirationGap(itm.expires))
		assert.True(t, setAt.Add(time.Duration(itm.expires)*time.Second).Equal(GetAccessTokenExpiresAt(at)))
		assert.True(t, GetAccessTokenExpiresAt(at).Add(itm.gap).Equal(GetAccessTokenRenewAt(at)))
	}
	at.SessionToken.RefreshTokenExpiresIn = 7200
	assert.True(t, setAt.Add(2*time.Hour).Equal(GetRefreshTokenExpiresAt(at)))
	assert.True(t, HasValidRefreshToken(at))
	at.SessionToken.RefreshTokenExpiresIn = 60
	assert.False(t, HasValidRefreshToken(at))
}

func TestAuthenticationModes(t *testing.T) {
	ctx := context.Background()
	assert.False(t, IsNonInteractive(ctx))
	assert.True(t, IsNonInteractive(WithNonInteractive(ctx)))
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "static")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	assert.NoError(t, Authenticate(ctx, nil))
	StartGetAccessToken(ctx, "")
	token, err := GetAccessToken(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, "static", token)
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "proxy.sock")
	assert.NoError(t, Authenticate(ctx, nil))
	StartGetAccessToken(ctx, "")
	for _, fn := range []func(context.Context, string) (string, error){GetAccessToken, RenewAccessToken} {
		token, err := fn(ctx, "")
		require.NoError(t, err)
		assert.Empty(t, token)
	}
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	t.Setenv("OCTELIUM_DOMAIN", "")
	_, err = newAuthenticator(ctx, nil)
	assert.ErrorContains(t, err, "Cluster domain is not set")
	_, err = GetAccessToken(ctx, "")
	assert.ErrorContains(t, err, "Cluster domain is not set")
	assert.Error(t, Authenticate(ctx, nil))
}

func TestGetAssertionInputs(t *testing.T) {
	t.Setenv("OCTELIUM_TEST_JWT", "jwt-value")
	path := filepath.Join(t.TempDir(), "jwt")
	require.NoError(t, os.WriteFile(path, []byte("file-jwt"), 0600))
	for _, itm := range []struct {
		name string
		arg  *AuthenticateOptsAssertion
		want string
		err  string
	}{
		{"missing", nil, "", "No assertion argument"},
		{"empty", &AuthenticateOptsAssertion{}, "", "No assertion argument"},
		{"literal", &AuthenticateOptsAssertion{Assertion: "literal", IdentityProviderRef: &metav1.ObjectReference{Name: "provider"}}, "literal", ""},
		{"environment", &AuthenticateOptsAssertion{Arg: "jwt:env=OCTELIUM_TEST_JWT"}, "jwt-value", ""},
		{"file", &AuthenticateOptsAssertion{Arg: "jwt:file=" + path}, "file-jwt", ""},
		{"missing file", &AuthenticateOptsAssertion{Arg: "jwt:file=" + path + "-missing"}, "", "no such file"},
		{"unknown", &AuthenticateOptsAssertion{Arg: "invalid"}, "", "Could not get assertion type"},
		{"no options", &AuthenticateOptsAssertion{Arg: "jwt"}, "", "No JWT option"},
		{"wrong option", &AuthenticateOptsAssertion{Arg: "jwt:audience=example.com"}, "", "Neither env nor file"},
	} {
		t.Run(itm.name, func(t *testing.T) {
			a := &authenticator{opts: &AuthenticateOpts{Assertion: itm.arg}}
			ret, err := a.getAssertion(context.Background())
			if itm.err != "" {
				require.Error(t, err)
				if itm.name == "missing file" {
					assert.ErrorIs(t, err, os.ErrNotExist)
				} else {
					assert.Contains(t, err.Error(), itm.err)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, itm.want, ret.assertion)
			if itm.arg.Assertion != "" {
				assert.Equal(t, itm.arg.IdentityProviderRef, ret.identityProviderRef)
			}
		})
	}
}

func TestParseAssertionVariants(t *testing.T) {
	uid := "9cf5cddc-6a18-4d48-9a04-722846144d92"
	ret, err := parseAssertion(uid + ":jwt:env=TOKEN")
	require.NoError(t, err)
	assert.Equal(t, uid, ret.identityProviderRef.Uid)
	assert.Empty(t, ret.identityProviderRef.Name)
	assert.Equal(t, "TOKEN", ret.argMap["env"])
	for _, arg := range []string{"", "unsupported", "provider:unsupported"} {
		_, err := parseAssertion(arg)
		assert.Error(t, err)
	}
	assert.Equal(t, map[string]string{}, getArgMap(""))
	assert.Equal(t, map[string]string{"env": "last", "value": "a=b"}, getArgMap("ignored,env=first,value=a=b,env=last"))
	for _, arg := range []string{"k8s", "kubernetes", "azure", "provider:jwt:"} {
		_, err := parseAssertion(arg)
		assert.NoError(t, err)
	}
}

func TestGithubActionsAssertionHTTP(t *testing.T) {
	a := &authenticator{domain: "example.com"}
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	_, err := a.getAssertionGithubActions(context.Background(), "")
	assert.ErrorContains(t, err, "request token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")
	_, err = a.getAssertionGithubActions(context.Background(), "")
	assert.ErrorContains(t, err, "request URL")
	for _, itm := range []struct {
		name     string
		audience string
		code     int
		body     string
		want     string
	}{
		{"default audience", "", 200, `{"value":"jwt"}`, "jwt"},
		{"custom audience", "https://custom.example/path", 200, `{"value":"custom-jwt"}`, "custom-jwt"},
		{"denied", "", 403, `{"error":"denied"}`, ""},
		{"invalid response", "", 200, `{`, ""},
	} {
		t.Run(itm.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "Bearer request-token", r.Header.Get("Authorization"))
				assert.Equal(t, "kept", r.URL.Query().Get("existing"))
				want := itm.audience
				if want == "" {
					want = "https://example.com"
				}
				assert.Equal(t, want, r.URL.Query().Get("audience"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(itm.code)
				io.WriteString(w, itm.body)
			}))
			defer srv.Close()
			t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"?existing=kept")
			ret, err := a.getAssertionGithubActions(context.Background(), itm.audience)
			if itm.want == "" {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, itm.want, ret)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "http://127.0.0.1:1")
	_, err = a.getAssertionGithubActions(ctx, "")
	assert.Error(t, err)
}

func newAuthenticationTestContext(t *testing.T, path string, handler grpc.UnaryServerInterceptor) (context.Context, *db.DB) {
	t.Helper()
	for _, key := range []string{"OCTELIUM_ACCESS_TOKEN", "OCTELIUM_AUTH_PROXY_SOCKET", "OCTELIUM_AUTH_TOKEN", "OCTELIUM_AUTH_ASSERTION"} {
		t.Setenv(key, "")
	}
	t.Setenv("OCTELIUM_INSECURE_TLS", "true")
	certServer := httptest.NewTLSServer(nil)
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	previous := resolver.Get("dns")
	r := manual.NewBuilderWithScheme("dns")
	r.InitialState(resolver.State{Addresses: []resolver.Address{{Addr: lis.Addr().String()}}})
	resolver.Register(r)
	t.Cleanup(func() { resolver.Register(previous) })
	previousPassthrough := resolver.Get("passthrough")
	passthrough := manual.NewBuilderWithScheme("passthrough")
	passthrough.InitialState(resolver.State{Addresses: []resolver.Address{{Addr: lis.Addr().String()}}})
	resolver.Register(passthrough)
	t.Cleanup(func() { resolver.Register(previousPassthrough) })
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})), grpc.UnaryInterceptor(handler))
	authv1.RegisterMainServiceServer(srv, &authv1.UnimplementedMainServiceServer{})
	userv1.RegisterMainServiceServer(srv, &userv1.UnimplementedMainServiceServer{})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	d, err := db.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return cliutils.WithDB(ctx, d), d
}

func TestAssertionAuthenticationE2E(t *testing.T) {
	for _, path := range []string{"mem", t.TempDir()} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			var calls atomic.Int32
			ctx, d := newAuthenticationTestContext(t, path,
				func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
					calls.Add(1)
					assert.True(t, strings.HasSuffix(info.FullMethod, "/AuthenticateWithAssertion"))
					arg := req.(*authv1.AuthenticateWithAssertionRequest)
					assert.Equal(t, "signed-jwt", arg.Assertion)
					assert.Equal(t, []string{"service:api.default"}, arg.Scopes)
					assert.Equal(t, "provider", arg.IdentityProviderRef.GetName())
					return &authv1.SessionToken{AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 7200, RefreshTokenExpiresIn: 86400}, nil
				})
			opts := &AuthenticateOpts{Domain: "example.invalid", Scopes: []string{"service:api.default"}, Assertion: &AuthenticateOptsAssertion{
				Assertion: "signed-jwt", IdentityProviderRef: &metav1.ObjectReference{Name: "provider"},
			}}
			require.NoError(t, Authenticate(ctx, opts))
			token, err := d.GetSessionToken(opts.Domain)
			require.NoError(t, err)
			assert.Equal(t, "refresh", token.RefreshToken)
			got, err := GetAccessToken(WithNonInteractive(ctx), opts.Domain)
			require.NoError(t, err)
			assert.Equal(t, "access", got)
			assert.Equal(t, int32(1), calls.Load())
		})
	}
}

func TestAuthenticationTokenE2E(t *testing.T) {
	ctx, d := newAuthenticationTestContext(t, "mem",
		func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			switch {
			case strings.HasSuffix(info.FullMethod, "/AuthenticateWithAuthenticationToken"):
				arg := req.(*authv1.AuthenticateWithAuthenticationTokenRequest)
				assert.Equal(t, "auth-token", arg.AuthenticationToken)
				assert.Equal(t, []string{"service:api"}, arg.Scopes)
				assert.Equal(t, []byte("verifier"), arg.CodeVerifier)
				return &authv1.SessionToken{AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 7200, RefreshTokenExpiresIn: 86400}, nil
			case strings.HasSuffix(info.FullMethod, "/GetStatus"):
				md, _ := metadata.FromIncomingContext(ctx)
				assert.Equal(t, []string{"access"}, md.Get("x-octelium-auth"))
				return &userv1.GetStatusResponse{User: &userv1.GetStatusResponse_User{Metadata: &metav1.Metadata{Name: "user", DisplayName: "User"}}}, nil
			default:
				return handler(ctx, req)
			}
		})
	require.NoError(t, Authenticate(ctx, &AuthenticateOpts{Domain: "example.invalid", AuthToken: "auth-token", Scopes: []string{"service:api"}, CodeVerifier: []byte("verifier")}))
	token, err := d.GetSessionToken("example.invalid")
	require.NoError(t, err)
	assert.Equal(t, "access", token.AccessToken)
}

func TestRefreshAccessTokenE2E(t *testing.T) {
	for _, code := range []codes.Code{codes.OK, codes.AlreadyExists, codes.Unauthenticated, codes.PermissionDenied} {
		t.Run(code.String(), func(t *testing.T) {
			var calls atomic.Int32
			ctx, d := newAuthenticationTestContext(t, "mem",
				func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
					if !strings.HasSuffix(info.FullMethod, "/AuthenticateWithRefreshToken") {
						return handler(ctx, req)
					}
					calls.Add(1)
					md, _ := metadata.FromIncomingContext(ctx)
					assert.Equal(t, []string{"old-refresh"}, md.Get("x-octelium-refresh-token"))
					if code != codes.OK {
						return nil, status.Error(code, "refresh failed")
					}
					return &authv1.SessionToken{AccessToken: "new-access", RefreshToken: "new-refresh", ExpiresIn: 7200, RefreshTokenExpiresIn: 86400}, nil
				})
			domain := "example.invalid"
			require.NoError(t, d.SetSessionToken(domain, &authv1.SessionToken{AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresIn: 60, RefreshTokenExpiresIn: 86400}))
			got, err := GetAccessToken(WithNonInteractive(ctx), domain)
			switch code {
			case codes.OK:
				require.NoError(t, err)
				assert.Equal(t, "new-access", got)
				stored, err := d.GetSessionToken(domain)
				require.NoError(t, err)
				assert.Equal(t, "new-refresh", stored.RefreshToken)
			case codes.AlreadyExists:
				require.NoError(t, err)
				assert.Equal(t, "old-access", got)
			case codes.Unauthenticated:
				assert.ErrorIs(t, err, ErrAuthenticationRequired)
				_, err = d.GetSessionToken(domain)
				assert.ErrorIs(t, err, db.ErrNotFound)
			case codes.PermissionDenied:
				assert.Equal(t, codes.PermissionDenied, status.Code(err))
				stored, err := d.GetSessionToken(domain)
				require.NoError(t, err)
				assert.Equal(t, "old-refresh", stored.RefreshToken)
			}
			assert.Equal(t, int32(1), calls.Load())
		})
	}
}

func TestNewAuthenticatorSelection(t *testing.T) {
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_DOMAIN", "example.invalid")
	t.Setenv("OCTELIUM_AUTH_TOKEN", "env-token")
	t.Setenv("OCTELIUM_AUTH_ASSERTION", "jwt:env=JWT")
	d, err := db.Open("mem")
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	ctx := cliutils.WithDB(context.Background(), d)
	a, err := newAuthenticator(ctx, nil)
	require.NoError(t, err)
	originalClient := a.c
	t.Cleanup(func() { originalClient.Close() })
	assert.Equal(t, "example.invalid", a.domain)
	assert.Equal(t, "env-token", a.opts.AuthToken)
	assert.True(t, a.isAuthentication)
	t.Setenv("OCTELIUM_AUTH_TOKEN", "")
	a, err = newAuthenticator(ctx, &AuthenticateOpts{})
	require.NoError(t, err)
	defer a.c.Close()
	assert.Equal(t, "jwt:env=JWT", a.opts.Assertion.Arg)
	for _, web := range []bool{false, true} {
		a := &authenticator{isAuthentication: true, opts: &AuthenticateOpts{IsWeb: web}}
		_, err := a.doGetAccessToken(WithNonInteractive(ctx))
		assert.ErrorIs(t, err, ErrAuthenticationRequired)
	}
	_, err = (&authenticator{}).doGetAccessToken(ctx)
	assert.ErrorContains(t, err, "Neither a refresh nor an authentication flow")
	assert.NoError(t, (&authenticator{isRefresh: true}).doPostAuth(ctx))
	assert.NoError(t, (&authenticator{}).doPostAuth(ctx))
}

func TestWebAuthenticatorCallbackE2E(t *testing.T) {
	ctx, _ := newAuthenticationTestContext(t, "mem",
		func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			return handler(ctx, req)
		})
	s, err := NewWebAuthenticator(&WebAuthenticatorOpts{Domain: "example.invalid"})
	require.NoError(t, err)
	require.NoError(t, s.Start(ctx))
	t.Cleanup(func() { s.Close() })
	httpC := &http.Client{Timeout: time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	base := fmt.Sprintf("http://127.0.0.1:%d", s.port)
	for _, path := range []string{"/wrong", s.successCallbackPath} {
		resp, err := httpC.Get(base + path)
		require.NoError(t, err)
		resp.Body.Close()
		if path == "/wrong" {
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		} else {
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		}
	}
	b, err := pbutils.Marshal(&authv1.ClientLoginResponse{AuthenticationToken: "rejected", CodeChallenge: s.codeChallenge})
	require.NoError(t, err)
	resp, err := httpC.Get(base + s.successCallbackPath + "?octelium_response=" + base64.RawURLEncoding.EncodeToString(b))
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "https://example.invalid", resp.Header.Get("Location"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))
	assert.Equal(t, codes.Unimplemented, status.Code(s.Wait(ctx)))
	assert.NoError(t, s.Close())
	_, err = httpC.Get(base + s.successCallbackPath)
	assert.Error(t, err)
}

func TestWebAuthenticatorWaitAndClose(t *testing.T) {
	s, err := NewWebAuthenticator(&WebAuthenticatorOpts{Domain: "example.com"})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, s.Wait(ctx), context.Canceled)
	s.err = fmt.Errorf("callback error")
	close(s.ch)
	assert.ErrorIs(t, s.Wait(context.Background()), s.err)
	require.NoError(t, s.listen())
	assert.NoError(t, s.Close())
	for _, lis := range s.listeners {
		_, err := lis.Accept()
		assert.Error(t, err)
	}
}

func TestWebLoginBrowserProcess(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_BROWSER") != "true" {
		return
	}
	u, err := url.Parse(os.Args[len(os.Args)-1])
	require.NoError(t, err)
	b, err := base64.RawURLEncoding.DecodeString(u.Query().Get("octelium_req"))
	require.NoError(t, err)
	req := &authv1.ClientLoginRequest{}
	require.NoError(t, pbutils.Unmarshal(b, req))
	b, err = pbutils.Marshal(&authv1.ClientLoginResponse{AuthenticationToken: "browser-token", CodeChallenge: req.CodeChallenge})
	require.NoError(t, err)
	callback := fmt.Sprintf("http://127.0.0.1:%d/callback/success/%s?octelium_response=%s", req.CallbackPort, req.CallbackSuffix, base64.RawURLEncoding.EncodeToString(b))
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(callback)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
}

func TestWebAuthenticationE2E(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("browser helper requires a shell")
	}
	var calls atomic.Int32
	ctx, d := newAuthenticationTestContext(t, "mem",
		func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			switch {
			case strings.HasSuffix(info.FullMethod, "/AuthenticateWithAuthenticationToken"):
				calls.Add(1)
				arg := req.(*authv1.AuthenticateWithAuthenticationTokenRequest)
				assert.Equal(t, "browser-token", arg.AuthenticationToken)
				assert.Len(t, arg.CodeVerifier, opkce.VerifierLen)
				assert.Equal(t, []string{"service:web.default"}, arg.Scopes)
				return &authv1.SessionToken{AccessToken: "web-access", RefreshToken: "web-refresh", ExpiresIn: 7200, RefreshTokenExpiresIn: 86400}, nil
			case strings.HasSuffix(info.FullMethod, "/GetStatus"):
				return &userv1.GetStatusResponse{User: &userv1.GetStatusResponse_User{Metadata: &metav1.Metadata{Name: "web-user"}}}, nil
			}
			return handler(ctx, req)
		})
	dir := t.TempDir()
	browser := "xdg-open"
	if runtime.GOOS == "darwin" {
		browser = "open"
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, browser), []byte("#!/bin/sh\nexec \"$OCTELIUM_TEST_BINARY\" -test.run='^TestWebLoginBrowserProcess$' -- \"$1\"\n"), 0700))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OCTELIUM_TEST_BINARY", os.Args[0])
	t.Setenv("OCTELIUM_TEST_BROWSER", "true")
	require.NoError(t, Authenticate(ctx, &AuthenticateOpts{Domain: "example.invalid", IsWeb: true, Scopes: []string{"service:web.default"}}))
	token, err := d.GetSessionToken("example.invalid")
	require.NoError(t, err)
	assert.Equal(t, "web-access", token.AccessToken)
	assert.Equal(t, int32(1), calls.Load())
}

func TestRefreshUsesSessionRenewedDuringRPC(t *testing.T) {
	for _, code := range []codes.Code{codes.AlreadyExists, codes.Unauthenticated} {
		t.Run(code.String(), func(t *testing.T) {
			var d *db.DB
			ctx, database := newAuthenticationTestContext(t, "mem", func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				if strings.HasSuffix(info.FullMethod, "/AuthenticateWithRefreshToken") {
					assert.NoError(t, d.SetSessionToken("example.invalid", &authv1.SessionToken{AccessToken: "concurrent-access", RefreshToken: "concurrent-refresh", ExpiresIn: 7200, RefreshTokenExpiresIn: 86400}))
					return nil, status.Error(code, "another client refreshed")
				}
				return handler(ctx, req)
			})
			d = database
			require.NoError(t, d.SetSessionToken("example.invalid", &authv1.SessionToken{AccessToken: "old-access", RefreshToken: "old-refresh", ExpiresIn: 60, RefreshTokenExpiresIn: 86400}))
			ret, err := GetAccessToken(WithNonInteractive(ctx), "example.invalid")
			require.NoError(t, err)
			assert.Equal(t, "concurrent-access", ret)
			stored, err := d.GetSessionToken("example.invalid")
			require.NoError(t, err)
			assert.Equal(t, "concurrent-refresh", stored.RefreshToken)
		})
	}
}
