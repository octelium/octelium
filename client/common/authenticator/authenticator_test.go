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
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/common/opkce"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
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

	s, err := newWebAuthenticator("example.com", nil)
	assert.Nil(t, err)

	assert.Equal(t, opkce.VerifierLen, len(s.codeVerifier))
	assert.Equal(t, opkce.GetChallenge(s.codeVerifier), s.codeChallenge)

	assert.Equal(t, callbackSuffixLen, len(s.callbackSuffix))
	assert.LessOrEqual(t, callbackSuffixLen, 8)
	assert.Equal(t, fmt.Sprintf("/callback/success/%s", s.callbackSuffix), s.successCallbackPath)

	s.port = 12345

	u, err := url.Parse(s.getLoginURL())
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

	s, err := newWebAuthenticator("example.com", nil)
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

	s, err := newWebAuthenticator("example.com", nil)
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

	s, err := newWebAuthenticator("example.com", nil)
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
