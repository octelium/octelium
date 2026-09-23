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
	"encoding/base64"
	"fmt"
	"net/url"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/pkg/common/clientlogin"
	"github.com/octelium/octelium/pkg/common/opkce"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func TestAppAuthenticatorLoginURL(t *testing.T) {

	{
		_, err := NewAppAuthenticator(nil)
		assert.NotNil(t, err)
	}
	{
		_, err := NewAppAuthenticator(&AppAuthenticatorOpts{})
		assert.NotNil(t, err)
	}

	s, err := NewAppAuthenticator(&AppAuthenticatorOpts{
		Domain: "example.com",
		Scopes: []string{"service:default"},
	})
	assert.Nil(t, err)

	assert.Equal(t, opkce.VerifierLen, len(s.codeVerifier))
	assert.Equal(t, opkce.GetChallenge(s.codeVerifier), s.codeChallenge)

	u, err := url.Parse(s.GetLoginURL())
	assert.Nil(t, err)
	assert.Equal(t, "https", u.Scheme)
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
	assert.Equal(t, authv1.ClientLoginRequest_APP, req.CallbackType)
	assert.Equal(t, uint32(0), req.CallbackPort)
	assert.Equal(t, "", req.CallbackSuffix)
	assert.Equal(t, s.codeChallenge, req.CodeChallenge)

	other, err := NewAppAuthenticator(&AppAuthenticatorOpts{
		Domain: "example.com",
	})
	assert.Nil(t, err)
	assert.NotEqual(t, s.codeVerifier, other.codeVerifier)
	assert.NotEqual(t, s.GetLoginURL(), other.GetLoginURL())
}

func TestAppAuthenticatorGetLoginResponse(t *testing.T) {

	s, err := NewAppAuthenticator(&AppAuthenticatorOpts{
		Domain: "example.com",
	})
	assert.Nil(t, err)

	encode := func(resp *authv1.ClientLoginResponse) string {
		b, err := pbutils.Marshal(resp)
		assert.Nil(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}

	validResp := encode(&authv1.ClientLoginResponse{
		AuthenticationToken: "token",
		CodeChallenge:       s.codeChallenge,
	})

	{
		resp, err := s.GetLoginResponse(fmt.Sprintf("%s?octelium_response=%s",
			clientlogin.AppCallbackURL, validResp))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "token", resp.AuthenticationToken)
	}

	{
		resp, err := s.GetLoginResponse(fmt.Sprintf("COM.Octelium.Client:%s?octelium_response=%s",
			clientlogin.AppCallbackPath, validResp))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "token", resp.AuthenticationToken)
	}

	{
		resp, err := s.GetLoginResponse(fmt.Sprintf("%s://%s?octelium_response=%s",
			clientlogin.AppCallbackScheme, clientlogin.AppCallbackPath, validResp))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "token", resp.AuthenticationToken)
	}

	invalidURLs := []string{
		"",
		"::::",
		clientlogin.AppCallbackURL,
		fmt.Sprintf("https://example.com%s?octelium_response=%s", clientlogin.AppCallbackPath, validResp),
		fmt.Sprintf("http://localhost:12345%s?octelium_response=%s", clientlogin.AppCallbackPath, validResp),
		fmt.Sprintf("com.octelium.other:%s?octelium_response=%s", clientlogin.AppCallbackPath, validResp),
		fmt.Sprintf("%s://evil.com%s?octelium_response=%s",
			clientlogin.AppCallbackScheme, clientlogin.AppCallbackPath, validResp),
		fmt.Sprintf("%s://user@%s?octelium_response=%s",
			clientlogin.AppCallbackScheme, clientlogin.AppCallbackPath, validResp),
		fmt.Sprintf("%s:callback/success?octelium_response=%s", clientlogin.AppCallbackScheme, validResp),
		fmt.Sprintf("%s:/callback/success/abcd?octelium_response=%s", clientlogin.AppCallbackScheme, validResp),
		fmt.Sprintf("%s?octelium_response=not-base64-$$$", clientlogin.AppCallbackURL),
		fmt.Sprintf("%s?octelium_response=%s", clientlogin.AppCallbackURL,
			base64.RawURLEncoding.EncodeToString([]byte{0xff, 0xff, 0xff})),
		fmt.Sprintf("%s?octelium_response=%s", clientlogin.AppCallbackURL,
			encode(&authv1.ClientLoginResponse{
				CodeChallenge: s.codeChallenge,
			})),
		fmt.Sprintf("%s?octelium_response=%s", clientlogin.AppCallbackURL,
			encode(&authv1.ClientLoginResponse{
				AuthenticationToken: "token",
			})),
		fmt.Sprintf("%s?octelium_response=%s", clientlogin.AppCallbackURL,
			encode(&authv1.ClientLoginResponse{
				AuthenticationToken: "token",
				CodeChallenge:       s.codeChallenge[:opkce.ChallengeLen-1],
			})),
		fmt.Sprintf("%s?octelium_response=%s", clientlogin.AppCallbackURL,
			encode(&authv1.ClientLoginResponse{
				AuthenticationToken: "token",
				CodeChallenge:       opkce.GetChallenge(s.codeChallenge),
			})),
	}

	for _, arg := range invalidURLs {
		_, err := s.GetLoginResponse(arg)
		assert.NotNil(t, err, "url: %s", arg)
	}
}

func TestAppAuthenticatorComplete(t *testing.T) {

	s, err := NewAppAuthenticator(&AppAuthenticatorOpts{
		Domain: "example.com",
	})
	assert.Nil(t, err)

	assert.NotNil(t, s.Complete(nil))

	resp := &authv1.ClientLoginResponse{
		AuthenticationToken: "token",
		CodeChallenge:       s.codeChallenge,
	}

	assert.Nil(t, s.Complete(resp))
	assert.NotNil(t, s.Complete(resp))

	assert.Equal(t, resp, <-s.respCh)
}

func TestAppAuthenticatorWaitCanceled(t *testing.T) {

	s, err := NewAppAuthenticator(&AppAuthenticatorOpts{
		Domain: "example.com",
	})
	assert.Nil(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = s.Wait(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestAppAuthenticatorWaitAuthProxyMode(t *testing.T) {
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "/run/octelium/auth.sock")

	s, err := NewAppAuthenticator(&AppAuthenticatorOpts{
		Domain: "example.com",
	})
	assert.Nil(t, err)

	assert.Nil(t, s.Complete(&authv1.ClientLoginResponse{
		AuthenticationToken: "token",
		CodeChallenge:       s.codeChallenge,
	}))

	assert.Nil(t, s.Wait(context.Background()))
}
