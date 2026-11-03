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

package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func newGithubTestSecret(t *testing.T, ctx context.Context, tst *tests.T) *corev1.Secret {
	sec, err := tst.C.OcteliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(32),
			},
		},
	})
	assert.Nil(t, err)
	return sec
}

func newGithubIDP(clientID, secretName string) *corev1.IdentityProvider {
	return &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
			Uid:  utilrand.GetRandomStringCanonical(16),
		},
		Spec: &corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: clientID,
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: secretName,
						},
					},
				},
			},
		},
		Status: &corev1.IdentityProvider_Status{
			Type: corev1.IdentityProvider_Status_GITHUB,
		},
	}
}

func TestNewConnector(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	sec := newGithubTestSecret(t, ctx, tst)

	{
		_, err := NewConnector(ctx, &utils.ProviderOpts{
			OcteliumC:     fakeC.OcteliumC,
			ClusterConfig: cc,
			Provider: &corev1.IdentityProvider{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
				Spec: &corev1.IdentityProvider_Spec{},
			},
		})
		assert.NotNil(t, err)
	}

	{
		_, err := NewConnector(ctx, &utils.ProviderOpts{
			OcteliumC:     fakeC.OcteliumC,
			ClusterConfig: cc,
			Provider:      newGithubIDP("client-id", utilrand.GetRandomStringCanonical(8)),
		})
		assert.NotNil(t, err)
	}

	{
		idp := newGithubIDP("client-id", sec.Metadata.Name)

		c, err := NewConnector(ctx, &utils.ProviderOpts{
			OcteliumC:     fakeC.OcteliumC,
			ClusterConfig: cc,
			Provider:      idp,
		})
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, c)

		assert.Equal(t, idp.Metadata.Name, c.Name())
		assert.Equal(t, "github", c.Type())
		assert.Equal(t, idp.Metadata.Uid, c.Provider().Metadata.Uid)
	}
}

func TestOauth2Config(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	sec := newGithubTestSecret(t, ctx, tst)

	clientID := utilrand.GetRandomStringCanonical(16)

	c, err := NewConnector(ctx, &utils.ProviderOpts{
		OcteliumC:     fakeC.OcteliumC,
		ClusterConfig: cc,
		Provider:      newGithubIDP(clientID, sec.Metadata.Name),
	})
	assert.Nil(t, err)

	cfg := c.oauth2Config()

	assert.Equal(t, clientID, cfg.ClientID)
	assert.True(t, len(cfg.ClientSecret) > 0)
	assert.Equal(t, "https://github.com/login/oauth/authorize", cfg.Endpoint.AuthURL)
	assert.Equal(t, "https://github.com/login/oauth/access_token", cfg.Endpoint.TokenURL)
	assert.Equal(t, []string{"user:email"}, cfg.Scopes)
	assert.Equal(t, utils.GetCallbackURL(cc.Status.Domain), cfg.RedirectURL)
	assert.Equal(t, fmt.Sprintf("https://%s/callback", cc.Status.Domain), cfg.RedirectURL)
}

func TestGetLogin(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	sec := newGithubTestSecret(t, ctx, tst)

	clientID := utilrand.GetRandomStringCanonical(16)

	c, err := NewConnector(ctx, &utils.ProviderOpts{
		OcteliumC:     fakeC.OcteliumC,
		ClusterConfig: cc,
		Provider:      newGithubIDP(clientID, sec.Metadata.Name),
	})
	assert.Nil(t, err)

	state := utilrand.GetRandomStringCanonical(36)

	ret, err := c.GetLogin(httptest.NewRequest("GET", "/", nil), state)
	assert.Nil(t, err, "%+v", err)
	assert.True(t, len(ret.LoginURL) > 0)

	u, err := url.Parse(ret.LoginURL)
	assert.Nil(t, err)

	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, "github.com", u.Host)
	assert.Equal(t, "/login/oauth/authorize", u.Path)

	q := u.Query()
	assert.Equal(t, clientID, q.Get("client_id"))
	assert.Equal(t, state, q.Get("state"))
	assert.Equal(t, "user:email", q.Get("scope"))
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, utils.GetCallbackURL(cc.Status.Domain), q.Get("redirect_uri"))

	{
		other, err := c.GetLogin(httptest.NewRequest("GET", "/", nil),
			utilrand.GetRandomStringCanonical(36))
		assert.Nil(t, err)
		assert.NotEqual(t, ret.LoginURL, other.LoginURL)
	}
}

func TestHandleCallbackError(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	sec := newGithubTestSecret(t, ctx, tst)

	c, err := NewConnector(ctx, &utils.ProviderOpts{
		OcteliumC:     fakeC.OcteliumC,
		ClusterConfig: cc,
		Provider:      newGithubIDP("client-id", sec.Metadata.Name),
	})
	assert.Nil(t, err)

	{
		req := httptest.NewRequest("GET",
			"https://example.com/callback?error=access_denied&error_description=the+user+denied", nil)

		_, err := c.HandleCallback(req, nil)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "the user denied")
	}

	{
		req := httptest.NewRequest("GET",
			"https://example.com/callback?error=server_error", nil)

		_, err := c.HandleCallback(req, nil)
		assert.NotNil(t, err)
	}
}

func TestGetVerifiedPrimaryEmail(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		email  string
	}{
		{name: "Empty", status: http.StatusOK, body: `[]`},
		{name: "UnverifiedPrimary", status: http.StatusOK, body: `[{"email":"unverified@example.com","primary":true,"verified":false}]`},
		{name: "VerifiedPrimary", status: http.StatusOK, body: `[{"email":"secondary@example.com","verified":true},{"email":"primary@example.com","primary":true,"verified":true}]`, email: "primary@example.com"},
		{name: "VerifiedFallback", status: http.StatusOK, body: `[{"email":"unverified@example.com","primary":true},{"email":"first@example.com","verified":true},{"email":"second@example.com","verified":true}]`, email: "first@example.com"},
		{name: "MissingFields", status: http.StatusOK, body: `[{}]`},
		{name: "Unauthorized", status: http.StatusUnauthorized, body: `{"message":"Bad credentials"}`},
		{name: "RateLimited", status: http.StatusForbidden, body: `{"message":"API rate limit exceeded"}`},
		{name: "MalformedJSON", status: http.StatusOK, body: `[{`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/user/emails", r.URL.Path)
				assert.Equal(t, "100", r.URL.Query().Get("per_page"))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.body))
			}))
			t.Cleanup(srv.Close)
			baseURL := srv.URL + "/"
			c, err := github.NewClient(github.WithHTTPClient(srv.Client()), github.WithURLs(&baseURL, &baseURL))
			assert.Nil(t, err)
			assert.Equal(t, tt.email, getVerifiedPrimaryEmail(context.Background(), c))
		})
	}
}

type githubTestTransport func(*http.Request) (*http.Response, error)

func (f githubTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func githubTestResponse(r *http.Request, status int, body string) *http.Response {
	w := httptest.NewRecorder()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write([]byte(body))
	ret := w.Result()
	ret.Request = r
	return ret
}

func newGithubCallbackTest(t *testing.T, transport http.RoundTripper) (*Connector, *http.Request) {
	c := &Connector{
		c: newGithubIDP("client-id", "client-secret"),
		cc: &corev1.ClusterConfig{
			Status: &corev1.ClusterConfig_Status{Domain: "example.com"},
		},
		secret: "secret-value",
	}
	r := httptest.NewRequestWithContext(t.Context(), "GET", "https://example.com/callback?code=authorization-code", nil)
	r = r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, &http.Client{Transport: transport}))
	return c, r
}

func TestHandleCallback(t *testing.T) {
	for _, tt := range []struct {
		name        string
		tokenBody   string
		userStatus  int
		userBody    string
		emailStatus int
		emailBody   string
		email       string
		err         string
	}{
		{name: "VerifiedPrimary", emailBody: `[{"email":"secondary@example.com","verified":true},{"email":"primary@example.com","primary":true,"verified":true}]`, email: "primary@example.com"},
		{name: "UnverifiedEmail", emailBody: `[{"email":"unverified@example.com","primary":true,"verified":false}]`},
		{name: "EmailLookupFailure", emailStatus: http.StatusForbidden, emailBody: `{"message":"Forbidden"}`},
		{name: "ExpiredToken", tokenBody: `{"access_token":"github-token","token_type":"bearer","expires_in":-1}`, err: "Invalid token"},
		{name: "TokenExchangeFailure", tokenBody: `{"error":"bad_verification_code"}`, err: "Could not get token"},
		{name: "UserLookupFailure", userStatus: http.StatusUnauthorized, userBody: `{"message":"Bad credentials"}`, err: "Could not get user"},
		{name: "MalformedUser", userBody: `{"login":`, err: "Could not get user"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var userRequested, emailsRequested bool
			transport := githubTestTransport(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Host + r.URL.Path {
				case "github.com/login/oauth/access_token":
					assert.Equal(t, "POST", r.Method)
					require.NoError(t, r.ParseForm())
					assert.Equal(t, "authorization-code", r.Form.Get("code"))
					assert.Equal(t, "https://example.com/callback", r.Form.Get("redirect_uri"))
					clientID, secret, ok := r.BasicAuth()
					if !ok {
						clientID, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
					}
					assert.Equal(t, "client-id", clientID)
					assert.Equal(t, "secret-value", secret)
					body := tt.tokenBody
					if body == "" {
						body = `{"access_token":"github-token","token_type":"bearer"}`
					}
					return githubTestResponse(r, http.StatusOK, body), nil
				case "api.github.com/user":
					userRequested = true
					assert.Equal(t, "GET", r.Method)
					assert.Equal(t, "Bearer github-token", r.Header.Get("Authorization"))
					status := tt.userStatus
					if status == 0 {
						status = http.StatusOK
					}
					body := tt.userBody
					if body == "" {
						body = `{"login":"octocat","email":"unverified@example.com","avatar_url":"https://avatars.githubusercontent.com/octocat"}`
					}
					return githubTestResponse(r, status, body), nil
				case "api.github.com/user/emails":
					emailsRequested = true
					assert.Equal(t, "GET", r.Method)
					assert.Equal(t, "Bearer github-token", r.Header.Get("Authorization"))
					assert.Equal(t, "100", r.URL.Query().Get("per_page"))
					status := tt.emailStatus
					if status == 0 {
						status = http.StatusOK
					}
					return githubTestResponse(r, status, tt.emailBody), nil
				default:
					return nil, fmt.Errorf("unexpected GitHub request: %s", r.URL)
				}
			})
			c, r := newGithubCallbackTest(t, transport)
			ret, err := c.HandleCallback(r, nil)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)
				assert.Nil(t, ret)
				assert.False(t, emailsRequested)
				if tt.tokenBody != "" {
					assert.False(t, userRequested)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, ret)
			assert.True(t, userRequested)
			assert.True(t, emailsRequested)
			assert.Equal(t, corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER, ret.Type)
			info := ret.GetIdentityProvider()
			require.NotNil(t, info)
			assert.Equal(t, corev1.IdentityProvider_Status_GITHUB, info.Type)
			assert.Equal(t, c.c.Metadata.Name, info.IdentityProviderRef.Name)
			assert.Equal(t, "octocat", info.Identifier)
			assert.Equal(t, tt.email, info.Email)
			assert.Equal(t, "https://avatars.githubusercontent.com/octocat", info.PicURL)
		})
	}
}

func TestHandleCallbackRedirectCredentials(t *testing.T) {
	for _, tt := range []struct {
		name       string
		url        string
		authorized bool
	}{
		{"APIOrigin", "https://api.github.com/redirected-user", true},
		{"UploadOrigin", "https://uploads.github.com/redirected-user", true},
		{"OtherHost", "https://example.net/redirected-user", false},
		{"Subdomain", "https://sub.api.github.com/redirected-user", false},
		{"OtherPort", "https://api.github.com:8443/redirected-user", false},
		{"Downgrade", "http://api.github.com/redirected-user", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var redirected, emailsRequested bool
			transport := githubTestTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() == tt.url {
					redirected = true
					if tt.authorized {
						assert.Equal(t, "Bearer github-token", r.Header.Get("Authorization"))
					} else {
						assert.Empty(t, r.Header.Get("Authorization"))
					}
					return githubTestResponse(r, http.StatusOK, `{"login":"octocat"}`), nil
				}
				switch r.URL.String() {
				case "https://github.com/login/oauth/access_token":
					return githubTestResponse(r, http.StatusOK, `{"access_token":"github-token","token_type":"bearer"}`), nil
				case "https://api.github.com/user":
					assert.Equal(t, "Bearer github-token", r.Header.Get("Authorization"))
					response := githubTestResponse(r, http.StatusFound, "")
					response.Header.Set("Location", tt.url)
					return response, nil
				case "https://api.github.com/user/emails?per_page=100":
					emailsRequested = true
					assert.Equal(t, "Bearer github-token", r.Header.Get("Authorization"))
					return githubTestResponse(r, http.StatusOK, `[{"email":"primary@example.com","primary":true,"verified":true}]`), nil
				default:
					return nil, fmt.Errorf("unexpected GitHub request: %s", r.URL)
				}
			})
			c, r := newGithubCallbackTest(t, transport)
			ret, err := c.HandleCallback(r, nil)
			require.NoError(t, err)
			require.NotNil(t, ret)
			assert.True(t, redirected)
			assert.True(t, emailsRequested)
			assert.Equal(t, "octocat", ret.GetIdentityProvider().Identifier)
			assert.Equal(t, "primary@example.com", ret.GetIdentityProvider().Email)
		})
	}
}

func TestHandleCallbackCancellation(t *testing.T) {
	for _, path := range []string{"/login/oauth/access_token", "/user", "/user/emails"} {
		t.Run(path, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var canceled bool
			transport := githubTestTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == path {
					canceled = true
					cancel()
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				switch r.URL.Path {
				case "/login/oauth/access_token":
					return githubTestResponse(r, http.StatusOK, `{"access_token":"github-token","token_type":"bearer"}`), nil
				case "/user":
					return githubTestResponse(r, http.StatusOK, `{"login":"octocat","email":"unverified@example.com"}`), nil
				default:
					return nil, fmt.Errorf("unexpected GitHub request: %s", r.URL)
				}
			})
			c, r := newGithubCallbackTest(t, transport)
			r = r.WithContext(context.WithValue(ctx, oauth2.HTTPClient, r.Context().Value(oauth2.HTTPClient)))
			ret, err := c.HandleCallback(r, nil)
			assert.True(t, canceled)
			if path == "/user/emails" {
				require.NoError(t, err)
				require.NotNil(t, ret)
				assert.Empty(t, ret.GetIdentityProvider().Email)
				return
			}
			require.ErrorContains(t, err, context.Canceled.Error())
			assert.Nil(t, ret)
		})
	}
}
