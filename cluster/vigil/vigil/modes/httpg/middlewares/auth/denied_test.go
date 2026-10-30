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

package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestHandleUnauthorized(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	m := &middleware{
		domain: "example.com",
	}

	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rw := httptest.NewRecorder()
		m.handleUnauthorized(rw, req, &middlewares.RequestContext{
			Service: &corev1.Service{
				Spec: &corev1.Service_Spec{
					IsPublic: true,
					Mode:     corev1.Service_Spec_HTTP,
				},
			},
		})

		assert.Equal(t, http.StatusUnauthorized, rw.Code)
		assert.Equal(t, "true", rw.Header().Get("X-Octelium-Unauthorized"))
	}
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rw := httptest.NewRecorder()
		m.handleUnauthorized(rw, req, &middlewares.RequestContext{
			IsAuthenticated: true,
			Service: &corev1.Service{
				Spec: &corev1.Service_Spec{
					IsPublic: true,
					Mode:     corev1.Service_Spec_HTTP,
				},
			},
		})

		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Equal(t, "true", rw.Header().Get("X-Octelium-Unauthorized"))
	}
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rw := httptest.NewRecorder()
		m.handleUnauthorized(rw, req, &middlewares.RequestContext{
			Service: &corev1.Service{
				Spec: &corev1.Service_Spec{
					IsPublic: true,
					Mode:     corev1.Service_Spec_GRPC,
				},
			},
		})

		assert.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, "true", rw.Header().Get("X-Octelium-Unauthorized"))
		assert.Equal(t, fmt.Sprintf("%d", codes.Unauthenticated), rw.Header().Get("Grpc-Status"))
		assert.Equal(t, "Octelium: Unauthenticated", rw.Header().Get("Grpc-Message"))
	}
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rw := httptest.NewRecorder()
		m.handleUnauthorized(rw, req, &middlewares.RequestContext{
			IsAuthenticated: true,
			Service: &corev1.Service{
				Spec: &corev1.Service_Spec{
					IsPublic: true,
					Mode:     corev1.Service_Spec_GRPC,
				},
			},
		})

		assert.Equal(t, http.StatusOK, rw.Code)
		assert.Equal(t, "true", rw.Header().Get("X-Octelium-Unauthorized"))
		assert.Equal(t, fmt.Sprintf("%d", codes.PermissionDenied), rw.Header().Get("Grpc-Status"))
		assert.Equal(t, "Octelium: Unauthorized", rw.Header().Get("Grpc-Message"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rw := httptest.NewRecorder()
		m.handleUnauthorized(rw, req, &middlewares.RequestContext{
			Service: &corev1.Service{
				Spec: &corev1.Service_Spec{
					IsAnonymous: true,
					IsPublic:    true,
					Mode:        corev1.Service_Spec_HTTP,
					Authorization: &corev1.Service_Spec_Authorization{
						EnableAnonymous: true,
					},
				},
			},
		})

		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Equal(t, "true", rw.Header().Get("X-Octelium-Unauthorized"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept", "text/html")
		rw := httptest.NewRecorder()
		m.handleUnauthorized(rw, req, &middlewares.RequestContext{
			Service: &corev1.Service{
				Spec: &corev1.Service_Spec{
					IsAnonymous: true,
					IsPublic:    true,
					Mode:        corev1.Service_Spec_HTTP,
					Authorization: &corev1.Service_Spec_Authorization{
						EnableAnonymous: true,
					},
				},
			},
		})

		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Equal(t, "true", rw.Header().Get("X-Octelium-Unauthorized"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("user-agent",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1")
		rw := httptest.NewRecorder()
		m.handleUnauthorized(rw, req, &middlewares.RequestContext{
			Service: &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
				},
				Spec: &corev1.Service_Spec{
					IsPublic: true,
					Mode:     corev1.Service_Spec_HTTP,
				},
				Status: &corev1.Service_Status{
					NamespaceRef: &metav1.ObjectReference{
						Name: "default",
					},
				},
			},
		})

		assert.Equal(t, http.StatusSeeOther, rw.Code)
		assert.Equal(t, "true", rw.Header().Get("X-Octelium-Unauthorized"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("user-agent",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1")
		rw := httptest.NewRecorder()
		m.handleUnauthorized(rw, req, &middlewares.RequestContext{
			IsAuthenticated: true,
			DownstreamInfo: &corev1.RequestContext{
				User: &corev1.User{
					Spec: &corev1.User_Spec{
						Type: corev1.User_Spec_HUMAN,
					},
				},
			},
			Service: &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
				},
				Spec: &corev1.Service_Spec{
					IsPublic: true,
					Mode:     corev1.Service_Spec_HTTP,
				},
				Status: &corev1.Service_Status{
					NamespaceRef: &metav1.ObjectReference{
						Name: "default",
					},
				},
			},
		})

		assert.Equal(t, http.StatusSeeOther, rw.Code)
		assert.Equal(t, "true", rw.Header().Get("X-Octelium-Unauthorized"))
		assert.Equal(t, fmt.Sprintf("https://%s/denied", m.domain), rw.Header().Get("Location"))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("user-agent",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1")
		rw := httptest.NewRecorder()
		m.handleUnauthorized(rw, req, &middlewares.RequestContext{
			IsAuthenticated: true,
			DownstreamInfo: &corev1.RequestContext{
				User: &corev1.User{
					Spec: &corev1.User_Spec{
						Type: corev1.User_Spec_WORKLOAD,
					},
				},
			},
			Service: &corev1.Service{
				Metadata: &metav1.Metadata{
					Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
				},
				Spec: &corev1.Service_Spec{
					IsPublic: true,
					Mode:     corev1.Service_Spec_HTTP,
				},
				Status: &corev1.Service_Status{
					NamespaceRef: &metav1.ObjectReference{
						Name: "default",
					},
				},
			},
		})

		assert.Equal(t, http.StatusForbidden, rw.Code)
		assert.Equal(t, "true", rw.Header().Get("X-Octelium-Unauthorized"))
	}
}

func TestLoginRedirectPreservesEscapedPath(t *testing.T) {
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "app.default"},
		Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, IsPublic: true},
		Status:   &corev1.Service_Status{NamespaceRef: &metav1.ObjectReference{Name: "default"}},
	}
	m := &middleware{domain: "example.com"}
	for _, path := range []string{"/items/plain?q=value", "/items/a%2Fb?q=one%2Ftwo", "/items/a%3Fb%23c?q=value"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com"+path, nil)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
			rw := httptest.NewRecorder()
			m.handleUnauthorized(rw, req, &middlewares.RequestContext{Service: svc})
			require.Equal(t, http.StatusSeeOther, rw.Code)
			location, err := url.Parse(rw.Header().Get("Location"))
			require.Nil(t, err)
			assert.Equal(t, "https://"+vutils.GetServicePublicFQDN(svc, m.domain)+path, location.Query().Get("redirect"))
		})
	}
}

func TestLoginRedirectRejectsMalformedForwardedHost(t *testing.T) {
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "app.default"},
		Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, IsPublic: true},
		Status: &corev1.Service_Status{
			NamespaceRef:   &metav1.ObjectReference{Name: "default"},
			ManagedService: &corev1.Service_Status_ManagedService{ForwardHost: true},
		},
	}
	m := &middleware{domain: "example.com"}
	for _, host := range []string{"custom.example.com", "example.com", "attacker.test/path.example.com", "attacker.test?next=.example.com", "attacker.test#fragment.example.com"} {
		t.Run(host, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
			req.Header.Set("Accept", "text/html")
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
			req.Header.Set("X-Forwarded-Host", host)
			rw := httptest.NewRecorder()
			m.handleUnauthorized(rw, req, &middlewares.RequestContext{Service: svc})
			require.Equal(t, http.StatusSeeOther, rw.Code)
			location, err := url.Parse(rw.Header().Get("Location"))
			require.Nil(t, err)
			redirect, err := url.Parse(location.Query().Get("redirect"))
			require.Nil(t, err)
			wantHost := vutils.GetServicePublicFQDN(svc, m.domain)
			if host == "custom.example.com" || host == "example.com" {
				wantHost = host
			}
			assert.Equal(t, wantHost, redirect.Hostname())
			assert.Nil(t, redirect.User)
		})
	}
}

func newLoginRedirectTestService() *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{Name: "app.default"},
		Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, IsPublic: true},
		Status:   &corev1.Service_Status{NamespaceRef: &metav1.ObjectReference{Name: "default"}},
	}
}

func newLoginRedirectTestRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
	return req
}

func TestLoginRedirectEncodedTargets(t *testing.T) {
	for _, forwarded := range []bool{false, true} {
		t.Run(fmt.Sprintf("Forwarded=%t", forwarded), func(t *testing.T) {
			for _, tc := range []struct {
				path string
				want string
			}{
				{"/", "/"},
				{"/items/plain?q=value", "/items/plain?q=value"},
				{"/items/a%2Fb?q=one%2Ftwo", "/items/a%2Fb?q=one%2Ftwo"},
				{"/items/a%2fb%3fc%23d?q=%2f%3f%23", "/items/a%2fb%3fc%23d?q=%2f%3f%23"},
				{"/items/a%3Fb%23c?q=value", "/items/a%3Fb%23c?q=value"},
				{"/items/a%252Fb%253Fc%2523d?q=%2526%253D", "/items/a%252Fb%253Fc%2523d?q=%2526%253D"},
				{"/items/a%20b?q=a+b&literal=a%2Bb", "/items/a%20b?q=a+b&literal=a%2Bb"},
				{"/items/%E4%B8%AD/%F0%9F%94%92?q=%E2%9C%93", "/items/%E4%B8%AD/%F0%9F%94%92?q=%E2%9C%93"},
				{"/items/café?q=%E2%9C%93", "/items/caf%C3%A9?q=%E2%9C%93"},
				{"/items/100%25?q=%25", "/items/100%25?q=%25"},
				{"/items/a%3Fb?redirect=https%3A%2F%2Foutside.test%2Fstart%3Fx%3D1%26y%3D2&redirect=second", "/items/a%3Fb?redirect=https%3A%2F%2Foutside.test%2Fstart%3Fx%3D1%26y%3D2&redirect=second"},
				{"/items/item?z=1&a=2&a=&empty=&flag&encoded=%26key%3Dvalue&semi=x;y", "/items/item?z=1&a=2&a=&empty=&flag&encoded=%26key%3Dvalue&semi=x;y"},
				{"/items/item?", "/items/item?"},
				{"?q=value", "?q=value"},
				{"?", "?"},
				{"/items//a%2Fpart", "/items//a%2Fpart"},
				{"/%2F%2Fattacker.test/%40name?q=value", "/%2F%2Fattacker.test/%40name?q=value"},
				{"//attacker.test/path?q=value", "//attacker.test/path?q=value"},
				{"/items/%5C%5Cattacker.test?q=value", "/items/%5C%5Cattacker.test?q=value"},
			} {
				t.Run(tc.path, func(t *testing.T) {
					m := &middleware{domain: "example.com"}
					svc := newLoginRedirectTestService()
					req := newLoginRedirectTestRequest(t, "https://app.example.com"+tc.path)
					wantHost := vutils.GetServicePublicFQDN(svc, m.domain)
					if forwarded {
						svc.Status.ManagedService = &corev1.Service_Status_ManagedService{ForwardHost: true}
						req.Header.Set("X-Forwarded-Host", "custom.example.com")
						wantHost = "custom.example.com"
					}
					original := *req.URL
					rw := httptest.NewRecorder()
					m.handleUnauthorized(rw, req, &middlewares.RequestContext{Service: svc})
					require.Equal(t, http.StatusSeeOther, rw.Code)
					assert.Equal(t, "true", rw.Header().Get("X-Octelium-Unauthorized"))
					location, err := url.Parse(rw.Header().Get("Location"))
					require.Nil(t, err)
					assert.Equal(t, "https", location.Scheme)
					assert.Equal(t, m.domain, location.Host)
					assert.Equal(t, "/login", location.Path)
					assert.Empty(t, location.Fragment)
					query, err := url.ParseQuery(location.RawQuery)
					require.Nil(t, err)
					require.Len(t, query, 1)
					require.Len(t, query["redirect"], 1)
					assert.Equal(t, "https://"+wantHost+tc.want, query.Get("redirect"))
					target, err := url.Parse(query.Get("redirect"))
					require.Nil(t, err)
					assert.Equal(t, "https", target.Scheme)
					assert.Equal(t, wantHost, target.Host)
					assert.Nil(t, target.User)
					assert.Empty(t, target.Fragment)
					assert.Equal(t, req.URL.Path, target.Path)
					assert.Equal(t, req.URL.RawQuery, target.RawQuery)
					assert.Equal(t, req.URL.ForceQuery, target.ForceQuery)
					assert.Equal(t, original, *req.URL)
				})
			}
		})
	}
}

func TestLoginRedirectURLFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  *url.URL
		want string
	}{
		{name: "EmptyPath", url: &url.URL{}, want: ""},
		{name: "EmptyQuery", url: &url.URL{Path: "/items", ForceQuery: true}, want: "/items?"},
		{name: "InvalidRawPath", url: &url.URL{Path: "/items/a?b#c", RawPath: "/items/a%zz"}, want: "/items/a%3Fb%23c"},
		{name: "MismatchedRawPath", url: &url.URL{Path: "/items/a?b#c", RawPath: "//attacker.test/other"}, want: "/items/a%3Fb%23c"},
		{name: "LiteralRawSeparators", url: &url.URL{Path: "/items/a?b#c", RawPath: "/items/a?b#c"}, want: "/items/a%3Fb%23c"},
		{name: "ValidRawPath", url: &url.URL{Path: "/items/a/b?c", RawPath: "/items/a%2fb%3fc", RawQuery: "q=%26%3D%23"}, want: "/items/a%2fb%3fc?q=%26%3D%23"},
		{name: "ControlCharacters", url: &url.URL{Path: "/items/\r\nLocation:evil"}, want: "/items/%0D%0ALocation:evil"},
		{name: "UnrelatedURLFields", url: &url.URL{
			Scheme: "http", Host: "attacker.test", User: url.UserPassword("attacker", "password"),
			Opaque: "//attacker.test/other", Fragment: "client-side", RawFragment: "client-side",
			Path: "/items/a?b#c", RawQuery: "redirect=https%3A%2F%2Foutside.test",
		}, want: "/items/a%3Fb%23c?redirect=https%3A%2F%2Foutside.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &middleware{domain: "example.com"}
			svc := newLoginRedirectTestService()
			req := newLoginRedirectTestRequest(t, "https://app.example.com/")
			req.URL = tc.url
			original := *req.URL
			rw := httptest.NewRecorder()
			m.handleUnauthorized(rw, req, &middlewares.RequestContext{Service: svc})
			require.Equal(t, http.StatusSeeOther, rw.Code)
			location, err := url.Parse(rw.Header().Get("Location"))
			require.Nil(t, err)
			wantHost := vutils.GetServicePublicFQDN(svc, m.domain)
			assert.Equal(t, "https://"+wantHost+tc.want, location.Query().Get("redirect"))
			target, err := url.Parse(location.Query().Get("redirect"))
			require.Nil(t, err)
			assert.Equal(t, wantHost, target.Host)
			assert.Nil(t, target.User)
			assert.Empty(t, target.Fragment)
			assert.Equal(t, req.URL.Path, target.Path)
			assert.Equal(t, original, *req.URL)
		})
	}
}

func TestLoginRedirectHostSelection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		managed bool
		forward bool
		host    string
		want    string
	}{
		{name: "OrdinaryService", host: "custom.example.com"},
		{name: "ForwardingDisabled", managed: true, host: "custom.example.com"},
		{name: "ManagedSubdomain", managed: true, forward: true, host: "custom.example.com", want: "custom.example.com"},
		{name: "ManagedRoot", managed: true, forward: true, host: "example.com", want: "example.com"},
		{name: "UnrelatedHost", managed: true, forward: true, host: "outside.test"},
		{name: "SuffixBoundary", managed: true, forward: true, host: "notexample.com"},
		{name: "EmptyHost", managed: true, forward: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &middleware{domain: "example.com"}
			svc := newLoginRedirectTestService()
			if tc.managed {
				svc.Status.ManagedService = &corev1.Service_Status_ManagedService{ForwardHost: tc.forward}
			}
			req := newLoginRedirectTestRequest(t, "https://app.example.com/items/a%2Fb%3Fc%23d?q=%2F")
			req.Header.Set("X-Forwarded-Host", tc.host)
			rw := httptest.NewRecorder()
			m.handleUnauthorized(rw, req, &middlewares.RequestContext{Service: svc})
			require.Equal(t, http.StatusSeeOther, rw.Code)
			location, err := url.Parse(rw.Header().Get("Location"))
			require.Nil(t, err)
			wantHost := tc.want
			if wantHost == "" {
				wantHost = vutils.GetServicePublicFQDN(svc, m.domain)
			}
			assert.Equal(t, "https://"+wantHost+"/items/a%2Fb%3Fc%23d?q=%2F", location.Query().Get("redirect"))
		})
	}
}

func TestLoginRedirectEligibility(t *testing.T) {
	for _, tc := range []struct {
		name          string
		method        string
		accept        string
		userAgent     string
		private       bool
		anonymous     bool
		authenticated bool
		userType      corev1.User_Spec_Type
		status        int
		location      string
	}{
		{name: "Browser", status: http.StatusSeeOther, location: "/login"},
		{name: "PrivateService", private: true, status: http.StatusSeeOther, location: "/login"},
		{name: "AnonymousAuthorization", anonymous: true, status: http.StatusForbidden},
		{name: "AuthenticatedHuman", authenticated: true, userType: corev1.User_Spec_HUMAN, status: http.StatusSeeOther, location: "/denied"},
		{name: "AuthenticatedWorkload", authenticated: true, userType: corev1.User_Spec_WORKLOAD, status: http.StatusForbidden},
		{name: "NonHTML", accept: "application/json", status: http.StatusUnauthorized},
		{name: "NonBrowser", userAgent: "curl/8.0", status: http.StatusUnauthorized},
		{name: "Post", method: http.MethodPost, status: http.StatusUnauthorized},
		{name: "Head", method: http.MethodHead, status: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &middleware{domain: "example.com"}
			svc := newLoginRedirectTestService()
			svc.Spec.IsPublic = !tc.private
			if tc.anonymous {
				svc.Spec.IsAnonymous = true
				svc.Spec.Authorization = &corev1.Service_Spec_Authorization{EnableAnonymous: true}
			}
			req := newLoginRedirectTestRequest(t, "https://app.example.com/items/a%3Fb%23c?q=value")
			if tc.method != "" {
				req.Method = tc.method
			}
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			if tc.userAgent != "" {
				req.Header.Set("User-Agent", tc.userAgent)
			}
			reqCtx := &middlewares.RequestContext{Service: svc, IsAuthenticated: tc.authenticated}
			if tc.authenticated {
				reqCtx.DownstreamInfo = &corev1.RequestContext{User: &corev1.User{Spec: &corev1.User_Spec{Type: tc.userType}}}
			}
			rw := httptest.NewRecorder()
			m.handleUnauthorized(rw, req, reqCtx)
			assert.Equal(t, tc.status, rw.Code)
			if tc.location == "" {
				assert.Empty(t, rw.Header().Get("Location"))
				return
			}
			location, err := url.Parse(rw.Header().Get("Location"))
			require.Nil(t, err)
			assert.Equal(t, "https", location.Scheme)
			assert.Equal(t, m.domain, location.Host)
			assert.Equal(t, tc.location, location.Path)
			if tc.private || tc.location == "/denied" {
				assert.Empty(t, location.RawQuery)
			} else {
				assert.Equal(t, "https://"+vutils.GetServicePublicFQDN(svc, m.domain)+"/items/a%3Fb%23c?q=value", location.Query().Get("redirect"))
			}
		})
	}
}

func FuzzLoginRedirectRequestTarget(f *testing.F) {
	f.Add("a/b?c#d", "one+two&next=outside", false)
	f.Add("a%2Fb%3Fc%23d", "%252F", true)
	f.Add("", "", true)
	f.Add("中/🔒", "é", false)
	f.Add("\r\nLocation:https://outside.test", "?redirect=https://outside.test#fragment", false)
	f.Fuzz(func(t *testing.T, path, query string, forceQuery bool) {
		if len(path)+len(query) > 8*1024 {
			t.Skip()
		}
		u := &url.URL{
			Path: "/items/" + path, RawPath: "/items/" + url.PathEscape(path),
			ForceQuery: forceQuery && query == "",
		}
		if query != "" {
			u.RawQuery = "value=" + url.QueryEscape(query) + "&value=two+words&empty="
		}
		original := *u
		queryValues := url.Values{"redirect": {"https://app.example.com" + getEscapedPathWithQuery(u)}}
		login, err := url.Parse("https://example.com/login?" + queryValues.Encode())
		require.Nil(t, err)
		require.Len(t, login.Query(), 1)
		target, err := url.Parse(login.Query().Get("redirect"))
		require.Nil(t, err)
		assert.Equal(t, "https", target.Scheme)
		assert.Equal(t, "app.example.com", target.Host)
		assert.Nil(t, target.User)
		assert.Empty(t, target.Fragment)
		assert.Equal(t, u.Path, target.Path)
		assert.Equal(t, u.RawPath, target.EscapedPath())
		assert.Equal(t, u.RawQuery, target.RawQuery)
		assert.Equal(t, u.ForceQuery, target.ForceQuery)
		assert.Equal(t, original, *u)
	})
}

func TestIsClusterHost(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"custom.example.com", true},
		{"a.b.example.com", true},
		{"", false},
		{"example.org", false},
		{"badexample.com", false},
		{"example.com.attacker.test", false},
		{"attacker.test/path.example.com", false},
		{"attacker.test?next=.example.com", false},
		{"attacker.test#fragment.example.com", false},
		{"attacker.test@custom.example.com", false},
		{"attacker.test\\custom.example.com", false},
		{"custom.example.com:8443", false},
		{"custom.example.com/", false},
		{" custom.example.com", false},
		{"custom..example.com", false},
		{"192.0.2.1", false},
	} {
		t.Run(tc.host, func(t *testing.T) {
			assert.Equal(t, tc.want, isClusterHost(tc.host, "example.com"))
		})
	}
}
