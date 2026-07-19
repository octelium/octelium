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

package preauth

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestMiddleware(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})
	mdlwr, err := New(ctx, next, tst.C.OcteliumC, "example.com")
	assert.Nil(t, err)

	{

		reqPath := fmt.Sprintf("/prefix/%s", utilrand.GetRandomStringCanonical(12))
		req := httptest.NewRequest(http.MethodGet, reqPath, bytes.NewBuffer(utilrand.GetRandomBytesMust(32)))

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
					},
					Spec: &corev1.Service_Spec{},
				},
			}))
		mdlwr.ServeHTTP(nil, req)

		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		assert.Equal(t, reqPath, reqCtx.DownstreamRequest.Request.GetHttp().Path)
		assert.False(t, reqCtx.IsAuthorized)
		assert.False(t, reqCtx.IsAuthenticated)
		assert.Nil(t, reqCtx.Body)
	}

	{

		reqPath := fmt.Sprintf("/prefix/%s", utilrand.GetRandomStringCanonical(12))
		reqBody := utilrand.GetRandomBytesMust(32)
		req := httptest.NewRequest(http.MethodGet, reqPath, bytes.NewBuffer(reqBody))

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							EnableRequestBuffering: true,
						},
					},
				},
			},
		}
		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service:   svc,
			}))
		mdlwr.ServeHTTP(nil, req)

		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		assert.Equal(t, reqPath, reqCtx.DownstreamRequest.Request.GetHttp().Path)
		assert.Equal(t, reqBody, reqCtx.Body)
		assert.True(t, pbutils.IsEqual(svc.Spec.Config, reqCtx.ServiceConfig))
	}

	{

		reqPath := fmt.Sprintf("/prefix/%s", utilrand.GetRandomStringCanonical(12))
		req := httptest.NewRequest(http.MethodGet, reqPath, bytes.NewBuffer(utilrand.GetRandomBytesMust(32)))

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				IsAnonymous: true,
			},
		}
		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service:   svc,
			}))
		mdlwr.ServeHTTP(nil, req)

		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		assert.Equal(t, reqPath, reqCtx.DownstreamRequest.Request.GetHttp().Path)
		assert.True(t, pbutils.IsEqual(svc, reqCtx.DownstreamInfo.Service))
		assert.True(t, pbutils.IsEqual(svc, reqCtx.Service))
		assert.Nil(t, reqCtx.DownstreamInfo.Session)
		assert.Nil(t, reqCtx.DownstreamInfo.User)
		assert.Nil(t, reqCtx.DownstreamInfo.Device)
		// assert.True(t, reqCtx.IsAuthorized)
		assert.False(t, reqCtx.IsAuthenticated)
		assert.Nil(t, reqCtx.Body)
		assert.True(t, pbutils.IsEqual(svc.Spec.Config, reqCtx.ServiceConfig))
	}

	{

		reqPath := fmt.Sprintf("/prefix/%s", utilrand.GetRandomStringCanonical(12))

		usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		jsn, err := pbutils.MarshalJSON(usrT.Usr, false)
		assert.Nil(t, err)
		req := httptest.NewRequest(http.MethodGet, reqPath, bytes.NewBuffer(jsn))

		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							EnableRequestBuffering: true,
							Body: &corev1.Service_Spec_Config_HTTP_Body{
								Mode: corev1.Service_Spec_Config_HTTP_Body_JSON,
							},
						},
					},
				},
			},
		}
		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service:   svc,
			}))

		mdlwr.ServeHTTP(nil, req)
		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		bodyUsr := &corev1.User{}
		err = pbutils.UnmarshalJSON(reqCtx.Body, bodyUsr)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(bodyUsr, usrT.Usr))
		assert.Equal(t, reqCtx.BodyJSONMap, pbutils.MustConvertToMap(usrT.Usr))
	}

}

func TestRemoveDotSegments(t *testing.T) {
	type entry struct {
		arg      string
		expected string
		changed  bool
	}

	entries := []entry{
		{"/public/../secret.html", "/secret.html", true},
		{"/public/./ok.html", "/public/ok.html", true},
		{"/a/b/../c", "/a/c", true},
		{"/a/b/..", "/a/", true},
		{"/a/b/.", "/a/b/", true},
		{"/a/./b/../c", "/a/c", true},
		{"/a/b/c/../../d", "/a/d", true},
		{"/../x", "/x", true},
		{"/a/../../b", "/b", true},
		{"/..", "/", true},
		{"/.", "/", true},
		{"/a/..", "/", true},
		{"/a/../", "/", true},
		{"/a/./", "/a/", true},
		{"/a/b/../..", "/", true},
		{"//.", "//", true},
		{"/public/ok.html", "/public/ok.html", false},
		{"/", "/", false},
		{"/a", "/a", false},
		{"/a/", "/a/", false},
		{"/a//b", "/a//b", false},
		{"/bucket/a//b/key", "/bucket/a//b/key", false},
		{"/proxy/http://example.com/x", "/proxy/http://example.com/x", false},
		{"/static/app.min.js", "/static/app.min.js", false},
		{"/.well-known/acme", "/.well-known/acme", false},
		{"/a/...", "/a/...", false},
	}

	for _, e := range entries {
		ret, changed := removeDotSegments(e.arg)
		assert.Equal(t, e.expected, ret, "%s", e.arg)
		assert.Equal(t, e.changed, changed, "%s", e.arg)
	}
}

func TestRemoveDotSegmentsIsIdempotent(t *testing.T) {
	args := []string{
		"/public/../secret.html",
		"/a/b/..",
		"/a/./b",
		"/../x",
		"/a//b",
		"/",
	}

	for _, arg := range args {
		once, _ := removeDotSegments(arg)

		twice, changed := removeDotSegments(once)
		assert.Equal(t, once, twice, "%s", arg)
		assert.False(t, changed, "%s", arg)
	}
}

func TestRemoveEscapedDotSegments(t *testing.T) {
	type entry struct {
		arg      string
		expected string
		changed  bool
	}

	entries := []entry{
		{"/objects%2Farchive/a/../b", "/objects%2Farchive/b", true},
		{"/a/%2e%2e/b", "/b", true},
		{"/a/%2E/b", "/a/b", true},
		{"/public%2f..%2fsecret", "/public%2f..%2fsecret", false},
		{"/files/report%20final.pdf/../x", "/files/x", true},
		{"/a/b", "/a/b", false},
	}

	for _, e := range entries {
		ret, changed, err := removeEscapedDotSegments(e.arg)
		assert.Nil(t, err, "%s", e.arg)
		assert.Equal(t, e.expected, ret, "%s", e.arg)
		assert.Equal(t, e.changed, changed, "%s", e.arg)
	}

	_, _, err := removeEscapedDotSegments("/a/%zz/b")
	assert.NotNil(t, err)
}

func TestHasDotSegmentCandidate(t *testing.T) {
	positives := []string{
		"/public/../secret.html",
		"/a/./b",
		"/..",
		"/a/..",
		"/public\\..\\secret",
		"/public/..\\secret",
		"/.well-known/acme",
	}

	for _, arg := range positives {
		assert.True(t, hasDotSegmentCandidate(arg), "%s", arg)
	}

	negatives := []string{
		"/static/app.min.js",
		"/v1.2.3/api",
		"/files/report.final.pdf",
		"/public/ok.html",
		"/",
		"/a//b",
	}

	for _, arg := range negatives {
		assert.False(t, hasDotSegmentCandidate(arg), "%s", arg)
	}
}

func TestHasBackslashDotSegment(t *testing.T) {
	positives := []string{
		"/public\\..\\secret",
		"/public/..\\secret",
		"/public\\../secret",
		"/public\\.\\secret",
		"/a/b\\..",
	}

	for _, arg := range positives {
		assert.True(t, hasBackslashDotSegment(arg), "%s", arg)
	}

	negatives := []string{
		"/public/../secret",
		"/a\\b/../c",
		"/a\\b/c",
		"/public/ok.html",
		"/a/./b",
	}

	for _, arg := range negatives {
		assert.False(t, hasBackslashDotSegment(arg), "%s", arg)
	}
}

func TestCheckPathChars(t *testing.T) {
	assert.Nil(t, checkPathChars("/public/ok.html"))
	assert.Nil(t, checkPathChars("/a b/c"))

	for _, c := range []string{"\x00", "\x1f", "\x7f"} {
		assert.NotNil(t, checkPathChars("/public/"+c+"secret"), "%q", c)
	}
}

func TestCleanRequestRewritesTraversal(t *testing.T) {
	type entry struct {
		target       string
		expectedPath string
		expectedURI  string
	}

	entries := []entry{
		{"/public/../secret.html", "/secret.html", "/secret.html"},
		{"/a/b/../c?x=1", "/a/c", "/a/c?x=1"},
		{"/public/./ok.html", "/public/ok.html", "/public/ok.html"},
		{"/a/%2e%2e/b", "/b", "/b"},
		{"/files/report%20final.pdf/../other.pdf", "/files/other.pdf", "/files/other.pdf"},
	}

	for _, e := range entries {
		req := httptest.NewRequest(http.MethodGet, e.target, nil)

		err := cleanRequest(req)
		assert.Nil(t, err, "%s", e.target)

		assert.Equal(t, e.expectedPath, req.URL.Path, "%s", e.target)
		assert.Equal(t, e.expectedURI, req.URL.RequestURI(), "%s", e.target)
		assert.Equal(t, e.expectedURI, req.RequestURI, "%s", e.target)
	}
}

func TestCleanRequestPreservesUnambiguousEncodedSeparators(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/objects%2Farchive/a/../b", nil)

	err := cleanRequest(req)
	assert.Nil(t, err)

	assert.Equal(t, "/objects/archive/b", req.URL.Path)
	assert.Equal(t, "/objects%2Farchive/b", req.URL.RequestURI())
	assert.True(t, strings.Contains(req.RequestURI, "%2F"))
}

func TestCleanRequestRejectsAmbiguousEncodedSeparators(t *testing.T) {
	targets := []string{
		"/public%2f..%2fsecret.html",
		"/public%2F..%2Fsecret.html",
		"/api/users/a%2Fb/../c",
		"/public/%2e%2e%2fsecret",
	}

	for _, target := range targets {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		assert.NotNil(t, cleanRequest(req), "%s", target)
	}
}

func TestCleanRequestRejectsBackslashTraversal(t *testing.T) {
	paths := []string{
		"/public\\..\\secret",
		"/public/..\\secret",
		"/public\\../secret",
	}

	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = path
		req.URL.RawPath = ""

		assert.NotNil(t, cleanRequest(req), "%s", path)
	}
}

func TestCleanRequestPassthrough(t *testing.T) {
	targets := []string{
		"/public/ok.html",
		"/api/v4/projects/mygroup%2Fmyproject/repository/branches",
		"/bucket/a//b/key",
		"/proxy/http://example.com/x",
		"/pkg.Service/Method",
		"/api/v1/namespaces/ns/services/svc/proxy/metrics",
		"/static/app.min.js",
		"/v1.2.3/resource",
		"/.well-known/acme-challenge/token",
		"/files/report%20final.pdf",
		"/search?q=a%2Fb",
		"/a//b",
	}

	for _, target := range targets {
		req := httptest.NewRequest(http.MethodGet, target, nil)

		beforePath := req.URL.Path
		beforeRawPath := req.URL.RawPath
		beforeURI := req.URL.RequestURI()

		err := cleanRequest(req)
		assert.Nil(t, err, "%s", target)

		assert.Equal(t, beforePath, req.URL.Path, "%s", target)
		assert.Equal(t, beforeRawPath, req.URL.RawPath, "%s", target)
		assert.Equal(t, beforeURI, req.URL.RequestURI(), "%s", target)
	}
}

func TestCleanRequestAsteriskForm(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "http://example.com/", nil)
	req.URL.Path = "*"
	req.RequestURI = "*"

	assert.Nil(t, cleanRequest(req))
	assert.Equal(t, "*", req.RequestURI)

	req = httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.URL.Path = "*"
	req.RequestURI = "*"

	assert.NotNil(t, cleanRequest(req))
}

func TestCleanRequestPolicyAndUpstreamAgree(t *testing.T) {
	targets := []string{
		"/public/../secret.html",
		"/public/ok.html",
		"/api/v4/projects/mygroup%2Fmyproject/repo",
		"/objects%2Farchive/a/../b",
		"/bucket/a//b/key",
		"/a/b/../../c",
		"/files/report%20final.pdf/../other.pdf",
	}

	for _, target := range targets {
		req := httptest.NewRequest(http.MethodGet, target, nil)

		if err := cleanRequest(req); err != nil {
			continue
		}

		policyPath := req.URL.Path
		policyURI := req.URL.RequestURI()

		outReq := req.Clone(context.Background())
		outReq.RequestURI = ""

		assert.Equal(t, policyPath, outReq.URL.Path, "%s", target)
		assert.Equal(t, policyURI, outReq.URL.RequestURI(), "%s", target)
	}
}

func TestPrefixPolicyIsNotBypassable(t *testing.T) {
	isAllowed := func(path string) bool {
		return strings.HasPrefix(path, "/public/")
	}

	bypasses := []string{
		"/public/../secret.html",
		"/public%2f..%2fsecret.html",
		"/public%2F..%2Fsecret.html",
		"/public/./../secret.html",
		"/public/../../secret.html",
		"/public/a/../../secret.html",
		"/public/%2e%2e/secret.html",
		"/public/a/b/../../../secret.html",
	}

	for _, target := range bypasses {
		req := httptest.NewRequest(http.MethodGet, target, nil)

		if err := cleanRequest(req); err != nil {
			continue
		}

		assert.False(t, isAllowed(req.URL.Path), "%s -> %s", target, req.URL.Path)
	}

	allowed := []string{
		"/public/ok.html",
		"/public/./ok.html",
		"/public/sub/../ok.html",
		"/public/sub/deep/../../ok.html",
	}

	for _, target := range allowed {
		req := httptest.NewRequest(http.MethodGet, target, nil)

		err := cleanRequest(req)
		assert.Nil(t, err, "%s", target)
		assert.True(t, isAllowed(req.URL.Path), "%s -> %s", target, req.URL.Path)
	}
}

func TestDenyPolicyIsNotBypassable(t *testing.T) {
	isDenied := func(path string) bool {
		return strings.HasPrefix(path, "/admin")
	}

	bypasses := []string{
		"/x/../admin",
		"/x/../admin/users",
		"/x/./../admin",
		"/x%2f..%2fadmin",
		"/x/%2e%2e/admin",
	}

	for _, target := range bypasses {
		req := httptest.NewRequest(http.MethodGet, target, nil)

		if err := cleanRequest(req); err != nil {
			continue
		}

		assert.True(t, isDenied(req.URL.Path), "%s -> %s", target, req.URL.Path)
	}
}
