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

package path

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/paths"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	var path string
	var requestURI string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		requestURI = r.RequestURI
	})

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	mdlwr, err := New(ctx, next, celEngine, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
	assert.Nil(t, err)

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),

				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_Path_{
										Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{
											RemovePrefix: "/prefix",
										},
									},
								},
							},
						},
					},
				},
			}))
		mdlwr.ServeHTTP(nil, req)

		assert.Equal(t, "/v1", path)
		assert.Equal(t, "/v1", requestURI)
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)
		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),

				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{

							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_Path_{
										Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{
											AddPrefix: "/add01",
										},
									},
								},
							},
						},
					},
				},
			}))
		mdlwr.ServeHTTP(nil, req)

		assert.Equal(t, "/add01/prefix/v1", path)
		assert.Equal(t, "/add01/prefix/v1", requestURI)
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1/path", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),

				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_Path_{
										Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{

											RemovePrefix: "/v1",
											AddPrefix:    "/v2",
										},
									},
								},
							},
						},
					},
				},
			}))
		mdlwr.ServeHTTP(nil, req)

		assert.Equal(t, "/v2/path", path)
		assert.Equal(t, "/v2/path", requestURI)
	}
}

func TestPluginPathRewritePreservesEscapedSuffix(t *testing.T) {
	engine, err := celengine.New(t.Context(), &celengine.Opts{})
	require.Nil(t, err)
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/api/v1/item%2Fpart?q=a%2Fb", "/backend/item%2Fpart?q=a%2Fb"},
		{"/api%2Fv1/item%2Fpart?q=a%2Fb", "/backend/item%2Fpart?q=a%2Fb"},
		{"/api/v1", "/backend"},
		{"/unrelated/value", "/backend/unrelated/value"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			var got string
			h, err := New(t.Context(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.URL.RequestURI()
			}), engine, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
			require.Nil(t, err)
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req = req.WithContext(context.WithValue(t.Context(), middlewares.CtxRequestContext, &middlewares.RequestContext{
				ReqCtxMap: map[string]any{},
				ServiceConfig: &corev1.Service_Spec_Config{Type: &corev1.Service_Spec_Config_Http{Http: &corev1.Service_Spec_Config_HTTP{
					Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{{
						Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
						Type: &corev1.Service_Spec_Config_HTTP_Plugin_Path_{Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{
							RemovePrefix: "/api/v1", AddPrefix: "/backend",
						}},
					}},
				}}},
			}))
			h.ServeHTTP(httptest.NewRecorder(), req)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestPathRewriteEscapedVariants(t *testing.T) {
	engine, err := celengine.New(t.Context(), &celengine.Opts{})
	require.Nil(t, err)
	for _, mode := range []string{"Service", "Plugin"} {
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct {
				name      string
				target    string
				remove    string
				add       string
				want      string
				emptyPath bool
			}{
				{name: "EncodedPrefix", target: "/api%2Fv1/item%2Fpart?q=a%2Fb", remove: "/api/v1", add: "/backend", want: "/backend/item%2Fpart?q=a%2Fb"},
				{name: "EncodedLetters", target: "/%61pi/v%31/%61%2fpart", remove: "/api/v1", add: "/backend", want: "/backend/%61%2fpart"},
				{name: "UnicodePrefix", target: "/caf%C3%A9/%E9%9B%AA%2Fpart", remove: "/café", add: "/backend", want: "/backend/%E9%9B%AA%2Fpart"},
				{name: "UnicodeAndSlashPrefix", target: "/%E2%98%83%2fapi/x%252Fy%3Fz%23a", remove: "/☃/api", add: "/b", want: "/b/x%252Fy%3Fz%23a"},
				{name: "PartialSegment", target: "/prefixsuffix/item%2Fpart", remove: "/prefix", add: "/base", want: "/base/suffix/item%2Fpart"},
				{name: "LiteralPercentPrefix", target: "/api%252Fv1/item%252Fpart", remove: "/api%2Fv1", add: "/backend", want: "/backend/item%252Fpart"},
				{name: "EncodedConfigDoesNotMatchDecodedPath", target: "/api%2Fv1/item%2Fpart", remove: "/api%2Fv1", add: "/backend", want: "/backend/api%2Fv1/item%2Fpart"},
				{name: "EncodedBoundaryWithPrefix", target: "/api%2Fitem%2Fpart", remove: "/api", add: "/backend", want: "/backend%2Fitem%2Fpart"},
				{name: "EncodedBoundaryAtRoot", target: "/api%2Fitem%2fpart", remove: "/api", want: "/item%2fpart"},
				{name: "TwoEncodedBoundarySlashes", target: "/api%2F%2fitem", remove: "/api", want: "/%2fitem"},
				{name: "ReservedPrefix", target: "/api/item%2Fpart?q=a%2Fb", remove: "/api", add: "/next%25", want: "/next%2525/item%2Fpart?q=a%2Fb"},
				{name: "ReservedPrefixPlainPath", target: "/api/item", remove: "/api", add: "/next%25", want: "/next%2525/item"},
				{name: "LiteralQueryAndFragmentInPrefix", target: "/api/item%2Fpart", remove: "/api", add: "/next?group#anchor", want: "/next%3Fgroup%23anchor/item%2Fpart"},
				{name: "ExactPrefix", target: "/api%2fv1?x=a%2Fb", remove: "/api/v1", want: "/?x=a%2Fb", emptyPath: true},
				{name: "ForceQuery", target: "/api%2Fv1?", remove: "/api/v1", add: "/backend", want: "/backend?"},
				{name: "NoMatch", target: "/other%2Fpath?q=a+b", remove: "/api", add: "/backend", want: "/backend/other%2Fpath?q=a+b"},
				{name: "RelativeAddPrefix", target: "/a%2fb", add: "v2", want: "/v2/a%2fb"},
				{name: "NoRewrite", target: "/api%2Fv1/x%2Fz?z=%2f", want: "/api%2Fv1/x%2Fz?z=%2f"},
				{name: "RepeatedSlashes", target: "/api//v1///x%2Fpart", remove: "/api", add: "/backend", want: "/backend//v1///x%2Fpart"},
				{name: "TrailingSlash", target: "/api/v1/", remove: "/api/v1/", add: "/backend/", want: "/backend/"},
				{name: "PrefixJoiningKeepsSlashes", target: "/api/v1/item%2Fpart", remove: "/api/v1", add: "/backend/", want: "/backend//item%2Fpart"},
				{name: "ReservedSuffix", target: "/api%2fv1/x%3fy%23z%25w", remove: "/api/v1", add: "/backend", want: "/backend/x%3fy%23z%25w"},
				{name: "PlusIsNotSpace", target: "/api%2Fv1/a+b%2Bc?x=a+b&x=%2B", remove: "/api/v1", add: "/backend", want: "/backend/a+b%2Bc?x=a+b&x=%2B"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					want, err := url.ParseRequestURI(tc.want)
					require.Nil(t, err)
					cfg := &corev1.Service_Spec_Config_HTTP{}
					if mode == "Service" {
						cfg.Path = &corev1.Service_Spec_Config_HTTP_Path{RemovePrefix: tc.remove, AddPrefix: tc.add}
					} else {
						cfg.Plugins = []*corev1.Service_Spec_Config_HTTP_Plugin{{
							Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Path_{Path: &corev1.Service_Spec_Config_HTTP_Plugin_Path{
								RemovePrefix: tc.remove, AddPrefix: tc.add,
							}},
						}}
					}
					req := httptest.NewRequest(http.MethodGet, tc.target, nil)
					query, forceQuery := req.URL.RawQuery, req.URL.ForceQuery
					req = req.WithContext(context.WithValue(t.Context(), middlewares.CtxRequestContext, &middlewares.RequestContext{
						ReqCtxMap: map[string]any{},
						ServiceConfig: &corev1.Service_Spec_Config{Type: &corev1.Service_Spec_Config_Http{
							Http: cfg,
						}},
					}))
					calls := 0
					next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls++
						path := want.Path
						escapedPath := want.EscapedPath()
						if tc.emptyPath {
							path = ""
							escapedPath = ""
						}
						assert.Equal(t, path, r.URL.Path)
						assert.Equal(t, escapedPath, r.URL.EscapedPath())
						assert.Equal(t, tc.want, r.RequestURI)
						assert.Equal(t, tc.want, r.URL.RequestURI())
						assert.Equal(t, query, r.URL.RawQuery)
						assert.Equal(t, forceQuery, r.URL.ForceQuery)
						if r.URL.RawPath != "" {
							decoded, err := url.PathUnescape(r.URL.RawPath)
							assert.Nil(t, err)
							assert.Equal(t, r.URL.Path, decoded)
							assert.Equal(t, r.URL.RawPath, r.URL.EscapedPath())
						}
					})
					var h http.Handler
					if mode == "Service" {
						h, err = paths.New(t.Context(), next)
					} else {
						h, err = New(t.Context(), next, engine, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
					}
					require.Nil(t, err)
					h.ServeHTTP(httptest.NewRecorder(), req)
					assert.Equal(t, 1, calls)
				})
			}
		})
	}
}

func TestRewriteRequestPathRawHints(t *testing.T) {
	for _, rawPath := range []string{
		"/api%2Fv1/wrong%2Fvalue",
		"/api%zz",
		"/api/v1/item?query",
		"/api%2Fv1/item%3Fquery",
	} {
		t.Run(rawPath, func(t *testing.T) {
			req := &http.Request{URL: &url.URL{
				Scheme: "https", Host: "original.example.com", User: url.User("user"),
				Path: "/api/v1/item?query", RawPath: rawPath,
				RawQuery: "q=a%2Fb&z=+", ForceQuery: true, Fragment: "keep", RawFragment: "%6beep",
			}}
			before := *req.URL
			httputils.RewriteRequestPath(req, "/api/v1", "/backend")
			assert.Equal(t, "/backend/item?query", req.URL.Path)
			assert.Equal(t, "/backend/item%3Fquery", req.URL.EscapedPath())
			assert.Equal(t, "/backend/item%3Fquery?q=a%2Fb&z=+", req.RequestURI)
			assert.Equal(t, before.Scheme, req.URL.Scheme)
			assert.Equal(t, before.Host, req.URL.Host)
			assert.Equal(t, before.User, req.URL.User)
			assert.Equal(t, before.RawQuery, req.URL.RawQuery)
			assert.Equal(t, before.ForceQuery, req.URL.ForceQuery)
			assert.Equal(t, before.Fragment, req.URL.Fragment)
			assert.Equal(t, before.RawFragment, req.URL.RawFragment)
			if req.URL.RawPath != "" {
				decoded, err := url.PathUnescape(req.URL.RawPath)
				assert.Nil(t, err)
				assert.Equal(t, req.URL.Path, decoded)
			}
		})
	}
	req := httptest.NewRequest(http.MethodGet, "http://original.example.com/a%2fb?q=%2f", nil)
	before, requestURI := *req.URL, req.RequestURI
	httputils.RewriteRequestPath(req, "", "")
	assert.Equal(t, before, *req.URL)
	assert.Equal(t, requestURI, req.RequestURI)
}

func FuzzRewriteRequestPathEscapedSuffix(f *testing.F) {
	f.Add("api/v1", "item/part", "/backend", false)
	f.Add("café", "雪/☃", "/next%25", true)
	f.Add("literal%2F", "value?query#fragment", "next?group#anchor", false)
	f.Add("", "", "", true)
	f.Fuzz(func(t *testing.T, prefix, suffix, add string, forceQuery bool) {
		rawSuffix := "/" + strings.ReplaceAll(url.PathEscape(suffix), "%2F", "%2f")
		query := "q=%2F+%252F&flag=&dup=a&dup=b"
		if forceQuery {
			query = ""
		}
		req := &http.Request{URL: &url.URL{
			Scheme: "https", Host: "original.example.com",
			Path: "/" + prefix + "/" + suffix, RawPath: "/" + url.PathEscape(prefix) + rawSuffix,
			RawQuery: query, ForceQuery: forceQuery,
		}}
		httputils.RewriteRequestPath(req, "/"+prefix, add)
		want := add + "/" + suffix
		if !strings.HasPrefix(want, "/") {
			want = "/" + want
		}
		require.Equal(t, want, req.URL.Path)
		require.True(t, strings.HasSuffix(req.URL.EscapedPath(), rawSuffix), "The escaped suffix was changed")
		if req.URL.RawPath != "" {
			decoded, err := url.PathUnescape(req.URL.RawPath)
			require.Nil(t, err)
			require.Equal(t, req.URL.Path, decoded)
			require.Equal(t, req.URL.RawPath, req.URL.EscapedPath())
		}
		require.Equal(t, req.URL.RequestURI(), req.RequestURI)
		parsed, err := url.ParseRequestURI(req.RequestURI)
		require.Nil(t, err)
		require.Equal(t, req.URL.Path, parsed.Path)
		require.Equal(t, query, parsed.RawQuery)
		require.Equal(t, forceQuery, parsed.ForceQuery)
		require.Equal(t, "https", req.URL.Scheme)
		require.Equal(t, "original.example.com", req.URL.Host)
	})
}
