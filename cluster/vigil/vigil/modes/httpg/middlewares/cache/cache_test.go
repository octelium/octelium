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

package cache

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cvigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMiddleware(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	hdr1Val := utilrand.GetRandomString(32)
	respBody := utilrand.GetRandomString(32)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("X-Custom-1", hdr1Val)
		w.WriteHeader(203)
		w.Write([]byte(respBody))
	})

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	mdlwr, err := New(ctx, next, celEngine, tst.C.OcteliumC,
		vutils.UUIDv4(), corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
			}))

		rw := httptest.NewRecorder()

		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, 203, rw.Code)
	}

	{
		svcCfg := &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_MatchAny{
									MatchAny: true,
								},
							},

							Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_{
								Cache: &corev1.Service_Spec_Config_HTTP_Plugin_Cache{
									UseXCacheHeader: true,
									Ttl: &metav1.Duration{
										Type: &metav1.Duration_Seconds{
											Seconds: 2,
										},
									},
								},
							},
						},
					},
				},
			},
		}

		{
			usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, nil, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)

			req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)
			req = req.WithContext(context.WithValue(context.Background(),
				middlewares.CtxRequestContext,
				&middlewares.RequestContext{
					CreatedAt:     time.Now(),
					ServiceConfig: svcCfg,
					DownstreamInfo: &corev1.RequestContext{
						Session: usrT.Session,
						User:    usrT.Usr,
					},
				}))
			{
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				resp := rw.Result()
				assert.Equal(t, resp.StatusCode, 203)

				bb, err := io.ReadAll(resp.Body)
				assert.Nil(t, err)
				resp.Body.Close()

				assert.Equal(t, respBody, string(bb))
				assert.Equal(t, hdr1Val, resp.Header.Get("X-Custom-1"))
				assert.Equal(t, "MISS", resp.Header.Get("X-Cache"))
			}

			{
				time.Sleep(1 * time.Second)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				resp := rw.Result()
				assert.Equal(t, resp.StatusCode, 203)

				bb, err := io.ReadAll(resp.Body)
				assert.Nil(t, err)
				resp.Body.Close()

				assert.Equal(t, respBody, string(bb))
				assert.Equal(t, hdr1Val, resp.Header.Get("X-Custom-1"))
				assert.Equal(t, "HIT", resp.Header.Get("X-Cache"))
			}

			{
				time.Sleep(2 * time.Second)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				resp := rw.Result()
				assert.Equal(t, resp.StatusCode, 203)

				bb, err := io.ReadAll(resp.Body)
				assert.Nil(t, err)
				resp.Body.Close()

				assert.Equal(t, respBody, string(bb))
				assert.Equal(t, hdr1Val, resp.Header.Get("X-Custom-1"))
				assert.Equal(t, "MISS", resp.Header.Get("X-Cache"))
			}

			{
				time.Sleep(1 * time.Second)
				rw := httptest.NewRecorder()
				mdlwr.ServeHTTP(rw, req)
				resp := rw.Result()
				assert.Equal(t, resp.StatusCode, 203)

				bb, err := io.ReadAll(resp.Body)
				assert.Nil(t, err)
				resp.Body.Close()

				assert.Equal(t, respBody, string(bb))
				assert.Equal(t, hdr1Val, resp.Header.Get("X-Custom-1"))
				assert.Equal(t, "HIT", resp.Header.Get("X-Cache"))
			}
		}
	}

}

type testCacheClient struct {
	rcachev1.MainServiceClient
	response *rcachev1.GetCacheResponse
	err      error
	stored   []*rcachev1.SetCacheRequest
}

func (c *testCacheClient) GetCache(ctx context.Context, req *rcachev1.GetCacheRequest, opts ...grpc.CallOption) (*rcachev1.GetCacheResponse, error) {
	return c.response, c.err
}

func (c *testCacheClient) SetCache(ctx context.Context, req *rcachev1.SetCacheRequest, opts ...grpc.CallOption) (*rcachev1.SetCacheResponse, error) {
	c.stored = append(c.stored, req)
	return &rcachev1.SetCacheResponse{}, c.err
}

type testOcteliumClient struct {
	octeliumc.ClientInterface
	cache *testCacheClient
}

func (c *testOcteliumClient) CacheC() rcachev1.MainServiceClient {
	return c.cache
}

func TestCacheReplayRejectsInvalidEntries(t *testing.T) {
	marshal := func(entry *cvigilv1.CacheHTTP) []byte {
		data, err := pbutils.Marshal(entry)
		require.Nil(t, err)
		return data
	}
	for _, tc := range []struct {
		name string
		data []byte
		err  error
	}{
		{name: "Empty"},
		{name: "Missing", err: status.Error(codes.NotFound, "missing")},
		{name: "Unavailable", err: status.Error(codes.Unavailable, "unavailable")},
		{name: "Malformed", data: []byte{0xff, 0xff}},
		{name: "ErrorStatus", data: marshal(&cvigilv1.CacheHTTP{Code: 500})},
		{name: "PartialStatus", data: marshal(&cvigilv1.CacheHTTP{Code: 206})},
		{name: "ConfiguredSizeLimit", data: marshal(&cvigilv1.CacheHTTP{Code: 200, Body: []byte("large")})},
		{name: "HeaderLimit", data: marshal(&cvigilv1.CacheHTTP{Code: 200, Headers: make([]*cvigilv1.CacheHTTP_Header, maxCachedHeaderCount+1)})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &testCacheClient{response: &rcachev1.GetCacheResponse{Data: tc.data}, err: tc.err}
			m := &middleware{octeliumC: &testOcteliumClient{cache: client}}
			rw := httptest.NewRecorder()
			assert.False(t, m.serveCachedResponse(t.Context(), rw, httptest.NewRequest(http.MethodGet, "/", nil), []byte("key"), &corev1.Service_Spec_Config_HTTP_Plugin_Cache{MaxSize: 4}))
			assert.Empty(t, rw.Body.String())
			client.response = nil
			assert.False(t, m.serveCachedResponse(t.Context(), rw, httptest.NewRequest(http.MethodGet, "/", nil), []byte("key"), &corev1.Service_Spec_Config_HTTP_Plugin_Cache{}))
		})
	}
}

func TestCacheReplaySanitizesHeadersAndHEAD(t *testing.T) {
	entry := &cvigilv1.CacheHTTP{Code: 200, Body: []byte("body"), Headers: []*cvigilv1.CacheHTTP_Header{
		{Key: "Content-Length", Values: []string{"999"}},
		{Key: "Connection", Values: []string{"keep-alive"}},
		{Key: "Set-Cookie", Values: []string{"secret=value"}},
		{Key: "Bad Name", Values: []string{"invalid"}},
		{Key: "X-Valid", Values: []string{"safe", "bad\r\ninjected"}},
	}}
	data, err := pbutils.Marshal(entry)
	require.Nil(t, err)
	m := &middleware{octeliumC: &testOcteliumClient{cache: &testCacheClient{response: &rcachev1.GetCacheResponse{Data: data}}}}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			rw := httptest.NewRecorder()
			assert.True(t, m.serveCachedResponse(t.Context(), rw, httptest.NewRequest(method, "/", nil), []byte("key"), &corev1.Service_Spec_Config_HTTP_Plugin_Cache{UseXCacheHeader: true}))
			assert.Equal(t, http.StatusOK, rw.Code)
			assert.Equal(t, "HIT", rw.Header().Get("X-Cache"))
			assert.Equal(t, []string{"safe"}, rw.Header().Values("X-Valid"))
			assert.Empty(t, rw.Header().Get("Set-Cookie"))
			assert.Empty(t, rw.Header().Get("Connection"))
			assert.Empty(t, rw.Header().Get("Bad Name"))
			if method == http.MethodHead {
				assert.Empty(t, rw.Body.String())
			} else {
				assert.Equal(t, "body", rw.Body.String())
				assert.Equal(t, "4", rw.Header().Get("Content-Length"))
			}
		})
	}
}

func TestCacheStoresOnlyCompleteResponses(t *testing.T) {
	client := &testCacheClient{}
	m := &middleware{octeliumC: &testOcteliumClient{cache: client}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	cfg := &corev1.Service_Spec_Config_HTTP_Plugin_Cache{}
	for _, length := range []string{"8", "4"} {
		rw := newResponseWriter(httptest.NewRecorder(), 10)
		rw.Header().Set("Content-Length", length)
		rw.Write([]byte("body"))
		rw.finalize()
		require.Nil(t, m.cacheResponse(req, []byte("key"), rw, cfg))
		if length == "8" {
			assert.Empty(t, client.stored)
		}
	}
	require.Len(t, client.stored, 1)
	stored := &cvigilv1.CacheHTTP{}
	require.Nil(t, pbutils.Unmarshal(client.stored[0].Data, stored))
	assert.Equal(t, int64(http.StatusOK), stored.Code)
	assert.Equal(t, []byte("body"), stored.Body)
	assert.Equal(t, []byte("key"), client.stored[0].Key)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	rw := newResponseWriter(httptest.NewRecorder(), 10)
	rw.finalize()
	require.Nil(t, m.cacheResponse(req.WithContext(ctx), []byte("key"), rw, cfg))
	assert.Len(t, client.stored, 1)
}

func TestCacheStreamingRequestBypass(t *testing.T) {
	for _, header := range []http.Header{
		{"Connection": {"keep-alive, Upgrade"}},
		{"Accept": {"text/event-stream"}},
		{"Content-Type": {"application/grpc+proto"}},
		{"X-Accel-Buffering": {"NO"}},
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header = header
		assert.True(t, isStreamingRequest(req, nil))
	}
	reqCtx := &middlewares.RequestContext{Service: &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_KUBERNETES}}}
	for _, path := range []string{"/pods/app/exec", "/pods/app/attach", "/pods/app/log", "/pods/app/portforward", "/pods?watch=true", "/pods?follow=1"} {
		assert.True(t, isStreamingRequest(httptest.NewRequest(http.MethodGet, path, nil), reqCtx), path)
	}
	assert.False(t, isStreamingRequest(httptest.NewRequest(http.MethodGet, "/pods?watch=false", nil), reqCtx))
	assert.False(t, isStreamingRequest(nil, nil))
	assert.False(t, isStreamingRequest(httptest.NewRequest(http.MethodGet, "/", nil), nil))
}

func TestCacheRequestAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header http.Header
		custom bool
		pre    bool
		want   bool
	}{
		{name: "Plain", want: true},
		{name: "Range", header: http.Header{"Range": {"bytes=0-9"}}},
		{name: "IfRange", header: http.Header{"If-Range": {"etag"}}},
		{name: "NoCache", header: http.Header{"Cache-Control": {"public", "no-cache"}}},
		{name: "NoStore", header: http.Header{"Cache-Control": {"NO-STORE"}}},
		{name: "Private", header: http.Header{"Cache-Control": {`private="Authorization"`}}},
		{name: "ZeroAge", header: http.Header{"Cache-Control": {`max-age="0"`}}},
		{name: "Pragma", header: http.Header{"Pragma": {"no-cache"}}},
		{name: "PreAuthBearer", header: http.Header{"Authorization": {"Bearer token"}}, pre: true},
		{name: "PreAuthCookie", header: http.Header{"Cookie": {"session=private"}}, pre: true},
		{name: "PostAuthBearer", header: http.Header{"Authorization": {"Bearer token"}}, want: true},
		{name: "DefaultOrigin", header: http.Header{"Origin": {"https://example.com"}}},
		{name: "CustomOrigin", header: http.Header{"Origin": {"https://example.com"}}, custom: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header = tc.header
			phase := corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH
			if tc.pre {
				phase = corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH
			}
			assert.Equal(t, tc.want, requestAllowsCache(req, tc.custom, phase))
		})
	}
	assert.False(t, requestAllowsCache(nil, false, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH))
}

func TestCacheResponseAdmission(t *testing.T) {
	for _, key := range []string{"Set-Cookie", "Set-Cookie2", "Content-Range", "Trailer", "Vary"} {
		t.Run(key, func(t *testing.T) {
			assert.False(t, responseAllowsCache(http.Header{key: {"sensitive"}}))
		})
	}
	for _, value := range []string{"no-store", "private", "no-cache", "max-age=0", "s-maxage=0"} {
		assert.False(t, responseAllowsCache(http.Header{"Cache-Control": {value}}), value)
	}
	assert.True(t, responseAllowsCache(nil))
	assert.True(t, responseAllowsCache(http.Header{"Cache-Control": {"public, max-age=60"}}))
	for _, status := range []int{100, 199, 206, 300, 304, 404, 500} {
		assert.False(t, isCacheableStatus(status), status)
	}
	for _, status := range []int{200, 201, 204, 299} {
		assert.True(t, isCacheableStatus(status), status)
	}
}

func TestCacheResponseAdmissionMultipleHeaderLines(t *testing.T) {
	for _, key := range []string{"Set-Cookie", "Set-Cookie2", "Content-Range", "Trailer", "Vary"} {
		t.Run(key, func(t *testing.T) {
			assert.False(t, responseAllowsCache(http.Header{key: {"", "sensitive"}}))
		})
	}
}

func TestCacheTTLSelection(t *testing.T) {
	for _, tc := range []struct {
		name string
		ttl  *metav1.Duration
		cc   []string
		want int64
	}{
		{name: "Default", want: 600},
		{name: "MaxAge", cc: []string{"public, max-age=60"}, want: 60},
		{name: "SharedAge", cc: []string{"max-age=20", "s-maxage=40"}, want: 40},
		{name: "SmallestAge", cc: []string{"max-age=30, max-age=10"}, want: 10},
		{name: "InvalidAge", cc: []string{"max-age=invalid, max-age=-1"}, want: 600},
		{name: "Quoted", cc: []string{`max-age="25"`}, want: 25},
		{name: "ConfiguredCap", ttl: &metav1.Duration{Type: &metav1.Duration_Seconds{Seconds: 5}}, cc: []string{"max-age=60"}, want: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := getCacheDuration(&corev1.Service_Spec_Config_HTTP_Plugin_Cache{Ttl: tc.ttl}, http.Header{"Cache-Control": tc.cc})
			assert.Equal(t, tc.want, umetav1ToSeconds(got))
		})
	}
}

func TestCacheHeaderSanitizationAndLimits(t *testing.T) {
	hdr := http.Header{
		"X-Valid": {"one", "two"}, "Connection": {"keep-alive"}, "Set-Cookie": {"secret"},
		"X-Invalid": {"bad\r\nheader"}, "Bad Name": {"value"}, "X-Cache": {"MISS"},
	}
	got, ok := getCacheableHeaders(hdr)
	require.True(t, ok)
	assert.Equal(t, http.Header{"X-Valid": {"one", "two"}}, got)
	got.Set("X-Valid", "changed")
	assert.Equal(t, []string{"one", "two"}, hdr.Values("X-Valid"))
	_, ok = getCacheableHeaders(http.Header{"X-Large": {strings.Repeat("x", maxCachedHeaderBytes)}})
	assert.False(t, ok)
	values := make([]string, maxCachedHeaderCount+1)
	for i := range values {
		values[i] = "value"
	}
	_, ok = getCacheableHeaders(http.Header{"X-Many": values})
	assert.False(t, ok)
}

func TestCacheResponseWriterBoundaries(t *testing.T) {
	for _, size := range []int{0, 3, 4, 5} {
		t.Run(fmt.Sprintf("Size%d", size), func(t *testing.T) {
			rw := httptest.NewRecorder()
			w := newResponseWriter(rw, 4)
			w.Header().Set("Content-Length", fmt.Sprint(size))
			body := strings.Repeat("a", size)
			n, err := w.Write([]byte(body))
			require.Nil(t, err)
			w.finalize()
			assert.Equal(t, size, n)
			assert.Equal(t, body, rw.Body.String())
			assert.Equal(t, size > 4, w.overflow)
			assert.Equal(t, size <= 4, w.isBodyComplete(httptest.NewRequest(http.MethodGet, "/", nil)))
			w.Header().Set("Content-Length", "100")
			assert.Equal(t, fmt.Sprint(size), w.headers.Get("Content-Length"))
		})
	}
	rw := httptest.NewRecorder()
	w := newResponseWriter(rw, 4)
	w.Header().Set("Content-Length", "10")
	w.Write([]byte("abc"))
	assert.False(t, w.isBodyComplete(httptest.NewRequest(http.MethodGet, "/", nil)))
	w.Flush()
	assert.True(t, w.flushed)
	assert.True(t, rw.Flushed)
	assert.Same(t, rw, w.Unwrap())
	assert.ErrorIs(t, w.Push("/asset", nil), http.ErrNotSupported)
	_, _, err := w.Hijack()
	assert.NotNil(t, err)
}

func TestCacheFillGroupLifecycle(t *testing.T) {
	g := &fillGroup{calls: make(map[string]*fillCall)}
	release, leader, err := g.acquire(t.Context(), "key")
	require.Nil(t, err)
	require.True(t, leader)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, leader, err = g.acquire(ctx, "key")
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, leader)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			done, _, err := g.acquire(t.Context(), "key")
			if assert.Nil(t, err) {
				done()
			}
		})
	}
	release()
	release()
	wg.Wait()
	assert.Empty(t, g.calls)
}

func TestCacheKeyRequestIsolation(t *testing.T) {
	m := &middleware{svcUID: "service", phase: corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH}
	cfg := &corev1.Service_Spec_Config_HTTP_Plugin_Cache{AllowUnsafeMethods: true}
	reqCtx := &middlewares.RequestContext{Body: []byte("first")}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/resource?q=one", strings.NewReader("first"))
	key, custom := m.getKey(t.Context(), cfg, reqCtx, req)
	assert.False(t, custom)
	require.NotEmpty(t, key)
	reqCtx.Body = []byte("second")
	other, _ := m.getKey(t.Context(), cfg, reqCtx, req)
	assert.NotEqual(t, key, other)
	reqCtx.Body = nil
	other, _ = m.getKey(t.Context(), cfg, reqCtx, req)
	assert.Empty(t, other)
	reqCtx.Body = []byte("first")
	req.URL.RawQuery = "q=two"
	other, _ = m.getKey(t.Context(), cfg, reqCtx, req)
	assert.NotEqual(t, key, other)
	req.URL.RawQuery = "q=one"
	m.svcUID = "other-service"
	other, _ = m.getKey(t.Context(), cfg, reqCtx, req)
	assert.NotEqual(t, key, other)
	m.phase = corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH
	assert.False(t, m.canUseCacheInPhase(nil))
	assert.False(t, m.canUseCacheInPhase(&middlewares.RequestContext{Service: &corev1.Service{Spec: &corev1.Service_Spec{}}}))
	assert.True(t, m.canUseCacheInPhase(&middlewares.RequestContext{Service: &corev1.Service{Spec: &corev1.Service_Spec{IsAnonymous: true}}}))
	assert.False(t, m.canUseCacheInPhase(&middlewares.RequestContext{Service: &corev1.Service{Spec: &corev1.Service_Spec{
		IsAnonymous: true, Authorization: &corev1.Service_Spec_Authorization{EnableAnonymous: true},
	}}}))
}

func TestGetNormalizedAcceptEncoding(t *testing.T) {
	for _, e := range []struct {
		arg      []string
		expected string
	}{
		{nil, ""},
		{[]string{""}, ""},
		{[]string{"gzip"}, "gzip"},
		{[]string{"GZIP"}, "gzip"},
		{[]string{" gzip , br "}, "br,gzip"},
		{[]string{"br, gzip"}, "br,gzip"},
		{[]string{"gzip, br"}, "br,gzip"},
		{[]string{"gzip", "br"}, "br,gzip"},
		{[]string{"gzip;q=0.5, br;q=1.0"}, "br,gzip"},
		{[]string{"gzip;q=0, br"}, "br"},
		{[]string{"gzip;q=0.000, br"}, "br"},
		{[]string{"gzip, gzip"}, "gzip"},
		{[]string{"*"}, "*"},
		{[]string{"identity;q=0"}, ""},
	} {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
		for _, val := range e.arg {
			req.Header.Add("Accept-Encoding", val)
		}

		assert.Equal(t, e.expected, getNormalizedAcceptEncoding(req), "%v", e.arg)
	}
}

func newCacheTestReqCtx(svcCfg *corev1.Service_Spec_Config) *middlewares.RequestContext {
	return &middlewares.RequestContext{
		CreatedAt:     time.Now(),
		ServiceConfig: svcCfg,
	}
}

func newCacheTestSvcCfg(key *corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key) *corev1.Service_Spec_Config {
	return &corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Http{
			Http: &corev1.Service_Spec_Config_HTTP{
				Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
					{
						Condition: &corev1.Condition{
							Type: &corev1.Condition_MatchAny{MatchAny: true},
						},
						Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_{
							Cache: &corev1.Service_Spec_Config_HTTP_Plugin_Cache{
								UseXCacheHeader: true,
								Key:             key,
								Ttl: &metav1.Duration{
									Type: &metav1.Duration_Seconds{Seconds: 30},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestAcceptEncodingIsInTheKey(t *testing.T) {

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

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	serve := func(mdlwr http.Handler, svcCfg *corev1.Service_Spec_Config,
		acceptEncoding string) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)
		if acceptEncoding != "" {
			req.Header.Set("Accept-Encoding", acceptEncoding)
		}

		reqCtx := newCacheTestReqCtx(svcCfg)
		reqCtx.DownstreamInfo = &corev1.RequestContext{
			Session: usrT.Session,
			User:    usrT.Usr,
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext, reqCtx))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		return rw.Result()
	}

	for _, key := range []*corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key{
		nil,
		{
			Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key_Eval{
				Eval: `"tst-key"`,
			},
		},
	} {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(200)
			w.Write([]byte("compressed"))
		})

		mdlwr, err := New(ctx, next, celEngine, tst.C.OcteliumC,
			vutils.UUIDv4(), corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
		assert.Nil(t, err)

		svcCfg := newCacheTestSvcCfg(key)

		assert.Equal(t, "MISS", serve(mdlwr, svcCfg, "gzip").Header.Get("X-Cache"))
		assert.Equal(t, "HIT", serve(mdlwr, svcCfg, "gzip").Header.Get("X-Cache"))

		assert.Equal(t, "MISS", serve(mdlwr, svcCfg, "gzip, br").Header.Get("X-Cache"))
		assert.Equal(t, "HIT", serve(mdlwr, svcCfg, "br, gzip").Header.Get("X-Cache"))
		assert.Equal(t, "HIT", serve(mdlwr, svcCfg, "GZIP;q=0.5, br").Header.Get("X-Cache"))

		assert.Equal(t, "MISS", serve(mdlwr, svcCfg, "").Header.Get("X-Cache"))
		assert.Equal(t, "HIT", serve(mdlwr, svcCfg, "gzip;q=0").Header.Get("X-Cache"))

		assert.Equal(t, "MISS", serve(mdlwr, svcCfg, "identity").Header.Get("X-Cache"))
	}
}

func TestCustomKeyIsScopedPerPrincipal(t *testing.T) {

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

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("private"))
	})

	mdlwr, err := New(ctx, next, celEngine, tst.C.OcteliumC,
		vutils.UUIDv4(), corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
	assert.Nil(t, err)

	svcCfg := newCacheTestSvcCfg(&corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key{
		Type: &corev1.Service_Spec_Config_HTTP_Plugin_Cache_Key_Eval{
			Eval: `"shared-by-everyone"`,
		},
	})

	serve := func(usrT *tstuser.User) *http.Response {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)
		req.Header.Set("Cookie", "octelium_auth="+utilrand.GetRandomString(8))

		reqCtx := newCacheTestReqCtx(svcCfg)
		reqCtx.IsAuthenticated = true
		reqCtx.DownstreamInfo = &corev1.RequestContext{
			Session: usrT.Session,
			User:    usrT.Usr,
		}

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext, reqCtx))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)

		return rw.Result()
	}

	usr1, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	usr2, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	assert.Equal(t, "MISS", serve(usr1).Header.Get("X-Cache"))
	assert.Equal(t, "HIT", serve(usr1).Header.Get("X-Cache"))

	assert.Equal(t, "MISS", serve(usr2).Header.Get("X-Cache"))
	assert.Equal(t, "HIT", serve(usr2).Header.Get("X-Cache"))
}

func TestPreAuthRefusesCredentialedRequests(t *testing.T) {
	for _, isCustomKey := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
		req.Header.Set("Authorization", "Bearer tkn")

		assert.False(t, requestAllowsCache(req, isCustomKey,
			corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH))

		req = httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
		req.Header.Set("Cookie", "octelium_auth=tkn")

		assert.False(t, requestAllowsCache(req, isCustomKey,
			corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH))

		req = httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)

		assert.True(t, requestAllowsCache(req, isCustomKey,
			corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH))
	}
}
