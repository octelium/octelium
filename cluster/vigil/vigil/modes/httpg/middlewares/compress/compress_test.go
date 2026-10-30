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

package compress

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/httputils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompressionNegotiation(t *testing.T) {
	body := strings.Repeat("compressible response ", 256)
	h, err := New(t.Context(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	require.Nil(t, err)
	for _, tc := range []struct {
		encoding string
		want     bool
	}{{"gzip", true}, {"", false}, {"identity", false}, {"gzip;q=0", false}} {
		t.Run(tc.encoding, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req = req.WithContext(context.WithValue(t.Context(), middlewares.CtxRequestContext, &middlewares.RequestContext{}))
			req.Header.Set("Accept-Encoding", tc.encoding)
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, req)
			got := rw.Body.Bytes()
			if tc.want {
				assert.Equal(t, "gzip", rw.Header().Get("Content-Encoding"))
				reader, err := gzip.NewReader(rw.Body)
				require.Nil(t, err)
				defer reader.Close()
				got, err = io.ReadAll(reader)
				require.Nil(t, err)
			} else {
				assert.Empty(t, rw.Header().Get("Content-Encoding"))
			}
			assert.Equal(t, body, string(got))
		})
	}
}

func TestStreamingResponsesBypassCompression(t *testing.T) {
	body := strings.Repeat("streamed response ", 256)
	h, err := New(t.Context(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(body))
	}))
	require.Nil(t, err)
	for _, tc := range []struct {
		name   string
		path   string
		header http.Header
		ctx    *middlewares.RequestContext
	}{
		{name: "SSE", header: http.Header{"Accept": {"text/event-stream"}}},
		{name: "Upgrade", header: http.Header{"Connection": {"keep-alive, Upgrade"}}},
		{name: "BufferingDisabled", header: http.Header{"X-Accel-Buffering": {"NO"}}},
		{name: "LLM", ctx: &middlewares.RequestContext{LLM: &httputils.LLMRequest{Stream: true}}},
		{name: "Exec", path: "/api/v1/pods/app/exec", ctx: &middlewares.RequestContext{Service: &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_KUBERNETES}}}},
		{name: "Attach", path: "/api/v1/pods/app/attach", ctx: &middlewares.RequestContext{Service: &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_KUBERNETES}}}},
		{name: "Log", path: "/api/v1/pods/app/log", ctx: &middlewares.RequestContext{Service: &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_KUBERNETES}}}},
		{name: "PortForward", path: "/api/v1/pods/app/portforward", ctx: &middlewares.RequestContext{Service: &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_KUBERNETES}}}},
		{name: "Watch", path: "/api/v1/pods?watch=true", ctx: &middlewares.RequestContext{Service: &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_KUBERNETES}}}},
		{name: "Follow", path: "/api/v1/pods?follow=1", ctx: &middlewares.RequestContext{Service: &corev1.Service{Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_KUBERNETES}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path
			if path == "" {
				path = "/"
			}
			req := httptest.NewRequest(http.MethodGet, path, nil)
			if tc.header != nil {
				req.Header = tc.header.Clone()
			}
			req.Header.Set("Accept-Encoding", "gzip")
			if tc.ctx != nil {
				req = req.WithContext(context.WithValue(t.Context(), middlewares.CtxRequestContext, tc.ctx))
			}
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, req)
			assert.Empty(t, rw.Header().Get("Content-Encoding"))
			assert.Equal(t, body, rw.Body.String())
		})
	}
}
