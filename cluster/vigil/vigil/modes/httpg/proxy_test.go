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

package httpg

import (
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
)

func newForwardedProxyRequest(t *testing.T, hdrs map[string]string) *httputil.ProxyRequest {
	t.Helper()

	inReq := httptest.NewRequest(http.MethodGet, "http://localhost/v1", nil)
	for k, v := range hdrs {
		inReq.Header.Set(k, v)
	}

	outReq := inReq.Clone(inReq.Context())

	return &httputil.ProxyRequest{In: inReq, Out: outReq}
}

func newForwardedSvc(isManagedSvc bool) *corev1.Service {
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "tst.default"},
		Spec:     &corev1.Service_Spec{},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "default"},
		},
	}
	if isManagedSvc {
		svc.Status.ManagedService = &corev1.Service_Status_ManagedService{Type: "authserver"}
	}
	return svc
}

func TestEnvoyHeadersRemoved(t *testing.T) {
	for _, isManagedSvc := range []bool{false, true} {
		pr := newForwardedProxyRequest(t, map[string]string{
			"X-Envoy-Internal":            "true",
			"X-Envoy-External-Address":    "1.2.3.4",
			"X-Envoy-Max-Retries":         "1000",
			"X-Envoy-Upstream-Rq-Timeout": "60000",
			"X-Envoy-Original-Path":       "/admin",
			"Authorization":               "Bearer tkn",
		})
		pr.Out.Header["x-envoy-force-trace"] = []string{"true"}

		applyForwardedHeaders(pr, newForwardedSvc(isManagedSvc), nil, isManagedSvc, "https", "example.com", "obf")

		for name := range pr.Out.Header {
			assert.False(t, strings.HasPrefix(strings.ToLower(name), "x-envoy-"), name)
		}

		assert.Equal(t, "Bearer tkn", pr.Out.Header.Get("Authorization"))
	}
}

func TestForwardedClientCertRemoved(t *testing.T) {
	for _, mode := range []corev1.Service_Spec_Config_HTTP_Header_ForwardedMode{
		corev1.Service_Spec_Config_HTTP_Header_UNSET,
		corev1.Service_Spec_Config_HTTP_Header_TRANSPARENT,
		corev1.Service_Spec_Config_HTTP_Header_OBFUSCATE,
		corev1.Service_Spec_Config_HTTP_Header_DROP,
	} {
		pr := newForwardedProxyRequest(t, map[string]string{
			"X-Forwarded-Client-Cert": "By=spiffe://cluster/ns/default/sa/admin",
		})

		httpCfg := &corev1.Service_Spec_Config_HTTP{
			Header: &corev1.Service_Spec_Config_HTTP_Header{ForwardedMode: mode},
		}

		applyForwardedHeaders(pr, newForwardedSvc(false), httpCfg, false, "https", "example.com", "obf")

		assert.Equal(t, "", pr.Out.Header.Get("X-Forwarded-Client-Cert"), mode.String())
	}
}

func TestForwardedClientCertRemovedForManagedServices(t *testing.T) {
	pr := newForwardedProxyRequest(t, map[string]string{
		"X-Forwarded-Client-Cert": "By=spiffe://cluster/ns/default/sa/admin",
	})

	applyForwardedHeaders(pr, newForwardedSvc(true), nil, true, "https", "example.com", "obf")

	assert.Equal(t, "", pr.Out.Header.Get("X-Forwarded-Client-Cert"))
}

func TestForwardedPrefixHeadersFollowMode(t *testing.T) {
	hdrs := map[string]string{
		"X-Forwarded-Prefix": "/downstream",
		"X-Forwarded-Uri":    "/downstream/v1",
		"X-Forwarded-Scheme": "http",
	}

	{
		pr := newForwardedProxyRequest(t, hdrs)
		applyForwardedHeaders(pr, newForwardedSvc(false), nil, false, "https", "example.com", "obf")

		assert.Equal(t, "", pr.Out.Header.Get("X-Forwarded-Prefix"))
		assert.Equal(t, "", pr.Out.Header.Get("X-Forwarded-Uri"))
		assert.Equal(t, "", pr.Out.Header.Get("X-Forwarded-Scheme"))
	}

	{
		pr := newForwardedProxyRequest(t, hdrs)
		httpCfg := &corev1.Service_Spec_Config_HTTP{
			Header: &corev1.Service_Spec_Config_HTTP_Header{
				ForwardedMode: corev1.Service_Spec_Config_HTTP_Header_TRANSPARENT,
			},
		}
		applyForwardedHeaders(pr, newForwardedSvc(false), httpCfg, false, "https", "example.com", "obf")

		assert.Equal(t, "/downstream", pr.Out.Header.Get("X-Forwarded-Prefix"))
		assert.Equal(t, "/downstream/v1", pr.Out.Header.Get("X-Forwarded-Uri"))
		assert.Equal(t, "http", pr.Out.Header.Get("X-Forwarded-Scheme"))
	}
}

func TestForwardedModeStillDropsByDefault(t *testing.T) {
	pr := newForwardedProxyRequest(t, map[string]string{
		"X-Forwarded-For":   "9.9.9.9",
		"X-Real-IP":         "9.9.9.9",
		"X-Forwarded-Host":  "evil.example.com",
		"X-Forwarded-Proto": "http",
		"Forwarded":         "for=9.9.9.9",
	})

	applyForwardedHeaders(pr, newForwardedSvc(false), nil, false, "https", "example.com", "obf")

	for _, name := range forwardedHeaderNames {
		assert.Equal(t, "", pr.Out.Header.Get(name), name)
	}
}

func TestForwardedHeadersPreservedForManagedServices(t *testing.T) {
	pr := newForwardedProxyRequest(t, map[string]string{
		"X-Forwarded-For":   "203.0.113.7",
		"X-Forwarded-Proto": "https",
	})

	applyForwardedHeaders(pr, newForwardedSvc(true), nil, true, "https", "example.com", "obf")

	assert.Equal(t, "203.0.113.7", pr.Out.Header.Get("X-Forwarded-For"))
	assert.Equal(t, "https", pr.Out.Header.Get("X-Forwarded-Proto"))
}
