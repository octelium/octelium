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
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
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

		headerCfg := &corev1.Service_Spec_Config_HTTP_Header{ForwardedMode: mode}

		applyForwardedHeaders(pr, newForwardedSvc(false), headerCfg, false, "https", "example.com", "obf")

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
		headerCfg := &corev1.Service_Spec_Config_HTTP_Header{
			ForwardedMode: corev1.Service_Spec_Config_HTTP_Header_TRANSPARENT,
		}
		applyForwardedHeaders(pr, newForwardedSvc(false), headerCfg, false, "https", "example.com", "obf")

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

func TestMCPCommonConfig(t *testing.T) {

	cfg := ucorev1.ToServiceConfig(&corev1.Service_Spec_Config{
		Type: &corev1.Service_Spec_Config_Mcp{
			Mcp: &corev1.Service_Spec_Config_MCP{
				Header: &corev1.Service_Spec_Config_HTTP_Header{
					ForwardedMode: corev1.Service_Spec_Config_HTTP_Header_TRANSPARENT,
					Host: &corev1.Service_Spec_Config_HTTP_Header_Host{
						Type: &corev1.Service_Spec_Config_HTTP_Header_Host_Value{
							Value: "upstream.internal",
						},
					},
					AddResponseHeaders: []*corev1.Service_Spec_Config_HTTP_Header_KeyValue{
						{
							Key:  "X-Octelium-Test",
							Type: &corev1.Service_Spec_Config_HTTP_Header_KeyValue_Value{Value: "1"},
						},
					},
				},
				Auth: &corev1.Service_Spec_Config_HTTP_Auth{
					Type: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4_{
						Sigv4: &corev1.Service_Spec_Config_HTTP_Auth_Sigv4{
							Region:  "us-east-1",
							Service: "s3",
						},
					},
				},
				Path: &corev1.Service_Spec_Config_HTTP_Path{
					AddPrefix: "/api",
				},
				Plugins: []*corev1.Service_Spec_Config_MCP_Plugin{
					{Name: "tst"},
				},
			},
		},
	})

	headerCfg := cfg.GetHTTPHeader()
	assert.NotNil(t, headerCfg)
	assert.Equal(t, "upstream.internal", headerCfg.GetHost().GetValue())
	assert.Equal(t, corev1.Service_Spec_Config_HTTP_Header_TRANSPARENT, headerCfg.ForwardedMode)
	assert.Len(t, headerCfg.AddResponseHeaders, 1)

	assert.NotNil(t, cfg.GetHTTPAuth().GetSigv4())
	assert.Equal(t, "us-east-1", cfg.GetHTTPAuth().GetSigv4().Region)

	assert.Equal(t, "/api", cfg.GetHTTPPath().AddPrefix)
	assert.Len(t, cfg.GetHTTPPlugins(), 1)

	visibility := cfg.GetMCPVisibility()
	assert.True(t, visibility.EnableRequestBody)
	assert.True(t, visibility.EnableResponseBody)

	pr := newForwardedProxyRequest(t, map[string]string{
		"X-Forwarded-For":    "1.2.3.4",
		"X-Forwarded-Prefix": "/prefix",
	})

	applyForwardedHeaders(pr, newForwardedSvc(false), headerCfg, false, "https", "example.com", "obf")

	assert.Equal(t, "/prefix", pr.Out.Header.Get("X-Forwarded-Prefix"))
}

func newUpstreamPathService(mode corev1.Service_Spec_Mode) *corev1.Service {
	return &corev1.Service{
		Spec: &corev1.Service_Spec{
			Mode: mode,
		},
	}
}

func TestGetUpstreamPathLLM(t *testing.T) {
	svc := newUpstreamPathService(corev1.Service_Spec_LLM)

	assert.Equal(t, "/api/v1/chat/completions",
		getUpstreamPath(svc, "/api/v1", "/v1/chat/completions"))
	assert.Equal(t, "/openai/v1/chat/completions",
		getUpstreamPath(svc, "/openai/v1", "/v1/chat/completions"))
	assert.Equal(t, "/inference/v1/responses",
		getUpstreamPath(svc, "/inference/v1", "/v1/responses"))
	assert.Equal(t, "/v1beta/openai/chat/completions",
		getUpstreamPath(svc, "/v1beta/openai", "/v1/chat/completions"))
	assert.Equal(t, "/api/v1/models",
		getUpstreamPath(svc, "/api/v1", "/v1/models"))
	assert.Equal(t, "/api/v1/models/gpt-4o",
		getUpstreamPath(svc, "/api/v1", "/v1/models/gpt-4o"))
	assert.Equal(t, "/anthropic/v1/messages",
		getUpstreamPath(svc, "/anthropic/v1", "/v1/messages"))

	assert.Equal(t, "/v1/chat/completions",
		getUpstreamPath(svc, "", "/v1/chat/completions"))
}

func TestGetUpstreamPathMCP(t *testing.T) {
	svc := newUpstreamPathService(corev1.Service_Spec_MCP)

	assert.Equal(t, "/api/mcp", getUpstreamPath(svc, "/api/mcp", "/mcp"))
	assert.Equal(t, "/mcp", getUpstreamPath(svc, "/mcp", "/mcp"))
	assert.Equal(t, "/messages", getUpstreamPath(svc, "/messages", "/mcp"))
	assert.Equal(t, "/api/mcp", getUpstreamPath(svc, "/api/mcp", "/"))

	assert.Equal(t, "/mcp", getUpstreamPath(svc, "", "/mcp"))
}

func TestGetUpstreamPathOtherModes(t *testing.T) {
	for _, mode := range []corev1.Service_Spec_Mode{
		corev1.Service_Spec_HTTP,
		corev1.Service_Spec_WEB,
		corev1.Service_Spec_GRPC,
		corev1.Service_Spec_KUBERNETES,
	} {
		svc := newUpstreamPathService(mode)

		assert.Equal(t, "/v1/chat/completions",
			getUpstreamPath(svc, "/api/v1", "/v1/chat/completions"), mode.String())
		assert.Equal(t, "/foo", getUpstreamPath(svc, "/api", "/foo"), mode.String())
	}
}
