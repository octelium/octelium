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
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
)

const consoleOrigin = "https://console.example.com"

func newCORSService(mode corev1.Service_Spec_Mode,
	cors *corev1.Service_Spec_Config_HTTP_CORS) *corev1.Service {

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{Name: "my-svc.default"},
		Spec: &corev1.Service_Spec{
			Mode:     mode,
			IsPublic: true,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "default"},
		},
	}

	switch mode {
	case corev1.Service_Spec_MCP:
		svc.Spec.Config = &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Mcp{
				Mcp: &corev1.Service_Spec_Config_MCP{Cors: cors},
			},
		}
	case corev1.Service_Spec_LLM:
		svc.Spec.Config = &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Llm{
				Llm: &corev1.Service_Spec_Config_LLM{Cors: cors},
			},
		}
	default:
		svc.Spec.Config = &corev1.Service_Spec_Config{
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{Cors: cors},
			},
		}
	}

	return svc
}

func serveCORS(t *testing.T, svc *corev1.Service, method, origin string,
	preflight bool, next http.Handler) *http.Response {

	ctx := context.Background()

	if next == nil {
		next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	}

	mdlwr, err := New(ctx, next, nil, "example.com")
	assert.Nil(t, err)

	req := httptest.NewRequest(method,
		"http://my-svc.example.com/mcp", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if preflight {
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		req.Header.Set("Access-Control-Request-Headers", "content-type,mcp-session-id")
	}

	req = req.WithContext(context.WithValue(ctx,
		middlewares.CtxRequestContext,
		&middlewares.RequestContext{
			CreatedAt: time.Now(),
			Service:   svc,
		}))

	rw := httptest.NewRecorder()
	mdlwr.ServeHTTP(rw, req)

	return rw.Result()
}

func TestCORSPreflight(t *testing.T) {

	for _, mode := range []corev1.Service_Spec_Mode{
		corev1.Service_Spec_MCP,
		corev1.Service_Spec_LLM,
		corev1.Service_Spec_HTTP,
	} {
		svc := newCORSService(mode, &corev1.Service_Spec_Config_HTTP_CORS{
			AllowOriginStringMatch: []string{consoleOrigin},
			AllowCredentials:       true,
		})

		var isNext bool
		resp := serveCORS(t, svc, http.MethodOptions, consoleOrigin, true,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				isNext = true
			}))

		assert.False(t, isNext, mode.String())
		assert.Equal(t, http.StatusNoContent, resp.StatusCode, mode.String())
		assert.Equal(t, consoleOrigin,
			resp.Header.Get("Access-Control-Allow-Origin"), mode.String())
		assert.Equal(t, "true",
			resp.Header.Get("Access-Control-Allow-Credentials"), mode.String())
		assert.Equal(t, http.MethodPost,
			resp.Header.Get("Access-Control-Allow-Methods"), mode.String())
		assert.Equal(t, "content-type,mcp-session-id",
			resp.Header.Get("Access-Control-Allow-Headers"), mode.String())
		assert.Contains(t, resp.Header.Values("Vary"), "Origin", mode.String())
	}
}

func TestCORSPreflightDenied(t *testing.T) {
	svc := newCORSService(corev1.Service_Spec_MCP,
		&corev1.Service_Spec_Config_HTTP_CORS{
			AllowOriginStringMatch: []string{consoleOrigin},
		})

	resp := serveCORS(t, svc, http.MethodOptions, "https://evil.example.com", true, nil)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

func TestCORSPreflightSameOrigin(t *testing.T) {
	svc := newCORSService(corev1.Service_Spec_MCP, nil)

	resp := serveCORS(t, svc, http.MethodOptions, "https://my-svc.example.com", true, nil)

	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Equal(t, "https://my-svc.example.com",
		resp.Header.Get("Access-Control-Allow-Origin"))
}

func TestCORSWildcardNeverLiteral(t *testing.T) {
	svc := newCORSService(corev1.Service_Spec_LLM,
		&corev1.Service_Spec_Config_HTTP_CORS{
			AllowOriginStringMatch: []string{"*"},
			AllowCredentials:       true,
		})

	resp := serveCORS(t, svc, http.MethodOptions, consoleOrigin, true, nil)

	assert.Equal(t, consoleOrigin, resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
}

func TestCORSResponseHeadersOnDenial(t *testing.T) {
	svc := newCORSService(corev1.Service_Spec_MCP,
		&corev1.Service_Spec_Config_HTTP_CORS{
			AllowOriginStringMatch: []string{consoleOrigin},
			AllowCredentials:       true,
			ExposeHeaders:          "mcp-session-id",
		})

	resp := serveCORS(t, svc, http.MethodPost, consoleOrigin, false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, consoleOrigin, resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", resp.Header.Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "mcp-session-id", resp.Header.Get("Access-Control-Expose-Headers"))
	assert.Contains(t, resp.Header.Values("Vary"), "Origin")
}

func TestCORSResponseHeadersOverrideUpstream(t *testing.T) {
	svc := newCORSService(corev1.Service_Spec_LLM,
		&corev1.Service_Spec_Config_HTTP_CORS{
			AllowOriginStringMatch: []string{consoleOrigin},
		})

	resp := serveCORS(t, svc, http.MethodPost, consoleOrigin, false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "https://upstream.example.com")
			w.WriteHeader(http.StatusOK)
		}))

	assert.Equal(t, []string{consoleOrigin},
		resp.Header.Values("Access-Control-Allow-Origin"))
}

func TestCORSDisallowedOriginGetsNoHeaders(t *testing.T) {
	svc := newCORSService(corev1.Service_Spec_LLM,
		&corev1.Service_Spec_Config_HTTP_CORS{
			AllowOriginStringMatch: []string{consoleOrigin},
		})

	resp := serveCORS(t, svc, http.MethodPost, "https://evil.example.com", false, nil)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, resp.Header.Values("Vary"), "Origin")
}

func TestCORSAllowClusterServices(t *testing.T) {

	for _, mode := range []corev1.Service_Spec_Mode{
		corev1.Service_Spec_MCP,
		corev1.Service_Spec_LLM,
		corev1.Service_Spec_HTTP,
	} {
		svc := newCORSService(mode, &corev1.Service_Spec_Config_HTTP_CORS{
			AllowClusterServices: true,
		})

		for _, origin := range []string{
			"https://console.octelium.example.com",
			"https://my-mcp.example.com",
			"https://a.b.c.example.com",
			"https://example.com",
		} {
			resp := serveCORS(t, svc, http.MethodOptions, origin, true, nil)

			assert.Equal(t, http.StatusNoContent, resp.StatusCode, origin)
			assert.Equal(t, origin,
				resp.Header.Get("Access-Control-Allow-Origin"), origin)
			assert.Equal(t, "true",
				resp.Header.Get("Access-Control-Allow-Credentials"), origin)

			resp = serveCORS(t, svc, http.MethodPost, origin, false, nil)

			assert.Equal(t, origin,
				resp.Header.Get("Access-Control-Allow-Origin"), origin)
			assert.Equal(t, "true",
				resp.Header.Get("Access-Control-Allow-Credentials"), origin)
		}
	}
}

func TestCORSAllowClusterServicesRejected(t *testing.T) {
	svc := newCORSService(corev1.Service_Spec_MCP,
		&corev1.Service_Spec_Config_HTTP_CORS{
			AllowClusterServices: true,
		})

	for _, origin := range []string{
		"https://evil.com",
		"https://notexample.com",
		"https://example.com.evil.com",
		"https://evilexample.com",
		"http://other.example.com",
	} {
		resp := serveCORS(t, svc, http.MethodOptions, origin, true, nil)

		assert.Equal(t, http.StatusForbidden, resp.StatusCode, origin)
		assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"), origin)
	}
}

func TestCORSAllowClusterServicesDisabled(t *testing.T) {
	svc := newCORSService(corev1.Service_Spec_MCP,
		&corev1.Service_Spec_Config_HTTP_CORS{})

	resp := serveCORS(t, svc, http.MethodOptions,
		"https://console.octelium.example.com", true, nil)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Origin"))
}

func TestCORSAllowClusterServicesOtherOrigins(t *testing.T) {
	const externalOrigin = "https://app.partner.org"

	svc := newCORSService(corev1.Service_Spec_MCP,
		&corev1.Service_Spec_Config_HTTP_CORS{
			AllowClusterServices:   true,
			AllowOriginStringMatch: []string{externalOrigin},
		})

	resp := serveCORS(t, svc, http.MethodPost, externalOrigin, false, nil)

	assert.Equal(t, externalOrigin, resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Empty(t, resp.Header.Get("Access-Control-Allow-Credentials"))

	resp = serveCORS(t, svc, http.MethodOptions, "https://evil.example.org", true, nil)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
