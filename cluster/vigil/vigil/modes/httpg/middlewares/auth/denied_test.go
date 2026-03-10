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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
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
