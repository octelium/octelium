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
		assert.True(t, reqCtx.IsAuthorized)
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
