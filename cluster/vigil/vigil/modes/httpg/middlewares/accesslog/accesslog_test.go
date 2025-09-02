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

package accesslog

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
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
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},

				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Visibility: &corev1.Service_Spec_Config_HTTP_Visibility{
							EnableRequestBody:     true,
							EnableResponseBody:    true,
							EnableRequestBodyMap:  true,
							EnableResponseBodyMap: true,
						},
					},
				},
			},
			Mode: corev1.Service_Spec_HTTP,
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	respBody := utilrand.GetRandomString(512)
	statusCode := 418
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		w.Write([]byte(respBody))
	})

	mdlwr, err := New(ctx, next)
	assert.Nil(t, err)

	{
		reqPath := fmt.Sprintf("/prefix/%s", utilrand.GetRandomStringCanonical(12))

		usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)

		jsn, err := pbutils.MarshalJSON(usrT.Usr, false)
		assert.Nil(t, err)
		req := httptest.NewRequest(http.MethodPost, reqPath, bytes.NewBuffer(jsn))

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				Service:   svc,
				DownstreamInfo: &corev1.RequestContext{
					User:    usrT.Usr,
					Session: usrT.Session,
					Service: svc,
				},
				ServiceConfig: svc.Spec.Config,
				Body:          jsn,
				DownstreamRequest: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "127.0.0.1",
						Port:    12345,
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{},
						},
					},
				},
			}))

		rw := httptest.NewRecorder()
		mdlwr.ServeHTTP(rw, req)
		resp := rw.Result()
		body, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)
		assert.Equal(t, statusCode, resp.StatusCode)
		assert.Equal(t, respBody, string(body))
	}

}
