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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
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
				assert.Equal(t, "", resp.Header.Get("X-Cache"))
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
				assert.Equal(t, "", resp.Header.Get("X-Cache"))
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
