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

package lua

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func TestMiddleware(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	var rReq *http.Request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rReq = r
	})
	mdlwr, err := New(ctx, next, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	{
		usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				DownstreamInfo: &corev1.RequestContext{
					User:    usrT.Usr,
					Session: usrT.Session,
				},

				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
										Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
											Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
												Inline: `
function onRequest(ctx)
  octelium.req.setRequestHeader("X-User-Uid", ctx.user.metadata.uid)
end

function onResponse(ctx)
  octelium.req.setResponseHeader("X-Session-Uid", ctx.session.metadata.uid)
  octelium.req.setResponseBody(json.encode(ctx.user))
end`,
											},
										},
									},
								},
							},
						},
					},
				},
			}))

		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		rw := httptest.NewRecorder()

		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, reqCtx.DownstreamInfo.User.Metadata.Uid, rReq.Header.Get("X-User-Uid"))

		assert.Equal(t, reqCtx.DownstreamInfo.Session.Metadata.Uid, rw.Header().Get("X-Session-Uid"))

		resp := rw.Result()
		assert.Equal(t, resp.StatusCode, http.StatusOK)

		bb, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)
		resp.Body.Close()
		usr := &corev1.User{}
		err = pbutils.UnmarshalJSON(bb, usr)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(reqCtx.DownstreamInfo.User, usr))

	}
}

func TestWithExit(t *testing.T) {

	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	})
	mdlwr, err := New(ctx, next, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	{
		usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err)
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
				DownstreamInfo: &corev1.RequestContext{
					User:    usrT.Usr,
					Session: usrT.Session,
				},

				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
										Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
											Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
												Inline: `
function onRequest(ctx)
  octelium.req.setResponseBody(json.encode(ctx.session))
  octelium.req.setResponseHeader("X-Uid", ctx.user.metadata.uid)
  octelium.req.exit(207)
end

function onResponse(ctx)
  octelium.req.setResponseHeader("X-Session-Uid", ctx.session.metadata.uid)
  octelium.req.setResponseBody(json.encode(ctx.user))
end`,
											},
										},
									},
								},
							},
						},
					},
				},
			}))

		reqCtx := middlewares.GetCtxRequestContext(req.Context())
		rw := httptest.NewRecorder()

		mdlwr.ServeHTTP(rw, req)

		resp := rw.Result()
		assert.Equal(t, 207, resp.StatusCode)

		assert.Equal(t, usrT.Usr.Metadata.Uid, rw.Header().Get("X-Uid"))

		bb, err := io.ReadAll(resp.Body)
		assert.Nil(t, err)
		resp.Body.Close()
		sess := &corev1.Session{}
		err = pbutils.UnmarshalJSON(bb, sess)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(reqCtx.DownstreamInfo.Session, sess))

	}
}
