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

package vigil

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestServer(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Port: uint32(tests.GetPort()),
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	srv, err := NewServer(ctx, &Opts{
		OcteliumC: fakeC.OcteliumC,
		Service:   svc,
	})
	assert.Nil(t, err, "%+v", err)

	err = srv.server.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	time.Sleep(1 * time.Second)

	svc2 := pbutils.Clone(svc).(*corev1.Service)

	svc2.Spec.Port = 8081
	svc2, err = adminSrv.UpdateService(ctx, svc2)
	assert.Nil(t, err)

	err = srv.svcCtl.FnOnUpdate(ctx, svc2, svc)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	svc3 := pbutils.Clone(svc2).(*corev1.Service)
	svc3.Spec.GetConfig().GetUpstream().Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "postgres://localhost:5432",
	}

	svc3, err = adminSrv.UpdateService(ctx, svc3)
	assert.Nil(t, err)

	err = srv.svcCtl.FnOnUpdate(ctx, svc3, svc2)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	svc4 := pbutils.Clone(svc3).(*corev1.Service)
	svc4.Spec.GetConfig().GetUpstream().Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "ssh://localhost:2022",
	}
	svc4.Spec.Mode = corev1.Service_Spec_SSH

	svc4, err = adminSrv.UpdateService(ctx, svc4)
	assert.Nil(t, err)

	err = srv.svcCtl.FnOnUpdate(ctx, svc4, svc3)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	svc5 := pbutils.Clone(svc4).(*corev1.Service)
	svc5.Spec.GetConfig().GetUpstream().Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "dns://8.8.8.8",
	}

	svc5.Spec.Mode = corev1.Service_Spec_TCP

	svc5, err = adminSrv.UpdateService(ctx, svc5)
	assert.Nil(t, err)

	err = srv.svcCtl.FnOnUpdate(ctx, svc5, svc4)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	err = srv.server.Close()
	assert.Nil(t, err)
}
