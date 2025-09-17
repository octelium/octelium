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

package conncontroller

/*
import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func TestController(t *testing.T) {

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
	usrSrv := user.NewServer(tst.C.OcteliumC)

	netw, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	c := NewController(fakeC.OcteliumC)
	svc, err := adminSrv.CreateService(ctx, tests.GenService(netw.Metadata.Name))
	assert.Nil(t, err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	oldSess := pbutils.Clone(usr.Session).(*corev1.Session)

	err = c.OnAdd(ctx, oldSess)
	assert.Nil(t, err)

	svc.Spec.Config = &corev1.Service_Spec_Config{
		Upstream: &corev1.Service_Spec_Config_Upstream{
			Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{
				Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{
					Endpoints: []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
						{
							Url:  "http://localhost",
							User: usr.Usr.Metadata.Name,
						},
					},
				},
			},
		},
	}

	svc, err = adminSrv.UpdateService(ctx, svc)
	assert.Nil(t, err)

	err = usr.ConnectWithServeAll()
	assert.Nil(t, err)
	usr.Resync()

	err = c.OnUpdate(ctx, usr.Session, oldSess)
	assert.Nil(t, err)

	assert.NotNil(t, usr.Session.Status.Connection)
	assert.NotNil(t, usr.Session.Status.Connection.Upstreams)
	assert.Equal(t, svc.Metadata.Uid, usr.Session.Status.Connection.Upstreams[0].ServiceRef.Uid)
}

*/
