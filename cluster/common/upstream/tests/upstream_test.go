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

package upstreamtests

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func TestAddressToConnection(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	fakeC := tst.C

	getConnInfo := func() *cclusterv1.ClusterConnInfo {
		cfg, err := fakeC.OcteliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: "sys:conn-info"})
		assert.Nil(t, err)

		ret := &cclusterv1.ClusterConnInfo{}

		err = pbutils.StructToMessage(cfg.Data.GetAttrs(), ret)
		return ret
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	usrSrv := user.NewServer(fakeC.OcteliumC)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	network, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	networkK8s, err := fakeC.OcteliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{Name: network.Metadata.Name})
	assert.Nil(t, err)

	_, err = fakeC.OcteliumC.CoreC().UpdateNamespace(ctx, networkK8s)
	assert.Nil(t, err)

	network, err = adminSrv.UpdateNamespace(ctx, network)
	assert.Nil(t, err)

	err = usr.Connect()
	assert.Nil(t, err)
	assert.Equal(t, 1, len(usr.Session.Status.Connection.Addresses))

	assert.Equal(t, 1, len(getConnInfo().ActiveIndexesWG))

	for i := 2; i < 20; i++ {
		err = upstream.AddAddressToConnection(ctx, fakeC.OcteliumC, usr.Session)
		assert.Nil(t, err)
		assert.Equal(t, i, len(usr.Session.Status.Connection.Addresses))

		assert.Equal(t, i, len(getConnInfo().ActiveIndexesWG))
	}
	assert.Equal(t, 19, len(usr.Session.Status.Connection.Addresses))

	err = upstream.RemoveAllAddressFromConnection(ctx, fakeC.OcteliumC, usr.Session)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(getConnInfo().ActiveIndexesWG))
}
