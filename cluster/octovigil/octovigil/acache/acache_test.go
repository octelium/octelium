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

package acache

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {

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
	usrSrv := user.NewServer(tst.C.OcteliumC)

	grp, err := tst.C.OcteliumC.CoreC().CreateGroup(ctx, &corev1.Group{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Group_Spec{},
	})
	assert.Nil(t, err)

	usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, []string{grp.Metadata.Name})
	assert.Nil(t, err)

	c, err := NewCache()
	assert.Nil(t, err)
	defer c.Close()

	err = c.SetGroup(grp)
	assert.Nil(t, err)

	err = c.SetUser(usr.Usr)
	assert.Nil(t, err)

	usr.Connect()
	err = c.SetSession(usr.Session)
	assert.Nil(t, err)

	getAddrV4 := func(addr *metav1.DualStackNetwork) string {
		return umetav1.ToDualStackNetwork(addr).ToIP().Ipv4
	}
	getAddrV6 := func(addr *metav1.DualStackNetwork) string {
		return umetav1.ToDualStackNetwork(addr).ToIP().Ipv6
	}

	{
		di, err := c.GetDownstreamInfoBySessionIdentifier(getAddrV4(usr.Session.Status.Connection.Addresses[0]))
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(usr.Session, di.Session))
		assert.Equal(t, usr.Usr.Metadata.Uid, di.User.Metadata.Uid)
		assert.Equal(t, grp.Metadata.Uid, di.Groups[0].Metadata.Uid)
	}
	{
		di, err := c.GetDownstreamInfoBySessionIdentifier(getAddrV6(usr.Session.Status.Connection.Addresses[0]))
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(usr.Session, di.Session))
	}

	{
		webSess, err := usr.NewSessionWithType(corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)
		c.SetSession(webSess)
		di, err := c.GetDownstreamInfoBySessionIdentifier(webSess.Metadata.Uid)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(webSess, di.Session))
	}

}
