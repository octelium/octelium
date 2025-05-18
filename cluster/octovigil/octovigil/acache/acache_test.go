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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func TestCache(t *testing.T) {

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

	usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	c, err := NewCache()
	assert.Nil(t, err)
	defer c.Close()

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
