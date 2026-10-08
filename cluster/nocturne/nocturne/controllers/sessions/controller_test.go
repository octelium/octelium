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

package sesscontroller

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestOnDelete(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	c := NewController(fakeC.OcteliumC)

	getConnInfo := func() *cclusterv1.ClusterConnInfo {
		cfg, err := fakeC.OcteliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: "sys:conn-info"})
		assert.Nil(t, err, "%+v", err)

		ret := &cclusterv1.ClusterConnInfo{}
		err = pbutils.StructToMessage(cfg.Data.GetAttrs(), ret)
		assert.Nil(t, err, "%+v", err)
		return ret
	}

	deleteSession := func(sess *corev1.Session) {
		_, err := fakeC.OcteliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{Uid: sess.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
	}

	other, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err, "%+v", err)
	err = other.Connect()
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 1, len(getConnInfo().ActiveIndexesWG))

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err, "%+v", err)
		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, len(getConnInfo().ActiveIndexesWG))

		deleteSession(usr.Session)

		err = c.OnDelete(ctx, usr.Session)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(getConnInfo().ActiveIndexesWG))
	}

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err, "%+v", err)
		err = usr.ConnectQUIC0()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(getConnInfo().ActiveIndexesQUIC))

		deleteSession(usr.Session)

		err = c.OnDelete(ctx, usr.Session)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, len(getConnInfo().ActiveIndexesQUIC))
		assert.Equal(t, 1, len(getConnInfo().ActiveIndexesWG))
	}

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err, "%+v", err)

		deleteSession(usr.Session)

		err = c.OnDelete(ctx, usr.Session)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(getConnInfo().ActiveIndexesWG))
	}

	{
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err, "%+v", err)
		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)

		err = upstream.AddAddressToConnection(ctx, fakeC.OcteliumC, usr.Session)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, len(usr.Session.Status.Connection.Addresses))
		assert.Equal(t, 3, len(getConnInfo().ActiveIndexesWG))

		deleteSession(usr.Session)

		partial := proto.Clone(usr.Session).(*corev1.Session)
		partial.Status.Connection.Addresses = partial.Status.Connection.Addresses[:1]
		err = c.OnDelete(ctx, partial)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, len(getConnInfo().ActiveIndexesWG))

		err = c.OnDelete(ctx, usr.Session)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(getConnInfo().ActiveIndexesWG))
		assert.Equal(t, 0, len(usr.Session.Status.Connection.Addresses))

		err = c.OnDelete(ctx, usr.Session)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(getConnInfo().ActiveIndexesWG))
	}

	{
		sess, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: other.Session.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, sess.Status.IsConnected)
		assert.Equal(t, 1, len(sess.Status.Connection.Addresses))
	}
}

func TestOnDeleteNoConnection(t *testing.T) {
	c := NewController(nil)

	assert.Nil(t, c.OnDelete(context.Background(), &corev1.Session{
		Status: &corev1.Session_Status{},
	}))

	assert.Nil(t, c.OnDelete(context.Background(), &corev1.Session{
		Status: &corev1.Session_Status{
			Connection: &corev1.Session_Status_Connection{},
		},
	}))

	assert.Nil(t, c.OnDelete(context.Background(), &corev1.Session{}))
}
