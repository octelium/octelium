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
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
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

func newConnectedSession(typ corev1.Session_Status_Connection_Type, addrs ...*metav1.DualStackNetwork) *corev1.Session {
	return &corev1.Session{
		Metadata: &metav1.Metadata{
			Uid:  utilrand.GetRandomStringCanonical(8),
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Status: &corev1.Session_Status{
			IsConnected: true,
			Connection: &corev1.Session_Status_Connection{
				Type:      typ,
				Addresses: addrs,
			},
		},
	}
}

func TestSessionIndexes(t *testing.T) {
	c := NewController(nil)

	wg := upstream.ConnIndex{
		Type:  corev1.Session_Status_Connection_WIREGUARD,
		Index: 0x0102,
	}

	sess := newConnectedSession(corev1.Session_Status_Connection_WIREGUARD,
		&metav1.DualStackNetwork{V4: "10.10.1.2/32", V6: "fdee::1:102/128"})

	assert.Nil(t, c.OnAdd(context.Background(), sess))
	assert.True(t, c.getOwnedIndexes(nil)[wg])

	disconnected := proto.Clone(sess).(*corev1.Session)
	disconnected.Status.IsConnected = false
	disconnected.Status.Connection = nil

	assert.Nil(t, c.OnUpdate(context.Background(), disconnected, sess))
	assert.False(t, c.getOwnedIndexes(nil)[wg])
	assert.Equal(t, 0, len(c.indexes))

	assert.Nil(t, c.OnUpdate(context.Background(), sess, disconnected))
	assert.True(t, c.getOwnedIndexes(nil)[wg])

	assert.Nil(t, c.OnDelete(context.Background(), disconnected))
	assert.False(t, c.getOwnedIndexes(nil)[wg])
	assert.Equal(t, 0, len(c.indexes))

	assert.Nil(t, c.OnAdd(context.Background(), &corev1.Session{}))
	assert.Nil(t, c.OnDelete(context.Background(), &corev1.Session{}))
}

func TestGetOwnedIndexes(t *testing.T) {
	c := NewController(nil)

	wgSess := newConnectedSession(corev1.Session_Status_Connection_WIREGUARD,
		&metav1.DualStackNetwork{V4: "10.10.0.5/32"})
	quicSess := newConnectedSession(corev1.Session_Status_Connection_QUICV0,
		&metav1.DualStackNetwork{V6: "fdee::2:10/128"})
	unknownSess := newConnectedSession(corev1.Session_Status_Connection_TYPE_UNKNOWN,
		&metav1.DualStackNetwork{V4: "10.10.0.7/32"})
	watchedSess := newConnectedSession(corev1.Session_Status_Connection_WIREGUARD,
		&metav1.DualStackNetwork{V4: "10.10.3.4/32"})

	assert.Nil(t, c.OnAdd(context.Background(), watchedSess))

	owned := c.getOwnedIndexes([]*corev1.Session{
		wgSess,
		quicSess,
		unknownSess,
		{Status: &corev1.Session_Status{}},
	})

	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 5}])
	assert.False(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_QUICV0, Index: 5}])

	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_QUICV0, Index: 0x10}])
	assert.False(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 0x10}])

	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 7}])
	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_QUICV0, Index: 7}])

	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 0x0304}])

	assert.Equal(t, 5, len(owned))
}

func TestSelectOrphans(t *testing.T) {
	c := NewController(nil)

	owned := upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 1}
	orphan := upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 2}
	transient := upstream.ConnIndex{Type: corev1.Session_Status_Connection_QUICV0, Index: 2}
	ownedMap := map[upstream.ConnIndex]bool{owned: true}

	for i := 1; i < orphanReleaseRounds; i++ {
		ret := c.selectOrphans([]upstream.ConnIndex{owned, orphan, transient, orphan}, ownedMap)
		assert.Equal(t, 0, len(ret))
		assert.Equal(t, i, c.orphans[orphan])
		assert.Equal(t, i, c.orphans[transient])
	}

	ret := c.selectOrphans([]upstream.ConnIndex{owned, orphan}, map[upstream.ConnIndex]bool{
		owned:     true,
		transient: true,
	})
	assert.Equal(t, []upstream.ConnIndex{orphan}, ret)
	assert.Equal(t, 0, c.orphans[transient])

	ret = c.selectOrphans([]upstream.ConnIndex{owned, transient}, ownedMap)
	assert.Equal(t, 0, len(ret))
	assert.Equal(t, 1, c.orphans[transient])
	assert.Equal(t, 0, c.orphans[orphan])

	ret = c.selectOrphans([]upstream.ConnIndex{owned, transient}, map[upstream.ConnIndex]bool{
		owned:     true,
		transient: true,
	})
	assert.Equal(t, 0, len(ret))
	assert.Equal(t, 0, len(c.orphans))
}

func TestReconcile(t *testing.T) {

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

	connected, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err, "%+v", err)
	err = connected.Connect()
	assert.Nil(t, err, "%+v", err)

	leaked, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err, "%+v", err)
	err = leaked.ConnectQUIC0()
	assert.Nil(t, err, "%+v", err)
	_, err = fakeC.OcteliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{Uid: leaked.Session.Metadata.Uid})
	assert.Nil(t, err, "%+v", err)

	watchedOnly := newConnectedSession(corev1.Session_Status_Connection_WIREGUARD)
	err = upstream.AddAddressToConnection(ctx, fakeC.OcteliumC, watchedOnly)
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, c.OnAdd(ctx, watchedOnly))

	assert.Equal(t, 2, len(getConnInfo().ActiveIndexesWG))
	assert.Equal(t, 1, len(getConnInfo().ActiveIndexesQUIC))

	for i := 1; i < orphanReleaseRounds; i++ {
		err = c.reconcile(ctx)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, len(getConnInfo().ActiveIndexesWG))
		assert.Equal(t, 1, len(getConnInfo().ActiveIndexesQUIC))
	}

	err = c.reconcile(ctx)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 2, len(getConnInfo().ActiveIndexesWG))
	assert.Equal(t, 0, len(getConnInfo().ActiveIndexesQUIC))
	assert.Equal(t, 0, len(c.orphans))

	{
		sess, err := fakeC.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: connected.Session.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, upstream.GetConnectionIndexes(sess)[0].Index,
			getConnInfo().ActiveIndexesWG[0])
	}

	assert.Nil(t, c.OnDelete(ctx, &corev1.Session{Metadata: watchedOnly.Metadata}))

	for i := 0; i < orphanReleaseRounds; i++ {
		err = c.reconcile(ctx)
		assert.Nil(t, err, "%+v", err)
	}
	assert.Equal(t, 1, len(getConnInfo().ActiveIndexesWG))
}
