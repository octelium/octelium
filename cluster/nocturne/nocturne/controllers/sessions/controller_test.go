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
	"slices"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

type fakeCoreC struct {
	rcorev1.ResourceServiceClient

	mu       sync.Mutex
	sessions map[string]*corev1.Session
	gets     []string
}

func (c *fakeCoreC) GetSession(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.gets = append(c.gets, in.Uid)

	if sess, ok := c.sessions[in.Uid]; ok {
		return sess, nil
	}

	return nil, status.Error(codes.NotFound, "not found")
}

type fakeOcteliumC struct {
	octeliumc.ClientInterface
	coreC rcorev1.ResourceServiceClient
}

func (c *fakeOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
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
	assert.Equal(t, map[string][]upstream.ConnIndex{
		sess.Metadata.Uid: {wg},
	}, c.getWatchedIndexes())

	disconnected := proto.Clone(sess).(*corev1.Session)
	disconnected.Status.IsConnected = false
	disconnected.Status.Connection = nil

	assert.Nil(t, c.OnUpdate(context.Background(), disconnected, sess))
	assert.Equal(t, 0, len(c.getWatchedIndexes()))

	assert.Nil(t, c.OnUpdate(context.Background(), sess, disconnected))
	assert.Equal(t, []upstream.ConnIndex{wg}, c.getWatchedIndexes()[sess.Metadata.Uid])

	assert.Nil(t, c.OnDelete(context.Background(), disconnected))
	assert.Equal(t, 0, len(c.getWatchedIndexes()))

	assert.Nil(t, c.OnAdd(context.Background(), &corev1.Session{}))
	assert.Nil(t, c.OnDelete(context.Background(), &corev1.Session{}))
}

func TestGetOwnedIndexes(t *testing.T) {
	coreC := &fakeCoreC{
		sessions: make(map[string]*corev1.Session),
	}
	c := NewController(&fakeOcteliumC{
		coreC: coreC,
	})

	wgSess := newConnectedSession(corev1.Session_Status_Connection_WIREGUARD,
		&metav1.DualStackNetwork{V4: "10.10.0.5/32"})
	quicSess := newConnectedSession(corev1.Session_Status_Connection_QUICV0,
		&metav1.DualStackNetwork{V6: "fdee::2:10/128"})
	unknownSess := newConnectedSession(corev1.Session_Status_Connection_TYPE_UNKNOWN,
		&metav1.DualStackNetwork{V4: "10.10.0.7/32"})
	watchedSess := newConnectedSession(corev1.Session_Status_Connection_WIREGUARD,
		&metav1.DualStackNetwork{V4: "10.10.3.4/32"})
	newerSess := proto.Clone(watchedSess).(*corev1.Session)
	newerSess.Status.Connection.Addresses = []*metav1.DualStackNetwork{{V4: "10.10.3.5/32"}}
	staleSess := newConnectedSession(corev1.Session_Status_Connection_WIREGUARD,
		&metav1.DualStackNetwork{V4: "10.10.4.4/32"})
	listedSess := newConnectedSession(corev1.Session_Status_Connection_QUICV0,
		&metav1.DualStackNetwork{V4: "10.10.5.5/32"})

	coreC.sessions[watchedSess.Metadata.Uid] = newerSess

	assert.Nil(t, c.OnAdd(context.Background(), watchedSess))
	assert.Nil(t, c.OnAdd(context.Background(), staleSess))
	assert.Nil(t, c.OnAdd(context.Background(), listedSess))

	owned := c.getOwnedIndexes(context.Background(), []*corev1.Session{
		wgSess,
		quicSess,
		unknownSess,
		listedSess,
		{Status: &corev1.Session_Status{}},
	})

	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 5}])
	assert.False(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_QUICV0, Index: 5}])

	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_QUICV0, Index: 0x10}])
	assert.False(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 0x10}])

	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 7}])
	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_QUICV0, Index: 7}])

	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 0x0304}])
	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 0x0305}])
	assert.False(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_WIREGUARD, Index: 0x0404}])
	assert.True(t, owned[upstream.ConnIndex{Type: corev1.Session_Status_Connection_QUICV0, Index: 0x0505}])

	assert.Equal(t, 7, len(owned))

	assert.ElementsMatch(t, []string{watchedSess.Metadata.Uid, staleSess.Metadata.Uid}, coreC.gets)

	watched := c.getWatchedIndexes()
	assert.Equal(t, 2, len(watched))
	assert.NotNil(t, watched[watchedSess.Metadata.Uid])
	assert.NotNil(t, watched[listedSess.Metadata.Uid])
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

type skippingCoreC struct {
	rcorev1.ResourceServiceClient

	mu      sync.Mutex
	skipped string
}

func (c *skippingCoreC) setSkipped(uid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.skipped = uid
}

func (c *skippingCoreC) ListSession(ctx context.Context,
	in *rmetav1.ListOptions, opts ...grpc.CallOption) (*corev1.SessionList, error) {
	ret, err := c.ResourceServiceClient.ListSession(ctx, in, opts...)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	ret.Items = slices.DeleteFunc(ret.Items, func(itm *corev1.Session) bool {
		return itm.Metadata.Uid == c.skipped
	})

	return ret, nil
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

	coreC := &skippingCoreC{
		ResourceServiceClient: fakeC.OcteliumC.CoreC(),
	}
	c := NewController(&fakeOcteliumC{
		ClientInterface: fakeC.OcteliumC,
		coreC:           coreC,
	})

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

	skipped, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err, "%+v", err)
	err = skipped.Connect()
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, c.OnAdd(ctx, skipped.Session))
	coreC.setSkipped(skipped.Session.Metadata.Uid)

	stale := newConnectedSession(corev1.Session_Status_Connection_WIREGUARD)
	err = upstream.AddAddressToConnection(ctx, fakeC.OcteliumC, stale)
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, c.OnAdd(ctx, stale))

	assert.Equal(t, 3, len(getConnInfo().ActiveIndexesWG))
	assert.Equal(t, 1, len(getConnInfo().ActiveIndexesQUIC))

	for i := 1; i < orphanReleaseRounds; i++ {
		err = c.reconcile(ctx)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 3, len(getConnInfo().ActiveIndexesWG))
		assert.Equal(t, 1, len(getConnInfo().ActiveIndexesQUIC))
	}

	err = c.reconcile(ctx)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 0, len(getConnInfo().ActiveIndexesQUIC))
	assert.Equal(t, 0, len(c.orphans))

	assert.ElementsMatch(t, []uint32{
		upstream.GetConnectionIndexes(connected.Session)[0].Index,
		upstream.GetConnectionIndexes(skipped.Session)[0].Index,
	}, getConnInfo().ActiveIndexesWG)

	_, ok := c.getWatchedIndexes()[stale.Metadata.Uid]
	assert.False(t, ok)
	_, ok = c.getWatchedIndexes()[skipped.Session.Metadata.Uid]
	assert.True(t, ok)
}
