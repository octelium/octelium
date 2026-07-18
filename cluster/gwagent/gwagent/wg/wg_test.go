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

package wg

import (
	"context"
	"sync"
	"testing"
	"time"

	osuser "os/user"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/gw"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func fakeNode(name string) *k8scorev1.Node {
	return &k8scorev1.Node{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: name,
			UID:  types.UID(vutils.UUIDv4()),
		},

		Spec: k8scorev1.NodeSpec{},

		Status: k8scorev1.NodeStatus{},
	}
}

func findPeer(dev *wgtypes.Device, pubKey wgtypes.Key) *wgtypes.Peer {
	for i := range dev.Peers {
		if dev.Peers[i].PublicKey.String() == pubKey.String() {
			return &dev.Peers[i]
		}
	}
	return nil
}

func getSessionPubKey(t *testing.T, sess *corev1.Session) wgtypes.Key {
	pubKey, err := wgtypes.NewKey(sess.Status.Connection.X25519PublicKey)
	assert.Nil(t, err)
	return pubKey
}

func allowedIPSet(peer *wgtypes.Peer) map[string]bool {
	ret := make(map[string]bool)
	for _, addr := range peer.AllowedIPs {
		ret[addr.String()] = true
	}
	return ret
}

func TestGetAllowedIPs(t *testing.T) {

	newSession := func(l3Mode corev1.Session_Status_Connection_L3Mode,
		addrs []*metav1.DualStackNetwork) *corev1.Session {
		return &corev1.Session{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
				Uid:  vutils.UUIDv4(),
			},
			Spec: &corev1.Session_Spec{},
			Status: &corev1.Session_Status{
				Type: corev1.Session_Status_CLIENT,
				Connection: &corev1.Session_Status_Connection{
					Type:      corev1.Session_Status_Connection_WIREGUARD,
					L3Mode:    l3Mode,
					Addresses: addrs,
				},
			},
		}
	}

	addrs := []*metav1.DualStackNetwork{
		{
			V4: "10.0.0.5/32",
			V6: "fd00::5/128",
		},
	}

	{
		sess := newSession(corev1.Session_Status_Connection_BOTH, addrs)
		ret := getAllowedIPs(sess)
		assert.Equal(t, 2, len(ret))
	}
	{
		sess := newSession(corev1.Session_Status_Connection_V4, addrs)
		ret := getAllowedIPs(sess)
		assert.Equal(t, 1, len(ret))
		assert.Equal(t, "10.0.0.5/32", ret[0].String())
	}
	{
		sess := newSession(corev1.Session_Status_Connection_V6, addrs)
		ret := getAllowedIPs(sess)
		assert.Equal(t, 1, len(ret))
		assert.Equal(t, "fd00::5/128", ret[0].String())
	}
	{
		sess := newSession(corev1.Session_Status_Connection_BOTH, nil)
		ret := getAllowedIPs(sess)
		assert.NotNil(t, ret)
		assert.Equal(t, 0, len(ret))
	}
	{
		sess := newSession(corev1.Session_Status_Connection_BOTH, addrs)
		sess.Status.Connection = nil
		ret := getAllowedIPs(sess)
		assert.NotNil(t, ret)
		assert.Equal(t, 0, len(ret))
	}
	{
		sess := newSession(corev1.Session_Status_Connection_BOTH, []*metav1.DualStackNetwork{
			{
				V4: "10.0.0.5/32",
			},
			{
				V6: "fd00::9/128",
			},
		})
		ret := getAllowedIPs(sess)
		assert.Equal(t, 2, len(ret))
	}
}

func TestIsConnWG(t *testing.T) {
	assert.False(t, isConnWG(nil))
	assert.False(t, isConnWG(&corev1.Session_Status_Connection{}))
	assert.False(t, isConnWG(&corev1.Session_Status_Connection{
		Type: corev1.Session_Status_Connection_QUICV0,
	}))
	assert.True(t, isConnWG(&corev1.Session_Status_Connection{
		Type: corev1.Session_Status_Connection_WIREGUARD,
	}))
}

func TestWg(t *testing.T) {

	{
		usr, err := osuser.Current()
		assert.Nil(t, err)
		if usr.Uid != "0" {
			zap.L().Warn("Skipping this test since the running user is not root")
			return
		}
	}

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	node, err := fakeC.K8sC.CoreV1().Nodes().Create(ctx, fakeNode("node"), k8smetav1.CreateOptions{})
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	privateKey, err := wgtypes.GeneratePrivateKey()
	assert.Nil(t, err)
	err = gw.InitGateway(ctx, []string{"1.2.3.4"}, node, fakeC.OcteliumC, 0, &metav1.ObjectReference{
		Name: "default",
		Uid:  vutils.UUIDv4(),
	}, privateKey)
	assert.NotNil(t, err, "%+v", err)

	wgC, err := New(ctx, node, fakeC.OcteliumC, privateKey)
	assert.Nil(t, err, "%+v", err)

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	err = wgC.Run(runCtx)
	assert.Nil(t, err)

	newConnectedUser := func() *tstuser.User {
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)
		err = usr.Connect()
		assert.Nil(t, err)
		return usr
	}

	t.Run("basic", func(t *testing.T) {

		usrs := []*tstuser.User{}

		for i := 0; i < 5; i++ {
			usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
			assert.Nil(t, err)
			usrs = append(usrs, usr)
		}

		for j := 0; j < 5; j++ {
			usr := usrs[utilrand.GetRandomRangeMath(0, len(usrs)-1)]

			err = usr.Connect()
			assert.Nil(t, err)

			err = wgC.AddConnection(usr.Session)
			assert.Nil(t, err)

			device, err := wgC.client.Device(devName)
			assert.Nil(t, err)

			pubKey, err := wgtypes.NewKey(usr.Session.Status.Connection.X25519PublicKey)
			assert.Nil(t, err)

			peer := func() *wgtypes.Peer {
				for _, p := range device.Peers {
					if p.PublicKey.String() == pubKey.String() {
						return &p
					}
				}
				return nil
			}()

			assert.NotNil(t, peer)

			assert.Equal(t, pubKey.String(), peer.PublicKey.String())

		}

	})

	t.Run("nilConnection", func(t *testing.T) {
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		usr.Session.Status.Connection = nil

		assert.Nil(t, wgC.AddConnection(usr.Session))
		assert.Nil(t, wgC.UpdateConnection(usr.Session))
		assert.Nil(t, wgC.RemoveConnection(usr.Session))
	})

	t.Run("nonWireGuardConnection", func(t *testing.T) {
		usr := newConnectedUser()

		pubKey := getSessionPubKey(t, usr.Session)

		usr.Session.Status.Connection.Type = corev1.Session_Status_Connection_QUICV0

		assert.Nil(t, wgC.AddConnection(usr.Session))

		dev, err := wgC.client.Device(devName)
		assert.Nil(t, err)
		assert.Nil(t, findPeer(dev, pubKey))
	})

	t.Run("addSetsAllowedIPs", func(t *testing.T) {
		usr := newConnectedUser()

		err := wgC.AddConnection(usr.Session)
		assert.Nil(t, err)

		dev, err := wgC.client.Device(devName)
		assert.Nil(t, err)

		peer := findPeer(dev, getSessionPubKey(t, usr.Session))
		assert.NotNil(t, peer)

		expected := getAllowedIPs(usr.Session)
		assert.Equal(t, len(expected), len(peer.AllowedIPs))

		got := allowedIPSet(peer)
		for _, addr := range expected {
			assert.True(t, got[addr.String()])
		}
	})

	t.Run("addReplacesAllowedIPs", func(t *testing.T) {
		usr := newConnectedUser()

		err := wgC.AddConnection(usr.Session)
		assert.Nil(t, err)

		dev, err := wgC.client.Device(devName)
		assert.Nil(t, err)
		peer := findPeer(dev, getSessionPubKey(t, usr.Session))
		assert.NotNil(t, peer)
		assert.True(t, len(peer.AllowedIPs) > 0)

		usr.Session.Status.Connection.Addresses = []*metav1.DualStackNetwork{
			{
				V4: "10.77.0.9/32",
				V6: "fd77::9/128",
			},
		}

		err = wgC.AddConnection(usr.Session)
		assert.Nil(t, err)

		dev, err = wgC.client.Device(devName)
		assert.Nil(t, err)
		peer = findPeer(dev, getSessionPubKey(t, usr.Session))
		assert.NotNil(t, peer)

		expected := getAllowedIPs(usr.Session)
		assert.Equal(t, len(expected), len(peer.AllowedIPs))

		got := allowedIPSet(peer)
		for _, addr := range expected {
			assert.True(t, got[addr.String()])
		}
	})

	t.Run("updateReplacesAllowedIPs", func(t *testing.T) {
		usr := newConnectedUser()

		err := wgC.AddConnection(usr.Session)
		assert.Nil(t, err)

		usr.Session.Status.Connection.Addresses = []*metav1.DualStackNetwork{
			{
				V4: "10.88.0.4/32",
				V6: "fd88::4/128",
			},
		}

		err = wgC.UpdateConnection(usr.Session)
		assert.Nil(t, err)

		dev, err := wgC.client.Device(devName)
		assert.Nil(t, err)

		peer := findPeer(dev, getSessionPubKey(t, usr.Session))
		assert.NotNil(t, peer)

		expected := getAllowedIPs(usr.Session)
		assert.Equal(t, len(expected), len(peer.AllowedIPs))

		got := allowedIPSet(peer)
		for _, addr := range expected {
			assert.True(t, got[addr.String()])
		}
	})

	t.Run("updateOnlyDoesNotCreatePeer", func(t *testing.T) {
		usr := newConnectedUser()

		pubKey := getSessionPubKey(t, usr.Session)

		wgC.UpdateConnection(usr.Session)

		dev, err := wgC.client.Device(devName)
		assert.Nil(t, err)
		assert.Nil(t, findPeer(dev, pubKey))
	})

	t.Run("remove", func(t *testing.T) {
		usr := newConnectedUser()

		pubKey := getSessionPubKey(t, usr.Session)

		err := wgC.AddConnection(usr.Session)
		assert.Nil(t, err)

		dev, err := wgC.client.Device(devName)
		assert.Nil(t, err)
		assert.NotNil(t, findPeer(dev, pubKey))

		err = wgC.RemoveConnection(usr.Session)
		assert.Nil(t, err)

		dev, err = wgC.client.Device(devName)
		assert.Nil(t, err)
		assert.Nil(t, findPeer(dev, pubKey))

		err = wgC.RemoveConnection(usr.Session)
		assert.Nil(t, err)
	})

	t.Run("preservesDeviceKeyAndPort", func(t *testing.T) {
		before, err := wgC.client.Device(devName)
		assert.Nil(t, err)

		beforeKey := before.PrivateKey.String()
		beforePort := before.ListenPort

		for i := 0; i < 4; i++ {
			usr := newConnectedUser()

			err = wgC.AddConnection(usr.Session)
			assert.Nil(t, err)

			err = wgC.UpdateConnection(usr.Session)
			assert.Nil(t, err)

			err = wgC.RemoveConnection(usr.Session)
			assert.Nil(t, err)
		}

		after, err := wgC.client.Device(devName)
		assert.Nil(t, err)

		assert.Equal(t, beforeKey, after.PrivateKey.String())
		assert.Equal(t, beforePort, after.ListenPort)
	})

	t.Run("peerOpsDoNotRevertKeyRotation", func(t *testing.T) {
		rotatedKey, err := wgtypes.GeneratePrivateKey()
		assert.Nil(t, err)

		err = wgC.client.ConfigureDevice(devName, wgtypes.Config{
			PrivateKey:   &rotatedKey,
			ReplacePeers: false,
		})
		assert.Nil(t, err)

		usr := newConnectedUser()

		err = wgC.AddConnection(usr.Session)
		assert.Nil(t, err)

		err = wgC.UpdateConnection(usr.Session)
		assert.Nil(t, err)

		err = wgC.RemoveConnection(usr.Session)
		assert.Nil(t, err)

		dev, err := wgC.client.Device(devName)
		assert.Nil(t, err)

		assert.Equal(t, rotatedKey.String(), dev.PrivateKey.String())
		assert.Equal(t, rotatedKey.PublicKey().String(), dev.PublicKey.String())
	})

	t.Run("concurrentOps", func(t *testing.T) {
		usrs := []*tstuser.User{}
		for i := 0; i < 8; i++ {
			usrs = append(usrs, newConnectedUser())
		}

		errCh := make(chan error, len(usrs))

		var wgWait sync.WaitGroup
		for _, usr := range usrs {
			wgWait.Add(1)
			go func(u *tstuser.User) {
				defer wgWait.Done()
				errCh <- wgC.AddConnection(u.Session)
			}(usr)
		}

		wgWait.Wait()
		close(errCh)

		for err := range errCh {
			assert.Nil(t, err)
		}

		dev, err := wgC.client.Device(devName)
		assert.Nil(t, err)

		for _, usr := range usrs {
			peer := findPeer(dev, getSessionPubKey(t, usr.Session))
			assert.NotNil(t, peer)
		}
	})

	t.Run("concurrentMixedOpsKeepDeviceConsistent", func(t *testing.T) {
		before, err := wgC.client.Device(devName)
		assert.Nil(t, err)
		beforeKey := before.PrivateKey.String()
		beforePort := before.ListenPort

		usrs := []*tstuser.User{}
		for i := 0; i < 6; i++ {
			usrs = append(usrs, newConnectedUser())
		}

		var wgWait sync.WaitGroup
		for _, usr := range usrs {
			wgWait.Add(1)
			go func(u *tstuser.User) {
				defer wgWait.Done()
				assert.Nil(t, wgC.AddConnection(u.Session))
				assert.Nil(t, wgC.UpdateConnection(u.Session))
			}(usr)
		}
		wgWait.Wait()

		for _, usr := range usrs {
			wgWait.Add(1)
			go func(u *tstuser.User) {
				defer wgWait.Done()
				assert.Nil(t, wgC.RemoveConnection(u.Session))
			}(usr)
		}
		wgWait.Wait()

		after, err := wgC.client.Device(devName)
		assert.Nil(t, err)

		assert.Equal(t, beforeKey, after.PrivateKey.String())
		assert.Equal(t, beforePort, after.ListenPort)

		for _, usr := range usrs {
			assert.Nil(t, findPeer(after, getSessionPubKey(t, usr.Session)))
		}
	})

	t.Run("closedController", func(t *testing.T) {
		usr := newConnectedUser()

		cancelRun()

		time.Sleep(500 * time.Millisecond)

		err := wgC.AddConnection(usr.Session)
		assert.NotNil(t, err)

		err = wgC.UpdateConnection(usr.Session)
		assert.NotNil(t, err)

		err = wgC.RemoveConnection(usr.Session)
		assert.NotNil(t, err)
	})
}
