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

package membercontroller

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/gw"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/wg"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type tstQUICController struct {
	removed []*corev1.Session
	err     error
}

func (c *tstQUICController) RemoveConnection(sess *corev1.Session) error {
	c.removed = append(c.removed, sess)
	return c.err
}

func newTstSession() *corev1.Session {
	return &corev1.Session{
		Metadata: &metav1.Metadata{Name: "session", Uid: vutils.UUIDv4()},
		Spec:     &corev1.Session_Spec{},
		Status: &corev1.Session_Status{
			Type: corev1.Session_Status_CLIENT,
			Connection: &corev1.Session_Status_Connection{
				Type:      corev1.Session_Status_Connection_QUICV0,
				Addresses: []*metav1.DualStackNetwork{{V4: "100.66.0.10/32", V6: "fd00::10/128"}},
			},
		},
	}
}

func TestController(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		nilQUIC bool
		err     error
	}{
		{name: "enabled", enabled: true},
		{name: "disabled"},
		{name: "nilQUIC", enabled: true, nilQUIC: true},
		{name: "removeError", enabled: true, err: fmt.Errorf("remove failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			quicCtl := &tstQUICController{err: tc.err}
			opts := &Opts{WgC: &wg.Wg{}, HasQuicV0: tc.enabled, Quicv0Ctl: quicCtl}
			if tc.nilQUIC {
				opts.Quicv0Ctl = nil
			}
			ctl := NewController(opts)
			old := newTstSession()
			disconnected := pbutils.Clone(old).(*corev1.Session)
			disconnected.Status.Connection = nil
			assert.Nil(t, ctl.OnAdd(t.Context(), disconnected))
			assert.Nil(t, ctl.OnDelete(t.Context(), disconnected))
			assert.Nil(t, ctl.OnUpdate(t.Context(), disconnected, disconnected))
			assert.Nil(t, ctl.OnAdd(t.Context(), old))
			assert.Nil(t, ctl.OnUpdate(t.Context(), old, disconnected))
			assert.Nil(t, ctl.OnUpdate(t.Context(), old, old))
			changed := pbutils.Clone(old).(*corev1.Session)
			changed.Status.Connection.Addresses[0].V4 = "100.66.0.11/32"
			assert.Nil(t, ctl.OnUpdate(t.Context(), changed, old))
			changed.Status.Connection.X25519PublicKey = []byte{1}
			assert.Nil(t, ctl.OnUpdate(t.Context(), changed, old))
			assert.ErrorIs(t, ctl.OnUpdate(t.Context(), disconnected, old), tc.err)
			assert.ErrorIs(t, ctl.OnDelete(t.Context(), old), tc.err)
			if tc.enabled && !tc.nilQUIC {
				require.Len(t, quicCtl.removed, 2)
				assert.Same(t, old, quicCtl.removed[0])
				assert.Same(t, old, quicCtl.removed[1])
			} else {
				assert.Empty(t, quicCtl.removed)
			}
		})
	}

	t.Run("nonClient", func(t *testing.T) {
		ctl := NewController(&Opts{})
		sess := newTstSession()
		sess.Status.Type = corev1.Session_Status_CLIENTLESS
		assert.Nil(t, ctl.OnAdd(t.Context(), sess))
		assert.Nil(t, ctl.OnUpdate(t.Context(), sess, sess))
		assert.Nil(t, ctl.OnDelete(t.Context(), sess))
	})
}

func TestWireGuardController(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("The WireGuard device requires root")
	}
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	t.Setenv(vutils.MultusConfDirEnv, t.TempDir())
	node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "node-1", UID: "node-uid"}}
	key, err := wgtypes.GeneratePrivateKey()
	require.Nil(t, err)
	require.Nil(t, gw.InitGateway(t.Context(), []string{"1.2.3.4"}, node, tst.C.OcteliumC, 0,
		&metav1.ObjectReference{Name: "default", Uid: vutils.UUIDv4()}, key))
	wgCtl, err := wg.New(t.Context(), node, tst.C.OcteliumC, key)
	require.Nil(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	require.Nil(t, wgCtl.Run(ctx))
	t.Cleanup(func() {
		cancel()
		wgCtl.Cleanup()
	})
	client, err := wgctrl.New()
	require.Nil(t, err)
	defer client.Close()
	deviceName := "octelium-wg"
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.Nil(t, err)
	sess := newTstSession()
	sess.Status.Connection.Type = corev1.Session_Status_Connection_WIREGUARD
	publicKey := peerKey.PublicKey()
	sess.Status.Connection.X25519PublicKey = publicKey[:]
	disconnected := pbutils.Clone(sess).(*corev1.Session)
	disconnected.Status.Connection = nil
	ctl := NewController(&Opts{WgC: wgCtl})
	assertPeers := func(expected []string) {
		t.Helper()
		dev, err := client.Device(deviceName)
		require.Nil(t, err)
		if expected == nil {
			assert.Empty(t, dev.Peers)
			return
		}
		require.Len(t, dev.Peers, 1)
		var addrs []string
		for _, addr := range dev.Peers[0].AllowedIPs {
			addrs = append(addrs, addr.String())
		}
		assert.ElementsMatch(t, expected, addrs)
	}
	require.Nil(t, ctl.OnAdd(t.Context(), sess))
	assertPeers([]string{"100.66.0.10/32", "fd00::10/128"})
	updated := pbutils.Clone(sess).(*corev1.Session)
	updated.Status.Connection.Addresses[0].V4 = "100.66.0.11/32"
	require.Nil(t, ctl.OnUpdate(t.Context(), updated, sess))
	assertPeers([]string{"100.66.0.11/32", "fd00::10/128"})
	require.Nil(t, ctl.OnUpdate(t.Context(), disconnected, updated))
	assertPeers(nil)
	require.Nil(t, ctl.OnUpdate(t.Context(), sess, disconnected))
	assertPeers([]string{"100.66.0.10/32", "fd00::10/128"})
	require.Nil(t, ctl.OnDelete(t.Context(), sess))
	assertPeers(nil)
	invalid := pbutils.Clone(sess).(*corev1.Session)
	invalid.Status.Connection.X25519PublicKey = []byte{1}
	assert.NotNil(t, ctl.OnAdd(t.Context(), invalid))
	assert.NotNil(t, ctl.OnUpdate(t.Context(), invalid, disconnected))
	assert.NotNil(t, ctl.OnUpdate(t.Context(), invalid, sess))
	assert.NotNil(t, ctl.OnUpdate(t.Context(), disconnected, invalid))
	assert.NotNil(t, ctl.OnDelete(t.Context(), invalid))
}

func newTstWireGuardController(t *testing.T) (*Controller, *wgctrl.Client, *tests.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("The WireGuard device requires root")
	}
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	t.Setenv(vutils.MultusConfDirEnv, t.TempDir())
	node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "node-reconnect", UID: "node-reconnect"}}
	key, err := wgtypes.GeneratePrivateKey()
	require.Nil(t, err)
	require.Nil(t, gw.InitGateway(t.Context(), []string{"1.2.3.4"}, node, tst.C.OcteliumC, 0,
		&metav1.ObjectReference{Name: "default", Uid: vutils.UUIDv4()}, key))
	wgCtl, err := wg.New(t.Context(), node, tst.C.OcteliumC, key)
	require.Nil(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	require.Nil(t, wgCtl.Run(ctx))
	t.Cleanup(func() {
		cancel()
		wgCtl.Cleanup()
	})
	client, err := wgctrl.New()
	require.Nil(t, err)
	t.Cleanup(func() { client.Close() })
	return NewController(&Opts{WgC: wgCtl, HasQuicV0: true, Quicv0Ctl: &tstQUICController{}}), client, tst
}

type tstSessionWatchClient struct {
	octeliumc.ClientInterface
	core *tstSessionWatchCoreClient
}

func (c *tstSessionWatchClient) CoreC() rcorev1.ResourceServiceClient {
	return c.core
}

type tstSessionWatchCoreClient struct {
	rcorev1.ResourceServiceClient
	mu       sync.Mutex
	resumeCh chan struct{}
	cancelFn context.CancelFunc
}

func (c *tstSessionWatchCoreClient) WatchSession(ctx context.Context, opts *rmetav1.WatchOptions,
	callOpts ...grpc.CallOption) (grpc.ServerStreamingClient[rmetav1.WatchEvent], error) {
	c.mu.Lock()
	resumeCh := c.resumeCh
	c.mu.Unlock()
	if resumeCh != nil {
		select {
		case <-resumeCh:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	streamCtx, cancel := context.WithCancel(ctx)
	stream, err := c.ResourceServiceClient.WatchSession(streamCtx, opts, callOpts...)
	if err != nil {
		cancel()
		return nil, err
	}
	c.mu.Lock()
	c.cancelFn = cancel
	c.mu.Unlock()
	return stream, nil
}

func (c *tstSessionWatchCoreClient) pause() {
	c.mu.Lock()
	c.resumeCh = make(chan struct{})
	cancel := c.cancelFn
	c.mu.Unlock()
	cancel()
}

func (c *tstSessionWatchCoreClient) resume() {
	c.mu.Lock()
	resumeCh := c.resumeCh
	c.resumeCh = nil
	c.mu.Unlock()
	if resumeCh != nil {
		close(resumeCh)
	}
}

func TestSessionWatchReconnect(t *testing.T) {
	ctl, deviceClient, tst := newTstWireGuardController(t)
	client := tst.C.OcteliumC
	adminSrv := admin.NewServer(&admin.Opts{OcteliumC: client, IsEmbedded: true})
	usrSrv := user.NewServer(client)

	for _, tc := range []struct {
		name string
		old  userv1.ConnectRequest_Initialize_ConnectionType
		new  userv1.ConnectRequest_Initialize_ConnectionType
	}{
		{name: "WireGuardToWireGuard", old: userv1.ConnectRequest_Initialize_WIREGUARD, new: userv1.ConnectRequest_Initialize_WIREGUARD},
		{name: "WireGuardToQUIC", old: userv1.ConnectRequest_Initialize_WIREGUARD, new: userv1.ConnectRequest_Initialize_QUICV0},
		{name: "QUICToWireGuard", old: userv1.ConnectRequest_Initialize_QUICV0, new: userv1.ConnectRequest_Initialize_WIREGUARD},
	} {
		t.Run(tc.name, func(t *testing.T) {
			usr, err := tstuser.NewUser(client, adminSrv, usrSrv, nil)
			require.Nil(t, err)
			_, err = usrSrv.DoInitConnect(usr.Ctx(), &userv1.ConnectRequest_Initialize{ConnectionType: tc.old})
			require.Nil(t, err)
			usr.Resync()
			old := pbutils.Clone(usr.Session).(*corev1.Session)
			sessionUID := old.Metadata.Uid
			core := &tstSessionWatchCoreClient{ResourceServiceClient: client.CoreC()}
			watchClient := &tstSessionWatchClient{ClientInterface: client, core: core}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			type event struct {
				new *corev1.Session
				old *corev1.Session
				err error
			}
			events := make(chan event, 16)
			err = watchers.NewCoreV1(watchClient).Session(ctx, nil,
				func(ctx context.Context, sess *corev1.Session) error {
					if sess.Metadata.Uid != sessionUID {
						return nil
					}
					err := ctl.OnAdd(ctx, sess)
					events <- event{new: sess, err: err}
					return err
				},
				func(ctx context.Context, new, old *corev1.Session) error {
					if new.Metadata.Uid != sessionUID {
						return nil
					}
					err := ctl.OnUpdate(ctx, new, old)
					events <- event{new: new, old: old, err: err}
					return err
				}, ctl.OnDelete)
			require.Nil(t, err)
			waitEvent := func() event {
				t.Helper()
				select {
				case ev := <-events:
					require.Nil(t, ev.err)
					return ev
				case <-time.After(10 * time.Second):
					t.Fatal("The Session watch event was not handled")
					return event{}
				}
			}
			initial := waitEvent()
			assert.Nil(t, initial.old)
			assert.True(t, pbutils.IsEqual(old.Status.Connection, initial.new.Status.Connection))
			core.pause()
			defer core.resume()
			require.Nil(t, usr.Disconnect())
			assert.Nil(t, usr.Session.Status.Connection)
			_, err = usrSrv.DoInitConnect(usr.Ctx(), &userv1.ConnectRequest_Initialize{ConnectionType: tc.new})
			require.Nil(t, err)
			usr.Resync()
			current := pbutils.Clone(usr.Session).(*corev1.Session)
			assert.Equal(t, old.Metadata.Uid, current.Metadata.Uid)
			assert.NotEqual(t, old.Status.Connection.X25519PublicKey, current.Status.Connection.X25519PublicKey)
			core.resume()
			snapshot := waitEvent()
			require.NotNil(t, snapshot.old)
			assert.True(t, pbutils.IsEqual(old.Status.Connection, snapshot.old.Status.Connection))
			assert.True(t, pbutils.IsEqual(current.Status.Connection, snapshot.new.Status.Connection))
			device, err := deviceClient.Device("octelium-wg")
			require.Nil(t, err)
			if tc.new == userv1.ConnectRequest_Initialize_WIREGUARD {
				require.Len(t, device.Peers, 1)
				key, err := wgtypes.NewKey(current.Status.Connection.X25519PublicKey)
				require.Nil(t, err)
				assert.Equal(t, key, device.Peers[0].PublicKey)
			} else {
				assert.Empty(t, device.Peers)
			}
			require.Nil(t, usr.Disconnect())
			disconnected := waitEvent()
			assert.Nil(t, disconnected.new.Status.Connection)
			assert.Nil(t, ctl.OnDelete(t.Context(), old))
		})
	}
}

func TestConnectionReplacement(t *testing.T) {
	ctl, client, _ := newTstWireGuardController(t)
	for _, tc := range []struct {
		name        string
		oldType     corev1.Session_Status_Connection_Type
		newType     corev1.Session_Status_Connection_Type
		sameKey     bool
		changedAddr bool
		timestamps  bool
	}{
		{name: "WireGuardWithoutTimestamps", oldType: corev1.Session_Status_Connection_WIREGUARD, newType: corev1.Session_Status_Connection_WIREGUARD},
		{name: "WireGuardWithTimestamps", oldType: corev1.Session_Status_Connection_WIREGUARD, newType: corev1.Session_Status_Connection_WIREGUARD, timestamps: true},
		{name: "WireGuardNewAddresses", oldType: corev1.Session_Status_Connection_WIREGUARD, newType: corev1.Session_Status_Connection_WIREGUARD, changedAddr: true},
		{name: "WireGuardToQUIC", oldType: corev1.Session_Status_Connection_WIREGUARD, newType: corev1.Session_Status_Connection_QUICV0},
		{name: "QUICToWireGuard", oldType: corev1.Session_Status_Connection_QUICV0, newType: corev1.Session_Status_Connection_WIREGUARD},
		{name: "sameConnection", oldType: corev1.Session_Status_Connection_WIREGUARD, newType: corev1.Session_Status_Connection_WIREGUARD, sameKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := newTstSession()
			old.Status.Connection.Type = tc.oldType
			key, err := wgtypes.GeneratePrivateKey()
			require.Nil(t, err)
			oldKey := key.PublicKey()
			old.Status.Connection.X25519PublicKey = oldKey[:]
			current := pbutils.Clone(old).(*corev1.Session)
			current.Status.Connection.Type = tc.newType
			current.Metadata.DisplayName = "current"
			currentKey := oldKey
			if !tc.sameKey {
				key, err := wgtypes.GeneratePrivateKey()
				require.Nil(t, err)
				currentKey = key.PublicKey()
				current.Status.Connection.X25519PublicKey = currentKey[:]
			}
			if tc.timestamps {
				old.Status.Connection.StartedAt = pbutils.Timestamp(time.Now().Add(-time.Minute))
				current.Status.Connection.StartedAt = pbutils.Now()
			}
			if tc.changedAddr {
				current.Status.Connection.Addresses = []*metav1.DualStackNetwork{{V4: "100.66.0.11/32", V6: "fd00::11/128"}}
			}
			other := newTstSession()
			other.Status.Connection.Type = corev1.Session_Status_Connection_WIREGUARD
			other.Status.Connection.Addresses = []*metav1.DualStackNetwork{{V4: "100.66.0.77/32", V6: "fd00::77/128"}}
			otherKey, err := wgtypes.GeneratePrivateKey()
			require.Nil(t, err)
			otherPublicKey := otherKey.PublicKey()
			other.Status.Connection.X25519PublicKey = otherPublicKey[:]
			require.Nil(t, ctl.OnAdd(t.Context(), other))
			require.Nil(t, ctl.OnAdd(t.Context(), old))
			if tc.sameKey {
				require.Nil(t, client.ConfigureDevice("octelium-wg", wgtypes.Config{
					Peers: []wgtypes.PeerConfig{{
						PublicKey: oldKey,
						Endpoint:  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
					}},
				}))
			}
			before, err := client.Device("octelium-wg")
			require.Nil(t, err)
			require.Nil(t, ctl.OnUpdate(t.Context(), current, old))
			require.Nil(t, ctl.OnUpdate(t.Context(), current, old))
			after, err := client.Device("octelium-wg")
			require.Nil(t, err)
			assert.Equal(t, before.PrivateKey, after.PrivateKey)
			assert.Equal(t, before.ListenPort, after.ListenPort)
			peers := make(map[wgtypes.Key][]string)
			for _, peer := range after.Peers {
				if tc.sameKey && peer.PublicKey == oldKey {
					assert.Equal(t, &net.UDPAddr{IP: net.ParseIP("127.0.0.1").To4(), Port: 12345}, peer.Endpoint)
				}
				for _, addr := range peer.AllowedIPs {
					peers[peer.PublicKey] = append(peers[peer.PublicKey], addr.String())
				}
			}
			assert.ElementsMatch(t, []string{"100.66.0.77/32", "fd00::77/128"}, peers[otherPublicKey])
			if tc.newType == corev1.Session_Status_Connection_WIREGUARD {
				assert.Len(t, peers, 2)
				assert.ElementsMatch(t, []string{current.Status.Connection.Addresses[0].V4, current.Status.Connection.Addresses[0].V6}, peers[currentKey])
			} else {
				assert.Len(t, peers, 1)
			}
			if !tc.sameKey {
				assert.NotContains(t, peers, oldKey)
			}
			require.Nil(t, ctl.OnDelete(t.Context(), current))
			require.Nil(t, ctl.OnDelete(t.Context(), old))
			require.Nil(t, ctl.OnDelete(t.Context(), other))
		})
	}
}

func TestConnectionReplacementErrors(t *testing.T) {
	ctl, client, _ := newTstWireGuardController(t)
	for _, name := range []string{"removeWireGuard", "removeQUIC", "addWireGuard"} {
		t.Run(name, func(t *testing.T) {
			old := newTstSession()
			old.Status.Connection.Type = corev1.Session_Status_Connection_WIREGUARD
			key, err := wgtypes.GeneratePrivateKey()
			require.Nil(t, err)
			oldKey := key.PublicKey()
			old.Status.Connection.X25519PublicKey = oldKey[:]
			current := pbutils.Clone(old).(*corev1.Session)
			key, err = wgtypes.GeneratePrivateKey()
			require.Nil(t, err)
			currentKey := key.PublicKey()
			current.Status.Connection.X25519PublicKey = currentKey[:]
			quicCtl := ctl.quicv0Ctl.(*tstQUICController)
			switch name {
			case "removeWireGuard":
				old.Status.Connection.X25519PublicKey = []byte{1}
			case "removeQUIC":
				old.Status.Connection.Type = corev1.Session_Status_Connection_QUICV0
				quicCtl.err = fmt.Errorf("remove failed")
			case "addWireGuard":
				require.Nil(t, ctl.OnAdd(t.Context(), old))
				current.Status.Connection.X25519PublicKey = []byte{1}
			}
			assert.NotNil(t, ctl.OnUpdate(t.Context(), current, old))
			device, err := client.Device("octelium-wg")
			require.Nil(t, err)
			assert.Empty(t, device.Peers)
			quicCtl.err = nil
			old.Status.Connection.X25519PublicKey = oldKey[:]
			current.Status.Connection.X25519PublicKey = currentKey[:]
			require.Nil(t, ctl.OnUpdate(t.Context(), current, old))
			device, err = client.Device("octelium-wg")
			require.Nil(t, err)
			require.Len(t, device.Peers, 1)
			assert.Equal(t, currentKey, device.Peers[0].PublicKey)
			require.Nil(t, ctl.OnDelete(t.Context(), current))
		})
	}
}
