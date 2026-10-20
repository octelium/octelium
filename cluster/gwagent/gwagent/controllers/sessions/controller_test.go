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
	"os"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/gw"
	"github.com/octelium/octelium/cluster/gwagent/gwagent/wg"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
