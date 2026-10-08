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

package harness

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testNetwork() *corev1.ClusterConfig_Status_Network {
	return &corev1.ClusterConfig_Status_Network{
		WgConnSubnet:   &metav1.DualStackNetwork{V4: "100.65.0.0/16", V6: "fdee:0:0:0:1::/80"},
		QuicConnSubnet: &metav1.DualStackNetwork{V4: "100.66.0.0/16", V6: "fdee:0:0:0:2::/80"},
	}
}

func testKey(i int) []byte {
	ret := make([]byte, 32)
	ret[0] = byte(i)
	ret[1] = byte(i >> 8)
	ret[31] = 0x7
	return ret
}

func connectedSession(name string, typ corev1.Session_Status_Connection_Type,
	mode corev1.Session_Status_Connection_L3Mode, idx int) *corev1.Session {
	v4, v6 := "100.65", "fdee::1:0:0"
	if typ == corev1.Session_Status_Connection_QUICV0 {
		v4, v6 = "100.66", "fdee::2:0:0"
	}

	return &corev1.Session{
		Metadata: &metav1.Metadata{Name: name, Uid: name + "-uid"},
		Status: &corev1.Session_Status{
			Type:        corev1.Session_Status_CLIENT,
			IsConnected: true,
			Connection: &corev1.Session_Status_Connection{
				Type:            typ,
				L3Mode:          mode,
				X25519PublicKey: testKey(idx),
				Addresses: []*metav1.DualStackNetwork{{
					V4: fmt.Sprintf("%s.%d.%d/32", v4, idx>>8, idx&0xff),
					V6: fmt.Sprintf("%s:%x/128", v6, idx),
				}},
			},
		},
	}
}

func TestCheckConnAddresses(t *testing.T) {
	t.Run("a consistent Cluster", func(t *testing.T) {
		inv := &ConnInventory{
			Network: testNetwork(),
			Sessions: []*corev1.Session{
				connectedSession("a", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_BOTH, 0x101),
				connectedSession("b", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_V4, 0x203),
				connectedSession("c", corev1.Session_Status_Connection_QUICV0, corev1.Session_Status_Connection_V6, 0x101),
				{
					Metadata: &metav1.Metadata{Name: "idle"},
					Status:   &corev1.Session_Status{Type: corev1.Session_Status_CLIENT},
				},
			},
			ConnInfo: &cclusterv1.ClusterConnInfo{
				ActiveIndexesWG:   []uint32{0x101, 0x203},
				ActiveIndexesQUIC: []uint32{0x101},
			},
		}

		r := CheckConnAddresses(inv)
		require.NoError(t, r.Err())

		assert.Equal(t, 4, r.Sessions)
		assert.Equal(t, 3, r.Connected)
		assert.Equal(t, 2, r.WireGuard)
		assert.Equal(t, 1, r.QUIC)
		assert.Equal(t, 1, r.V4Only)
		assert.Equal(t, 1, r.V6Only)
		assert.Equal(t, 1, r.DualStack)
		assert.Contains(t, r.String(), "3 connected")
	})

	t.Run("leaks, unreserved and duplicated indexes", func(t *testing.T) {
		inv := &ConnInventory{
			Network: testNetwork(),
			Sessions: []*corev1.Session{
				connectedSession("a", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_BOTH, 0x101),
				connectedSession("b", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_BOTH, 0x102),
			},
			ConnInfo: &cclusterv1.ClusterConnInfo{
				ActiveIndexesWG:   []uint32{0x101, 0x101, 0x999},
				ActiveIndexesQUIC: []uint32{0x55},
			},
		}

		r := CheckConnAddresses(inv)
		assert.Equal(t, []uint32{0x999}, r.LeakedWG)
		assert.Equal(t, []uint32{0x55}, r.LeakedQUIC)
		assert.Equal(t, []uint32{0x102}, r.UnreservedWG)
		assert.Equal(t, []uint32{0x101}, r.DuplicateIdx)

		err := r.Err()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "leaked")
		assert.Contains(t, err.Error(), "not reserved")
	})

	t.Run("two connected Sessions sharing an address", func(t *testing.T) {
		a := connectedSession("a", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_BOTH, 0x101)
		b := connectedSession("b", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_BOTH, 0x101)

		r := CheckConnAddresses(&ConnInventory{
			Network:  testNetwork(),
			Sessions: []*corev1.Session{a, b},
			ConnInfo: &cclusterv1.ClusterConnInfo{ActiveIndexesWG: []uint32{0x101}},
		})

		require.Len(t, r.DuplicateAddrs, 2, "both the v4 and the v6 address are reported")
		assert.Contains(t, r.DuplicateAddrs[0], "a and b")
	})

	t.Run("addresses outside of the subnet and inconsistent Sessions", func(t *testing.T) {
		wrong := connectedSession("wrong", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_BOTH, 0x101)
		wrong.Status.Connection.Addresses[0].V4 = "100.66.1.1/32"

		zero := connectedSession("zero", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_BOTH, 0x200)

		flag := &corev1.Session{
			Metadata: &metav1.Metadata{Name: "flag"},
			Status:   &corev1.Session_Status{Type: corev1.Session_Status_CLIENT, IsConnected: true},
		}

		empty := connectedSession("empty", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_BOTH, 0x301)
		empty.Status.Connection.Addresses = nil

		r := CheckConnAddresses(&ConnInventory{
			Network:  testNetwork(),
			Sessions: []*corev1.Session{wrong, zero, flag, empty},
			ConnInfo: &cclusterv1.ClusterConnInfo{ActiveIndexesWG: []uint32{0x101, 0x200}},
		})

		require.Len(t, r.OutOfSubnet, 1)
		assert.Contains(t, r.OutOfSubnet[0], "100.66.1.1")
		require.Len(t, r.InvalidIndex, 2, "x.y.0.0 is a multiple of 256 for both families")
		assert.Len(t, r.Inconsistent, 2)
		assert.Error(t, r.Err())
	})
}

func TestNewLeaks(t *testing.T) {
	assert.Equal(t, []uint32{3, 4}, NewLeaks([]uint32{1, 2}, []uint32{1, 3, 4}))
	assert.Empty(t, NewLeaks([]uint32{1, 2}, []uint32{1}))
	assert.Empty(t, NewLeaks(nil, nil))
}

func wgDump(peers ...string) string {
	return strings.Join(append([]string{"cHJpdmF0ZQ== cHVibGlj 53820 off"}, peers...), "\n")
}

func TestParseWGDump(t *testing.T) {
	out := wgDump(
		"a2V5LWE= (none) 172.29.128.5:43210 100.65.1.1/32,fdee::1:0:101/128 1700000000 1024 2048 off",
		"a2V5LWI= (none) (none) (none) 0 0 0 off",
	)

	peers, err := ParseWGDump(out)
	require.NoError(t, err)
	require.Len(t, peers, 2)

	assert.Equal(t, "a2V5LWE=", peers[0].PublicKey)
	assert.Equal(t, "172.29.128.5:43210", peers[0].Endpoint)
	assert.Equal(t, []netip.Prefix{
		netip.MustParsePrefix("100.65.1.1/32"), netip.MustParsePrefix("fdee::1:0:101/128"),
	}, peers[0].AllowedIPs)
	assert.Equal(t, uint64(1024), peers[0].RxBytes)
	assert.Equal(t, uint64(2048), peers[0].TxBytes)
	assert.False(t, peers[0].LatestHandshake.IsZero())

	assert.Empty(t, peers[1].AllowedIPs)
	assert.True(t, peers[1].LatestHandshake.IsZero())

	peers, err = ParseWGDump(wgDump())
	require.NoError(t, err)
	assert.Empty(t, peers)

	for _, bad := range []string{
		"",
		"just-one-field",
		wgDump("too few fields"),
		wgDump("a2V5 (none) (none) not-a-prefix 0 0 0 off"),
	} {
		_, err := ParseWGDump(bad)
		assert.Error(t, err, bad)
	}
}

func TestCheckGatewayPeers(t *testing.T) {
	both := connectedSession("both", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_BOTH, 0x101)
	v4 := connectedSession("v4", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_V4, 0x102)
	v6 := connectedSession("v6", corev1.Session_Status_Connection_WIREGUARD, corev1.Session_Status_Connection_V6, 0x103)
	quic := connectedSession("quic", corev1.Session_Status_Connection_QUICV0, corev1.Session_Status_Connection_BOTH, 0x104)

	peerOf := func(sess *corev1.Session, allowed ...netip.Prefix) *WGPeer {
		return &WGPeer{
			PublicKey:  base64.StdEncoding.EncodeToString(sess.Status.Connection.X25519PublicKey),
			AllowedIPs: allowed,
		}
	}

	assert.Len(t, ExpectedAllowedIPs(both), 2)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("100.65.1.2/32")}, ExpectedAllowedIPs(v4))
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("fdee::1:0:0:103/128")}, ExpectedAllowedIPs(v6))

	t.Run("in sync", func(t *testing.T) {
		r := CheckGatewayPeers("gw", []*WGPeer{
			peerOf(both, netip.MustParsePrefix("fdee::1:0:0:101/128"), netip.MustParsePrefix("100.65.1.1/32")),
			peerOf(v4, ExpectedAllowedIPs(v4)...),
			peerOf(v6, ExpectedAllowedIPs(v6)...),
		}, []*corev1.Session{both, v4, v6, quic})

		require.NoError(t, r.Err())
		assert.Equal(t, 3, r.Expected, "QUICv0 Connections have no WireGuard peer")
	})

	t.Run("missing, stale and wrong peers", func(t *testing.T) {
		r := CheckGatewayPeers("gw", []*WGPeer{
			peerOf(both, netip.MustParsePrefix("100.65.1.1/32")),
			peerOf(v4, append(ExpectedAllowedIPs(v4), netip.MustParsePrefix("fdee::1:0:0:102/128"))...),
			{PublicKey: "c3RhbGU="},
		}, []*corev1.Session{both, v4, v6})

		assert.Equal(t, []string{"v6"}, r.Missing)
		assert.Equal(t, []string{"c3RhbGU="}, r.Stale)
		assert.Len(t, r.WrongIPs, 2, "a dual-stack peer without its v6 address and a v4-only peer with one")

		err := r.Err()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "has 3 WireGuard peers, want 3")
	})
}
