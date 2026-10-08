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

package suite

import (
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChaosScales(t *testing.T) {
	t.Setenv(harness.ChaosClientsEnv, "")

	var prev chaosScale
	for i, name := range harness.ChaosScales {
		s, err := chaosScaleFor(name)
		require.NoError(t, err, name)

		assert.Equal(t, name, s.Name)
		assert.Positive(t, s.Users)
		assert.Positive(t, s.ConnectWorkers)
		assert.Positive(t, s.StreamsPerConn)
		assert.Positive(t, s.TakeoverRacers)
		assert.Positive(t, s.Hold)
		assert.LessOrEqual(t, (s.Clients+s.spare())/s.Users, 5000,
			"%s: the Sessions per User stay well below the per-User limit", name)

		if i > 0 {
			assert.Greater(t, s.Clients, prev.Clients, "%s must be heavier than %s", name, prev.Name)
		}
		prev = s
	}

	_, err := chaosScaleFor("huge")
	require.Error(t, err)

	_, ok := chaosScales[harness.ChaosScaleDefault]
	assert.True(t, ok, "the default scale must exist")
}

func TestChaosClientsOverride(t *testing.T) {
	t.Setenv(harness.ChaosClientsEnv, "20000")

	s, err := chaosScaleFor("small")
	require.NoError(t, err)

	assert.Equal(t, 20000, s.Clients)
	assert.Equal(t, "small-20000", s.Name)
	assert.Equal(t, 40, s.Users, "the Users grow with the clients to stay below the per-User limit")
	assert.Equal(t, 4000, s.LongLived)

	for _, bad := range []string{"5", "x", "100000"} {
		t.Setenv(harness.ChaosClientsEnv, bad)
		_, err := chaosScaleFor("small")
		assert.Error(t, err, bad)
	}
}

func TestChaosClientOptsCoverEveryCombination(t *testing.T) {
	e := &chaosEnv{ipv6: true, quic: true, scale: chaosScale{KeepAlive: time.Minute}}

	type combo struct {
		tunnel userv1.ConnectRequest_Initialize_ConnectionType
		mode   userv1.ConnectRequest_Initialize_L3Mode
	}

	seen := map[combo]int{}
	for i := range 90 {
		o := e.clientOpts(i)
		assert.Equal(t, time.Minute, o.KeepAlive)
		seen[combo{o.Tunnel, o.L3Mode}]++
	}

	assert.Len(t, seen, 6, "every tunnel must be paired with every IP mode")
	for c, n := range seen {
		if c.tunnel == userv1.ConnectRequest_Initialize_QUICV0 {
			assert.Equal(t, 10, n)
		} else {
			assert.Equal(t, 20, n)
		}
	}

	single := &chaosEnv{}
	for i := range 10 {
		o := single.clientOpts(i)
		assert.Equal(t, userv1.ConnectRequest_Initialize_WIREGUARD, o.Tunnel)
		assert.Equal(t, userv1.ConnectRequest_Initialize_V4, o.L3Mode,
			"a Cluster without IPv6 only accepts IPv4-only Connections")
	}
}

func TestPickSamples(t *testing.T) {
	e := &chaosEnv{ipv6: true, quic: true}

	var population []*harness.VClient
	for i := range 60 {
		population = append(population, harness.NewVClient(&harness.FleetSession{}, nil, e.clientOpts(i)))
	}

	picked := e.pickSamples(population, 12)
	require.Len(t, picked, 12)

	combos := map[string]int{}
	for _, c := range picked {
		combos[c.Opts().Tunnel.String()+"/"+c.Opts().L3Mode.String()]++
	}
	assert.Len(t, combos, 6, "the samples must cover every combination first")
	for _, n := range combos {
		assert.Equal(t, 2, n)
	}

	assert.Len(t, e.pickSamples(population[:3], 12), 3)
}

func TestDNSMatchesMode(t *testing.T) {
	both := []string{"100.64.0.10", "fdee::10"}
	v4 := []string{"100.64.0.10"}
	v6 := []string{"fdee::10"}

	assert.True(t, dnsMatchesMode(both, corev1.Session_Status_Connection_BOTH))
	assert.True(t, dnsMatchesMode(v4, corev1.Session_Status_Connection_V4))
	assert.True(t, dnsMatchesMode(v6, corev1.Session_Status_Connection_V6))

	assert.False(t, dnsMatchesMode(both, corev1.Session_Status_Connection_V4))
	assert.False(t, dnsMatchesMode(both, corev1.Session_Status_Connection_V6))
	assert.False(t, dnsMatchesMode(nil, corev1.Session_Status_Connection_BOTH))
	assert.False(t, dnsMatchesMode(v6, corev1.Session_Status_Connection_V4))
}

func TestModeMapping(t *testing.T) {
	assert.Equal(t, corev1.Session_Status_Connection_V4, wantL3Mode(userv1.ConnectRequest_Initialize_V4))
	assert.Equal(t, corev1.Session_Status_Connection_V6, wantL3Mode(userv1.ConnectRequest_Initialize_V6))
	assert.Equal(t, corev1.Session_Status_Connection_BOTH, wantL3Mode(userv1.ConnectRequest_Initialize_BOTH))

	assert.Equal(t, corev1.Session_Status_Connection_V6, stateL3Mode(userv1.ConnectionState_V6))
	assert.Equal(t, corev1.Session_Status_Connection_QUICV0, wantTunnel(userv1.ConnectRequest_Initialize_QUICV0))
	assert.Equal(t, corev1.Session_Status_Connection_WIREGUARD, wantTunnel(userv1.ConnectRequest_Initialize_UNSET))

	assert.Equal(t, []bool{false, true}, modeFamilies(userv1.ConnectRequest_Initialize_BOTH))
	assert.Equal(t, []bool{true}, modeFamilies(userv1.ConnectRequest_Initialize_V6))
}
