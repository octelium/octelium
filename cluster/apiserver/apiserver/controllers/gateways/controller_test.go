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

package memcontroller

import (
	"fmt"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type tstBroadcast struct {
	messages []*userv1.ConnectResponse
	err      error
}

func (c *tstBroadcast) BroadcastMessage(msg *userv1.ConnectResponse) error {
	c.messages = append(c.messages, msg)
	return c.err
}

func TestGatewayEvents(t *testing.T) {
	gw := &corev1.Gateway{
		Metadata: &metav1.Metadata{Name: "gateway", CreatedAt: timestamppb.Now()},
		Status: &corev1.Gateway_Status{
			Id: "gateway-id", Hostname: "gateway.example.com", PublicIPs: []string{"192.0.2.1", "2001:db8::1"},
			Cidr:      &metav1.DualStackNetwork{V4: "10.0.0.0/24", V6: "fd00::/64"},
			Wireguard: &corev1.Gateway_Status_WireGuard{Port: 51820, PublicKey: "key"},
		},
	}
	b := &tstBroadcast{}
	c := NewController(nil, b)
	require.Nil(t, c.OnAdd(t.Context(), gw))
	require.Len(t, b.messages, 1)
	got := b.messages[0].GetAddGateway().GetGateway()
	assert.Equal(t, gw.Status.Id, got.Id)
	assert.Equal(t, gw.Status.PublicIPs, got.Addresses)
	assert.Equal(t, []string{"10.0.0.0/24", "fd00::/64"}, got.CIDRs)
	assert.Equal(t, int32(51820), got.Wireguard.Port)
	assert.Nil(t, got.Quicv0)
	old := proto.Clone(gw).(*corev1.Gateway)
	old.Metadata.CreatedAt = timestamppb.New(time.Now().Add(-2 * time.Minute))
	require.Nil(t, c.OnAdd(t.Context(), old))
	require.Len(t, b.messages, 1)
	newGW := proto.Clone(gw).(*corev1.Gateway)
	newGW.Metadata.Description = "metadata-only change"
	require.Nil(t, c.OnUpdate(t.Context(), newGW, gw))
	require.Len(t, b.messages, 1)
	newGW.Status.PublicIPs = []string{"192.0.2.2"}
	newGW.Status.Quicv0 = &corev1.Gateway_Status_QUICV0{Port: 4443}
	require.Nil(t, c.OnUpdate(t.Context(), newGW, gw))
	require.Len(t, b.messages, 2)
	assert.Equal(t, []string{"192.0.2.2"}, b.messages[1].GetUpdateGateway().GetGateway().Addresses)
	assert.Equal(t, int32(4443), b.messages[1].GetUpdateGateway().GetGateway().Quicv0.Port)
	require.Nil(t, c.OnDelete(t.Context(), gw))
	require.Len(t, b.messages, 3)
	assert.Equal(t, "gateway-id", b.messages[2].GetDeleteGateway().Id)
	b.err = fmt.Errorf("broadcast failed")
	assert.ErrorIs(t, c.OnAdd(t.Context(), gw), b.err)
	assert.ErrorIs(t, c.OnUpdate(t.Context(), newGW, gw), b.err)
	assert.ErrorIs(t, c.OnDelete(t.Context(), gw), b.err)
}
