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

package svccontroller

import (
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
)

type fakeCtl struct {
	broadcasted []map[corev1.Session_Status_Connection_L3Mode]*userv1.ConnectResponse
}

func (c *fakeCtl) BroadcastMessage(msg *userv1.ConnectResponse) error {
	c.broadcasted = append(c.broadcasted, map[corev1.Session_Status_Connection_L3Mode]*userv1.ConnectResponse{
		corev1.Session_Status_Connection_BOTH: msg,
		corev1.Session_Status_Connection_V4:   msg,
		corev1.Session_Status_Connection_V6:   msg,
	})
	return nil
}

func (c *fakeCtl) BroadcastMessageByL3Mode(
	fn func(l3Mode corev1.Session_Status_Connection_L3Mode) *userv1.ConnectResponse) error {
	c.broadcasted = append(c.broadcasted, map[corev1.Session_Status_Connection_L3Mode]*userv1.ConnectResponse{
		corev1.Session_Status_Connection_BOTH: fn(corev1.Session_Status_Connection_BOTH),
		corev1.Session_Status_Connection_V4:   fn(corev1.Session_Status_Connection_V4),
		corev1.Session_Status_Connection_V6:   fn(corev1.Session_Status_Connection_V6),
	})
	return nil
}

func (c *fakeCtl) SendMessage(msg *userv1.ConnectResponse, sessUID string) error {
	return nil
}

func TestSetDNSState(t *testing.T) {

	newSvc := func(addrs []*corev1.Service_Status_Address) *corev1.Service {
		return &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "dns.octelium",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				PrimaryHostname: "dns",
				Addresses:       addrs,
			},
		}
	}

	{
		ctlI := &fakeCtl{}
		c := NewController(nil, ctlI)

		assert.Nil(t, c.setDNSState(newSvc(nil)))
		assert.Equal(t, 0, len(ctlI.broadcasted))
	}

	{
		ctlI := &fakeCtl{}
		c := NewController(nil, ctlI)

		assert.Nil(t, c.setDNSState(newSvc([]*corev1.Service_Status_Address{
			nil,
			{},
			{
				DualStackIP: &metav1.DualStackIP{},
			},
		})))
		assert.Equal(t, 0, len(ctlI.broadcasted))
	}

	{
		ctlI := &fakeCtl{}
		c := NewController(nil, ctlI)

		assert.Nil(t, c.setDNSState(newSvc([]*corev1.Service_Status_Address{
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv4: "1.2.3.4",
					Ipv6: "::1",
				},
			},
			{
				DualStackIP: nil,
			},
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv4: "1.2.3.5",
				},
			},
		})))

		assert.Equal(t, 1, len(ctlI.broadcasted))
		assert.Equal(t, []string{"1.2.3.4", "::1", "1.2.3.5"},
			ctlI.broadcasted[0][corev1.Session_Status_Connection_BOTH].GetUpdateDNS().GetDns().GetServers())
		assert.Equal(t, []string{"1.2.3.4", "1.2.3.5"},
			ctlI.broadcasted[0][corev1.Session_Status_Connection_V4].GetUpdateDNS().GetDns().GetServers())
		assert.Equal(t, []string{"::1"},
			ctlI.broadcasted[0][corev1.Session_Status_Connection_V6].GetUpdateDNS().GetDns().GetServers())
	}

	{
		ctlI := &fakeCtl{}
		c := NewController(nil, ctlI)

		assert.Nil(t, c.setDNSState(newSvc([]*corev1.Service_Status_Address{
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv4: "1.2.3.4",
				},
			},
		})))

		assert.Equal(t, 1, len(ctlI.broadcasted))
		assert.Equal(t, []string{"1.2.3.4"},
			ctlI.broadcasted[0][corev1.Session_Status_Connection_BOTH].GetUpdateDNS().GetDns().GetServers())
		assert.Equal(t, []string{"1.2.3.4"},
			ctlI.broadcasted[0][corev1.Session_Status_Connection_V4].GetUpdateDNS().GetDns().GetServers())
		assert.Nil(t, ctlI.broadcasted[0][corev1.Session_Status_Connection_V6],
			"a v6-only Connection must keep its DNS servers instead of getting unreachable ones")
	}
}

func TestOnUpdate(t *testing.T) {

	ctlI := &fakeCtl{}
	c := NewController(nil, ctlI)

	newSvc := func(addrs []*corev1.Service_Status_Address) *corev1.Service {
		return &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "dns.octelium",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				PrimaryHostname: "dns",
				Addresses:       addrs,
			},
		}
	}

	addrs := []*corev1.Service_Status_Address{
		{
			DualStackIP: &metav1.DualStackIP{
				Ipv4: "1.2.3.4",
			},
		},
	}

	{
		assert.Nil(t, c.OnUpdate(t.Context(), newSvc(addrs), newSvc(nil)))
		assert.Equal(t, 1, len(ctlI.broadcasted))
	}

	{
		assert.Nil(t, c.OnUpdate(t.Context(), newSvc(nil), newSvc(addrs)))
		assert.Equal(t, 1, len(ctlI.broadcasted))
	}

	{
		assert.Nil(t, c.OnUpdate(t.Context(), newSvc(addrs), newSvc(addrs)))
		assert.Equal(t, 1, len(ctlI.broadcasted))
	}
}
