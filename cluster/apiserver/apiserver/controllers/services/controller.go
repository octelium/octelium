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
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"go.uber.org/zap"
)

func (c *Controller) setDNSState(dnsSvc *corev1.Service) error {

	zap.L().Debug("Sending new DNS servers")
	dnsServers := []string{}
	if len(dnsSvc.Status.Addresses) == 0 {
		return nil
	}

	for _, addr := range dnsSvc.Status.Addresses {
		if addr.DualStackIP.Ipv4 != "" {
			dnsServers = append(dnsServers, addr.DualStackIP.Ipv4)
		}

		if addr.DualStackIP.Ipv6 != "" {
			dnsServers = append(dnsServers, addr.DualStackIP.Ipv6)
		}
	}

	return c.ctlI.BroadcastMessage(&userv1.ConnectResponse{
		Event: &userv1.ConnectResponse_UpdateDNS_{
			UpdateDNS: &userv1.ConnectResponse_UpdateDNS{
				Dns: &userv1.DNS{
					Servers: dnsServers,
				},
			},
		},
	})
}
