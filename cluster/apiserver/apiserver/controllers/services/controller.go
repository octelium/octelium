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
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"go.uber.org/zap"
)

func (c *Controller) setDNSState(dnsSvc *corev1.Service) error {

	dnsServers := []string{}

	for _, addr := range ucorev1.ToService(dnsSvc).Addresses() {
		if addr.DualStackIP.Ipv4 != "" {
			dnsServers = append(dnsServers, addr.DualStackIP.Ipv4)
		}

		if addr.DualStackIP.Ipv6 != "" {
			dnsServers = append(dnsServers, addr.DualStackIP.Ipv6)
		}
	}

	if len(dnsServers) == 0 {
		zap.L().Warn("The DNS Service has no usable addresses. Not broadcasting the new DNS servers")
		return nil
	}

	zap.L().Debug("Sending new DNS servers", zap.Strings("servers", dnsServers))

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
