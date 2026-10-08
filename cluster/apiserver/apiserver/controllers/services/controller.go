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

	getDNSServers := func(hasV4, hasV6 bool) []string {
		dnsServers := []string{}

		for _, addr := range ucorev1.ToService(dnsSvc).Addresses() {
			if hasV4 && addr.DualStackIP.Ipv4 != "" {
				dnsServers = append(dnsServers, addr.DualStackIP.Ipv4)
			}

			if hasV6 && addr.DualStackIP.Ipv6 != "" {
				dnsServers = append(dnsServers, addr.DualStackIP.Ipv6)
			}
		}

		return dnsServers
	}

	if len(getDNSServers(true, true)) == 0 {
		zap.L().Warn("The DNS Service has no usable addresses. Not broadcasting the new DNS servers")
		return nil
	}

	return c.ctlI.BroadcastMessageByL3Mode(func(l3Mode corev1.Session_Status_Connection_L3Mode) *userv1.ConnectResponse {
		dnsServers := getDNSServers(
			l3Mode != corev1.Session_Status_Connection_V6,
			l3Mode != corev1.Session_Status_Connection_V4)
		if len(dnsServers) == 0 {
			zap.L().Debug("The DNS Service has no usable addresses for the L3 mode",
				zap.String("l3Mode", l3Mode.String()))
			return nil
		}

		zap.L().Debug("Sending new DNS servers",
			zap.String("l3Mode", l3Mode.String()), zap.Strings("servers", dnsServers))

		return &userv1.ConnectResponse{
			Event: &userv1.ConnectResponse_UpdateDNS_{
				UpdateDNS: &userv1.ConnectResponse_UpdateDNS{
					Dns: &userv1.DNS{
						Servers: dnsServers,
					},
				},
			},
		}
	})
}
