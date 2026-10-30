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

package logentry

import (
	"net"

	"github.com/octelium/octelium/apis/main/corev1"
)

func GetEndpoint(addr net.Addr) *corev1.AccessLog_Entry_Common_Network_Endpoint {
	var ip net.IP
	var port int

	switch addr := addr.(type) {
	case *net.TCPAddr:
		if addr == nil {
			return nil
		}
		ip, port = addr.IP, addr.Port
	case *net.UDPAddr:
		if addr == nil {
			return nil
		}
		ip, port = addr.IP, addr.Port
	default:
		return nil
	}

	if ip.To16() == nil || port < 0 || port > 65535 {
		return nil
	}

	return &corev1.AccessLog_Entry_Common_Network_Endpoint{
		Ip:   ip.String(),
		Port: uint32(port),
	}
}

func GetNetwork(downstream net.Addr) *corev1.AccessLog_Entry_Common_Network {
	endpoint := GetEndpoint(downstream)
	if endpoint == nil {
		return nil
	}

	return &corev1.AccessLog_Entry_Common_Network{
		Downstream: endpoint,
	}
}

func WithUpstream(network *corev1.AccessLog_Entry_Common_Network, conn net.Conn) *corev1.AccessLog_Entry_Common_Network {
	if conn == nil {
		return network
	}

	local := GetEndpoint(conn.LocalAddr())
	remote := GetEndpoint(conn.RemoteAddr())
	if local == nil && remote == nil {
		return network
	}

	return &corev1.AccessLog_Entry_Common_Network{
		Downstream:        network.GetDownstream(),
		UpstreamLocal:     local,
		UpstreamRemote:    remote,
		ForwardedClientIP: network.GetForwardedClientIP(),
	}
}
