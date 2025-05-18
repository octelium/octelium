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

package utilnet

import (
	"net"

	k8snet "k8s.io/utils/net"
)

func IsIPv6(ip net.IP) bool {
	return k8snet.IsIPv6(ip)
}

func IsNetIPv6(ipNetStr string) (bool, error) {
	mip, _, err := net.ParseCIDR(ipNetStr)
	if err != nil {
		return false, err
	}
	return k8snet.IsIPv6(mip), nil
}

func ContainsCIDR(ipnet1, ipnet2 *net.IPNet) bool {
	ones1, _ := ipnet1.Mask.Size()
	ones2, _ := ipnet2.Mask.Size()
	return ones1 <= ones2 && ipnet1.Contains(ipnet2.IP)
}
