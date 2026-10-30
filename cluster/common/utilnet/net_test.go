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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		address string
		v6      bool
	}{
		{"127.0.0.1", false}, {"::ffff:127.0.0.1", false},
		{"::1", true}, {"fd00::1", true}, {"invalid", false},
	} {
		assert.Equal(t, tc.v6, IsIPv6(net.ParseIP(tc.address)))
	}
	for _, tc := range []struct {
		cidr string
		v6   bool
	}{
		{"10.0.0.0/8", false}, {"fd00::/64", true},
	} {
		res, err := IsNetIPv6(tc.cidr)
		assert.Nil(t, err)
		assert.Equal(t, tc.v6, res)
	}
	for _, cidr := range []string{"", "10.0.0.0/33", "fd00::/129", "invalid"} {
		_, err := IsNetIPv6(cidr)
		assert.NotNil(t, err)
	}
}

func TestContainsCIDR(t *testing.T) {
	for _, tc := range []struct {
		parent string
		child  string
		want   bool
	}{
		{"10.0.0.0/8", "10.1.2.0/24", true},
		{"10.0.0.0/8", "10.0.0.0/8", true},
		{"10.1.0.0/16", "10.0.0.0/8", false},
		{"10.0.0.0/8", "11.0.0.0/8", false},
		{"fd00::/64", "fd00::/80", true},
		{"fd00::/80", "fd00::/64", false},
		{"fd00::/64", "fd00:1::/80", false},
		{"0.0.0.0/0", "fd00::/64", false},
	} {
		_, parent, err := net.ParseCIDR(tc.parent)
		assert.Nil(t, err)
		_, child, err := net.ParseCIDR(tc.child)
		assert.Nil(t, err)
		assert.Equal(t, tc.want, ContainsCIDR(parent, child), "%s %s", tc.parent, tc.child)
	}
}

func TestGetPortFromScheme(t *testing.T) {
	for scheme, want := range map[string]int{
		"http": 80, "ws": 80, "h2c": 80, "https": 443, "wss": 443,
		"ssh": 22, "dns": 53, "postgres": 5432, "postgresql": 5432,
		"redis": 6379, "mysql": 3306, "mongodb": 27017, "rdp": 3389,
		"amqp": 5672, "ftp": 21, "dot": 853, "socks5": 1080,
	} {
		port, err := GetPortFromScheme(scheme)
		assert.Nil(t, err)
		assert.Equal(t, want, port)
	}
	for _, scheme := range []string{"", "unknown", "HTTPS", "https://example.com"} {
		port, err := GetPortFromScheme(scheme)
		assert.NotNil(t, err)
		assert.Zero(t, port)
	}
}
