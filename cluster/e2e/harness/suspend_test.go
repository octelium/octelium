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
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEstablishedLocalAddrs(t *testing.T) {
	out := `0      0          10.1.0.4:41234          10.1.0.4:443   users:(("octelium",pid=1234,fd=9))
0      0          10.1.0.4:41236          10.1.0.4:443   users:(("octelium",pid=12345,fd=9))
0      0          10.1.0.4:41238          10.1.0.4:8443  users:(("octelium",pid=1234,fd=10))
0      0   [::ffff:10.1.0.4]:41240   [::ffff:10.1.0.4]:443   users:(("octelium",pid=1234,fd=11))
0      0          [fd00::4]:41242          [fd00::5]:443   users:(("octelium",pid=1235,fd=12))
0      0          [fd00::4]:41244          [fd00::5]:443   users:(("curl",pid=999,fd=3))
`

	assert.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("10.1.0.4:41234"),
		netip.MustParseAddrPort("10.1.0.4:41240"),
		netip.MustParseAddrPort("[fd00::4]:41242"),
	}, establishedLocalAddrs(out, []int{1234, 1235}, 443))

	assert.Empty(t, establishedLocalAddrs(out, []int{4321}, 443))
	assert.Empty(t, establishedLocalAddrs("", []int{1234}, 443))
}
