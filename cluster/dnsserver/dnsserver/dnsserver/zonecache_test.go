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

package dnsserver

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"

	"github.com/octelium/octelium/cluster/common/tests"
)

func TestZoneCache(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	zc := newZoneCache(0)

	domain := "www.google.com."
	typ := dns.TypeA
	assert.Nil(t, zc.get(domain, typ))

	{
		c := new(dns.Client)
		m := new(dns.Msg)
		m.SetQuestion(domain, typ)
		r, _, err := c.Exchange(m, "8.8.8.8:53")
		assert.Nil(t, err)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode)

		zc.set(domain, typ, r)

		cr := zc.get(domain, typ)
		assert.NotNil(t, cr)

		{
			assert.Nil(t, zc.get("does-not.exist.com.", typ))
		}

		assert.Equal(t, (cr.Answer[0].(*dns.A)).A.String(), (r.Answer[0].(*dns.A)).A.String())

		zc.doCleanup()

		cr = zc.get(domain, typ)
		assert.NotNil(t, cr)
	}
}
