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

package httputils

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePublicAddress(t *testing.T) {

	for _, addr := range []string{
		"10.0.0.1",
		"10.244.3.7",
		"172.16.0.1",
		"172.20.0.1",
		"192.168.1.1",
		"127.0.0.1",
		"169.254.169.254",
		"100.64.0.1",
		"0.0.0.0",
		"224.0.0.1",
		"240.0.0.1",
		"::1",
		"fc00::1",
		"fe80::1",
		"ff02::1",
		"::ffff:10.0.0.1",
		"::ffff:127.0.0.1",
	} {
		assert.NotNil(t, ValidatePublicAddress(netip.MustParseAddr(addr)),
			"%s must be blocked", addr)
	}

	for _, addr := range []string{
		"1.1.1.1",
		"8.8.8.8",
		"93.184.216.34",
		"2606:4700:4700::1111",
	} {
		assert.Nil(t, ValidatePublicAddress(netip.MustParseAddr(addr)),
			"%s must be allowed", addr)
	}

	assert.NotNil(t, ValidatePublicAddress(netip.Addr{}))
}

func TestRestrictedTransportDialing(t *testing.T) {
	ctx := context.Background()

	tr := NewRestrictedTransport()
	assert.NotNil(t, tr.DialContext)
	assert.Nil(t, tr.Proxy)

	for _, addr := range []string{
		"127.0.0.1:80",
		"10.0.0.1:443",
		"169.254.169.254:80",
		"[::1]:80",
	} {
		_, err := tr.DialContext(ctx, "tcp", addr)
		assert.NotNil(t, err, "%s must not be dialable", addr)
	}

	_, err := tr.DialContext(ctx, "udp", "1.1.1.1:53")
	assert.NotNil(t, err, "only tcp is dialable")

	_, err = tr.DialContext(ctx, "tcp", "1.1.1.1:0")
	assert.NotNil(t, err, "port 0 is not dialable")
}

func TestRestrictTransport(t *testing.T) {
	ctx := context.Background()

	{
		rt := RestrictTransport(nil)
		tr, ok := rt.(*http.Transport)
		assert.True(t, ok)
		assert.NotNil(t, tr.DialContext)
	}

	{
		orig := &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10},
		}

		rt := RestrictTransport(orig)
		tr, ok := rt.(*http.Transport)
		assert.True(t, ok)

		assert.Nil(t, tr.Proxy)
		assert.Nil(t, tr.DialTLSContext)
		assert.Equal(t, uint16(tls.VersionTLS12), tr.TLSClientConfig.MinVersion)

		_, err := tr.DialContext(ctx, "tcp", "127.0.0.1:80")
		assert.NotNil(t, err)

		assert.NotNil(t, orig.Proxy, "the caller's transport must not be mutated")
	}
}
