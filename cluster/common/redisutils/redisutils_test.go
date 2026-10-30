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

package redisutils

import (
	"crypto/tls"
	"testing"

	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
)

func TestRedisOptions(t *testing.T) {
	previous := ldflags.TestMode
	t.Cleanup(func() { ldflags.TestMode = previous })
	ldflags.TestMode = "false"
	t.Setenv("OCTELIUM_REDIS_HOST", "2001:db8::1")
	t.Setenv("OCTELIUM_REDIS_USERNAME", "user")
	t.Setenv("OCTELIUM_REDIS_PASSWORD", "password")
	t.Setenv("OCTELIUM_REDIS_USE_TLS", "true")
	for _, tc := range []struct {
		port, db, address string
		wantDB            int
	}{
		{"", "", "[2001:db8::1]:6379", 0},
		{"invalid", "invalid", "[2001:db8::1]:6379", 0},
		{"6380", "2", "[2001:db8::1]:6380", 2},
	} {
		t.Setenv("OCTELIUM_REDIS_PORT", tc.port)
		t.Setenv("OCTELIUM_REDIS_DATABASE", tc.db)
		opts := NewOptions()
		assert.Equal(t, tc.address, opts.Addr)
		assert.Equal(t, tc.wantDB, opts.DB)
		assert.Equal(t, "user", opts.Username)
		assert.Equal(t, "password", opts.Password)
		assert.Equal(t, uint16(tls.VersionTLS12), opts.TLSConfig.MinVersion)
	}
	t.Setenv("OCTELIUM_REDIS_USE_TLS", "false")
	assert.Nil(t, NewOptions().TLSConfig)
	ldflags.TestMode = "true"
	opts := NewOptions()
	assert.Equal(t, "localhost:6379", opts.Addr)
	assert.Empty(t, opts.Password)
	client := NewClient()
	assert.NotNil(t, client)
	assert.Nil(t, client.Close())
}
