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
