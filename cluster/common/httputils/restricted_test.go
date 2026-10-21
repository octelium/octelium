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
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/dns/dnsmessage"
)

func TestRestrictedDestinationRanges(t *testing.T) {
	for _, prefix := range blockedDestinationPrefixes {
		assert.NotNil(t, ValidatePublicAddress(prefix.Addr()), prefix.String())
	}
	assert.NotNil(t, ValidatePublicAddress(netip.MustParseAddr("2606:4700::1%eth0")))
	assert.Nil(t, ValidatePublicAddress(netip.MustParseAddr("::ffff:8.8.8.8")))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := newPublicOnlyDialer()
	for _, tc := range []struct {
		network string
		address string
	}{
		{"unix", "/var/run/docker.sock"},
		{"tcp", "missing-port"}, {"tcp", ":80"}, {"tcp", ".:80"},
		{"tcp", "1.1.1.1:"}, {"tcp", "1.1.1.1:-1"},
		{"tcp", "1.1.1.1:65536"}, {"tcp", "1.1.1.1:http"},
		{"tcp", "[::ffff:127.0.0.1]:80"},
		{"tcp4", "[2606:4700::1111]:443"}, {"tcp6", "8.8.8.8:443"},
		{"tcp", "8.8.8.8:443"}, {"tcp", "example.invalid:443"},
	} {
		conn, err := d.DialContext(ctx, tc.network, tc.address)
		assert.NotNil(t, err, tc.address)
		assert.Nil(t, conn)
	}
}

func TestRestrictedDNSResolution(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []string
		wantDials int
	}{
		{"Private", []string{"127.0.0.1", "10.0.0.1", "fd00::1"}, 0},
		{"Mixed", []string{"127.0.0.1", "169.254.169.254", "8.8.8.8", "2606:4700::1111"}, 2},
		{"MappedPrivate", []string{"::ffff:127.0.0.1"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dnsSrv, err := net.ListenPacket("udp", "127.0.0.1:0")
			if !assert.Nil(t, err) {
				return
			}
			t.Cleanup(func() { dnsSrv.Close() })
			go func() {
				buf := make([]byte, 4096)
				for {
					n, addr, err := dnsSrv.ReadFrom(buf)
					if err != nil {
						return
					}
					var query dnsmessage.Message
					if query.Unpack(buf[:n]) != nil {
						continue
					}
					resp := dnsmessage.Message{
						Header:    dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RecursionAvailable: true},
						Questions: query.Questions,
					}
					for _, question := range query.Questions {
						for _, value := range tc.addresses {
							ip := netip.MustParseAddr(value)
							answer := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, Type: question.Type}}
							if ip.Is4() && question.Type == dnsmessage.TypeA {
								answer.Body = &dnsmessage.AResource{A: ip.As4()}
							} else if ip.Is6() && question.Type == dnsmessage.TypeAAAA {
								answer.Body = &dnsmessage.AAAAResource{AAAA: ip.As16()}
							} else {
								continue
							}
							resp.Answers = append(resp.Answers, answer)
						}
					}
					packet, err := resp.Pack()
					if err == nil {
						dnsSrv.WriteTo(packet, addr)
					}
				}
			}()
			d := newPublicOnlyDialer()
			d.resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", dnsSrv.LocalAddr().String())
			}}
			var mu sync.Mutex
			var addresses []string
			d.dialer.Control = func(network, address string, conn syscall.RawConn) error {
				mu.Lock()
				addresses = append(addresses, address)
				mu.Unlock()
				return fmt.Errorf("test dial stopped")
			}
			conn, err := d.DialContext(context.Background(), "tcp", "outbound.example.:443")
			assert.NotNil(t, err)
			assert.Nil(t, conn)
			mu.Lock()
			defer mu.Unlock()
			assert.Len(t, addresses, tc.wantDials)
			for _, address := range addresses {
				host, _, err := net.SplitHostPort(address)
				assert.Nil(t, err)
				assert.Nil(t, ValidatePublicAddress(netip.MustParseAddr(host)))
			}
		})
	}
}

func TestRestrictTransportCloning(t *testing.T) {
	for _, minVersion := range []uint16{0, tls.VersionTLS12, tls.VersionTLS13} {
		orig := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: minVersion}}
		tr := RestrictTransport(orig).(*http.Transport)
		assert.NotSame(t, orig, tr)
		assert.NotSame(t, orig.TLSClientConfig, tr.TLSClientConfig)
		assert.GreaterOrEqual(t, tr.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))
		assert.Equal(t, minVersion, orig.TLSClientConfig.MinVersion)
	}
	tr := RestrictTransport(&http.Transport{}).(*http.Transport)
	assert.Equal(t, uint16(tls.VersionTLS12), tr.TLSClientConfig.MinVersion)
	assert.Equal(t, restrictedTLSHandshakeTimeout, tr.TLSHandshakeTimeout)
	assert.Equal(t, restrictedResponseTimeout, tr.ResponseHeaderTimeout)
	assert.Equal(t, restrictedIdleConnTimeout, tr.IdleConnTimeout)
}

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
