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
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	restrictedDialTimeout         = 5 * time.Second
	restrictedTLSHandshakeTimeout = 5 * time.Second
	restrictedResponseTimeout     = 5 * time.Second
	restrictedIdleConnTimeout     = 30 * time.Second
)

var blockedDestinationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),

	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

type publicOnlyDialer struct {
	dialer   net.Dialer
	resolver *net.Resolver
}

func newPublicOnlyDialer() *publicOnlyDialer {
	return &publicOnlyDialer{
		dialer: net.Dialer{
			Timeout:   restrictedDialTimeout,
			KeepAlive: 30 * time.Second,
		},
		resolver: net.DefaultResolver,
	}
}

func NewRestrictedTransport() *http.Transport {
	d := newPublicOnlyDialer()

	return &http.Transport{
		Proxy: nil,

		DialContext: d.DialContext,

		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		MaxConnsPerHost:       16,
		IdleConnTimeout:       restrictedIdleConnTimeout,
		TLSHandshakeTimeout:   restrictedTLSHandshakeTimeout,
		ResponseHeaderTimeout: restrictedResponseTimeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

func RestrictTransport(tr *http.Transport) http.RoundTripper {
	if tr == nil {
		return NewRestrictedTransport()
	}

	ret := tr.Clone()

	ret.Proxy = nil
	ret.DialContext = newPublicOnlyDialer().DialContext
	ret.DialTLSContext = nil
	ret.TLSHandshakeTimeout = restrictedTLSHandshakeTimeout
	ret.ResponseHeaderTimeout = restrictedResponseTimeout
	ret.IdleConnTimeout = restrictedIdleConnTimeout

	if ret.TLSClientConfig == nil {
		ret.TLSClientConfig = &tls.Config{}
	}
	if ret.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		ret.TLSClientConfig.MinVersion = tls.VersionTLS12
	}

	return ret
}

func (d *publicOnlyDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.Errorf("unsupported outbound network %q", network)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.Errorf("invalid outbound address %q: %+v", address, err)
	}

	if err := validatePort(port); err != nil {
		return nil, err
	}

	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil, errors.Errorf("empty outbound host")
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if err := ValidatePublicAddress(addr); err != nil {
			return nil, errors.Errorf("outbound destination %q is blocked: %+v", host, err)
		}

		return d.dialAddress(ctx, network, addr, port)
	}

	resolved, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.Errorf("could not resolve outbound host %q: %+v", host, err)
	}

	publicAddrs := make([]netip.Addr, 0, len(resolved))
	for _, addr := range resolved {
		addr = addr.Unmap()
		if ValidatePublicAddress(addr) == nil {
			publicAddrs = append(publicAddrs, addr)
		}
	}

	if len(publicAddrs) == 0 {
		return nil, errors.Errorf("outbound host %q resolved only to blocked addresses", host)
	}

	for _, addr := range publicAddrs {
		conn, err := d.dialAddress(ctx, network, addr, port)
		if err == nil {
			return conn, nil
		}
	}

	return nil, errors.Errorf("could not connect to any public address for %q", host)
}

func (d *publicOnlyDialer) dialAddress(ctx context.Context, network string, addr netip.Addr, port string) (net.Conn, error) {
	if network == "tcp4" && !addr.Is4() {
		return nil, errors.Errorf("address %s is not IPv4", addr)
	}
	if network == "tcp6" && !addr.Is6() {
		return nil, errors.Errorf("address %s is not IPv6", addr)
	}

	return d.dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
}

func validatePort(port string) error {
	val, err := strconv.ParseUint(port, 10, 16)
	if err != nil || val == 0 {
		return errors.Errorf("invalid outbound port %q", port)
	}
	return nil
}

func ValidatePublicAddress(addr netip.Addr) error {
	if !addr.IsValid() {
		return errors.Errorf("invalid IP address")
	}

	addr = addr.Unmap()

	if addr.Zone() != "" {
		return errors.Errorf("scoped IP addresses are not allowed")
	}

	if !addr.IsGlobalUnicast() ||
		addr.IsPrivate() ||
		addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() {
		return errors.Errorf("IP address is not publicly routable")
	}

	for _, prefix := range blockedDestinationPrefixes {
		if prefix.Contains(addr) {
			return errors.Errorf("IP address belongs to blocked range %s", prefix)
		}
	}

	return nil
}
