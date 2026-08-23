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
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	DNSServiceName  = "dns.octelium"
	dnsQueryTimeout = 12 * time.Second
)

type DNSClient struct {
	Server string
	Source string

	c *dns.Client
}

func (h *H) ClusterDNSAddrs(t *testing.T) ([]netip.Addr, int) {
	t.Helper()

	svc := h.GetService(t, DNSServiceName)
	if svc.Status == nil || svc.Status.Port == 0 {
		t.Fatalf("The Service %s has no port", DNSServiceName)
	}

	var ret []netip.Addr
	for _, addr := range svc.Status.Addresses {
		if addr.DualStackIP == nil {
			continue
		}
		for _, val := range []string{addr.DualStackIP.Ipv4, addr.DualStackIP.Ipv6} {
			if parsed, err := netip.ParseAddr(val); err == nil {
				ret = append(ret, parsed)
			}
		}
	}

	return ret, int(svc.Status.Port)
}

func (h *H) DNSClient(t *testing.T) *DNSClient {
	t.Helper()

	sources := h.LocalSessionAddrs(t)
	if len(sources) == 0 {
		t.Fatalf("No host interface holds any of the Session addresses %v. "+
			"The Cluster DNS only answers queries coming from a Session address",
			h.SessionAddrs(t))
	}

	servers, port := h.ClusterDNSAddrs(t)

	for _, source := range sources {
		for _, server := range servers {
			if source.Is4() != server.Is4() {
				continue
			}

			ret := &DNSClient{
				Server: net.JoinHostPort(server.String(), fmt.Sprintf("%d", port)),
				Source: source.String(),
				c: &dns.Client{
					Net:     "udp",
					Timeout: dnsQueryTimeout,
					Dialer: &net.Dialer{
						LocalAddr: &net.UDPAddr{IP: net.IP(source.AsSlice())},
						Timeout:   dnsQueryTimeout,
					},
				},
			}

			zap.L().Debug("Built the Cluster DNS client",
				zap.String("server", ret.Server), zap.String("source", ret.Source))

			return ret
		}
	}

	t.Fatalf("None of the local Session addresses %v can reach the Cluster DNS addresses %v",
		sources, servers)
	return nil
}

func (c *DNSClient) Exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(name), qtype)

	ret, _, err := c.c.ExchangeContext(ctx, msg, c.Server)
	return ret, err
}

func DNSAnswerAddrs(msg *dns.Msg) []string {
	if msg == nil {
		return nil
	}

	var ret []string
	for _, rr := range msg.Answer {
		switch itm := rr.(type) {
		case *dns.A:
			ret = append(ret, itm.A.String())
		case *dns.AAAA:
			ret = append(ret, itm.AAAA.String())
		}
	}

	return ret
}
