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

func (h *H) ClusterDNSAddr(t *testing.T) string {
	t.Helper()

	svc := h.GetService(t, DNSServiceName)
	if svc.Status == nil || svc.Status.Port == 0 {
		t.Fatalf("The Service %s has no port", DNSServiceName)
	}

	for _, addr := range svc.Status.Addresses {
		if addr.DualStackIP != nil && addr.DualStackIP.Ipv4 != "" {
			return net.JoinHostPort(addr.DualStackIP.Ipv4,
				fmt.Sprintf("%d", svc.Status.Port))
		}
	}

	t.Fatalf("The Service %s has no IPv4 address", DNSServiceName)
	return ""
}

func (h *H) DNSClient(t *testing.T) *DNSClient {
	t.Helper()

	var source net.IP
	for _, addr := range h.SessionAddrs(t) {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil {
			continue
		}
		source = ip
		break
	}
	if source == nil {
		t.Fatalf("The Session has no IPv4 connection address to query the Cluster DNS from")
	}

	ret := &DNSClient{
		Server: h.ClusterDNSAddr(t),
		Source: source.String(),
		c: &dns.Client{
			Net:     "udp",
			Timeout: dnsQueryTimeout,
			Dialer: &net.Dialer{
				LocalAddr: &net.UDPAddr{IP: source},
				Timeout:   dnsQueryTimeout,
			},
		},
	}

	zap.L().Debug("Built the Cluster DNS client",
		zap.String("server", ret.Server), zap.String("source", ret.Source))

	return ret
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
