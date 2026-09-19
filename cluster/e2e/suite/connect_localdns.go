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

package suite

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func requireClusterDNSViaTunnel(t *testing.T, h *harness.H) {
	t.Helper()

	local := h.LocalSessionAddrs(t)
	require.True(t, len(local) > 0, "no Session address is set on the host")

	servers, _ := h.ClusterDNSAddrs(t)

	var routes []string
	for _, server := range servers {
		if !server.Is4() {
			continue
		}

		out, err := h.Output(t.Context(), fmt.Sprintf("ip route get %s", server))
		if err != nil {
			continue
		}

		route := strings.TrimSpace(string(out))
		routes = append(routes, route)

		src := routeSource(route)
		if slices.ContainsFunc(local, func(addr netip.Addr) bool {
			return addr.String() == src
		}) {
			zap.L().Info("The Cluster DNS is reachable over the tunnel",
				zap.String("server", server.String()), zap.String("route", route))
			return
		}
	}

	t.Skipf("traffic to the Cluster DNS does not egress from a Session address, so the "+
		"local DNS server cannot be answered by the Cluster DNS on this host. This is "+
		"expected when the Cluster runs on the same host as the client. Routes: %v", routes)
}

func waitLocalDNSAddrs(t *testing.T, h *harness.H, c *harness.DNSClient,
	name string, qtype uint16, want []string) {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("the local DNS server to resolve %s", name),
		harness.DecisionBudget, func(ctx context.Context) error {
			msg, err := c.Exchange(ctx, name, qtype)
			if err != nil {
				return err
			}
			if msg.Rcode != dns.RcodeSuccess {
				return errors.Errorf("%s returned %s", name, dns.RcodeToString[msg.Rcode])
			}

			got := harness.DNSAnswerAddrs(msg)
			if len(got) == 0 {
				return errors.Errorf("%s returned no address records", name)
			}
			for _, addr := range got {
				if !slices.Contains(want, addr) {
					return errors.Errorf("%s resolved to %s, want one of %v",
						name, addr, want)
				}
			}
			return nil
		})
}

func testConnectLocalDNS(t *testing.T, h *harness.H) {
	h.Require(t, capRootTUN)

	svc := h.GetService(t, h.NewPublicService(t, "default").Metadata.Name)

	want := serviceAddrs(svc, dns.TypeA)
	require.True(t, len(want) > 0,
		"the Service %s has no IPv4 address", svc.Metadata.Name)

	name, _, _ := strings.Cut(svc.Metadata.Name, ".")
	fqdn := fmt.Sprintf("%s.default.local", name)

	listen := fmt.Sprintf("127.0.0.1:%d", h.Port())

	h.Connect(t, harness.ConnectOpts{
		Root: true,
		Args: []string{"--no-dns", "--ip-mode v4", "--localdns",
			fmt.Sprintf("--localdns-addr %s", listen)},
	})

	requireClusterDNSViaTunnel(t, h)

	c := h.DNSClientAt(listen)

	zap.L().Info("Querying the local DNS server", zap.String("server", c.Server))

	t.Run("ClusterService", func(t *testing.T) {
		waitLocalDNSAddrs(t, h, c, fqdn, dns.TypeA, want)
	})

	t.Run("UnsupportedFamily", func(t *testing.T) {
		msg, err := c.Exchange(t.Context(), fqdn, dns.TypeAAAA)
		require.Nil(t, err)

		assert.Equal(t, dns.RcodeSuccess, msg.Rcode)
		assert.Empty(t, harness.DNSAnswerAddrs(msg),
			"an IPv4-only connection must not resolve Cluster Services to IPv6 addresses")
	})

	t.Run("UnknownService", func(t *testing.T) {
		waitDNSRcode(t, h, c, fmt.Sprintf("%s.default.local",
			utilrand.GetRandomStringCanonical(10)), dns.TypeA, dns.RcodeNameError)
	})
}
