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
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func serviceAddrs(svc *corev1.Service, qtype uint16) []string {
	var ret []string
	for _, addr := range svc.Status.Addresses {
		if addr.DualStackIP == nil {
			continue
		}
		switch qtype {
		case dns.TypeA:
			if addr.DualStackIP.Ipv4 != "" {
				ret = append(ret, addr.DualStackIP.Ipv4)
			}
		case dns.TypeAAAA:
			if addr.DualStackIP.Ipv6 != "" {
				ret = append(ret, addr.DualStackIP.Ipv6)
			}
		}
	}

	return ret
}

func waitDNSAnswer(t *testing.T, h *harness.H, c *harness.DNSClient,
	name string, qtype uint16, want []string) {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("the Cluster DNS to resolve %s", name),
		harness.DecisionBudget, func(ctx context.Context) error {
			msg, err := c.Exchange(ctx, name, qtype)
			if err != nil {
				return err
			}
			if msg.Rcode != dns.RcodeSuccess {
				return errors.Errorf("%s returned %s", name, dns.RcodeToString[msg.Rcode])
			}
			if !msg.Authoritative {
				return errors.Errorf("%s was not answered authoritatively", name)
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

func waitDNSRcode(t *testing.T, h *harness.H, c *harness.DNSClient,
	name string, qtype uint16, want int) {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("the Cluster DNS to answer %s with %s",
		name, dns.RcodeToString[want]), harness.DecisionBudget,
		func(ctx context.Context) error {
			msg, err := c.Exchange(ctx, name, qtype)
			if err != nil {
				return err
			}
			if msg.Rcode != want {
				return errors.Errorf("%s returned %s, want %s", name,
					dns.RcodeToString[msg.Rcode], dns.RcodeToString[want])
			}
			return nil
		})
}

func testDNSResolution(t *testing.T, h *harness.H) {
	h.Require(t, capRootTUN)

	ns := h.EnsureTestNamespace(t)

	rootSvc := h.NewPublicService(t, "default")
	nsSvc := h.NewPublicService(t, ns.Metadata.Name)

	rootSvc = h.GetService(t, rootSvc.Metadata.Name)
	nsSvc = h.GetService(t, nsSvc.Metadata.Name)

	rootName, _, _ := strings.Cut(rootSvc.Metadata.Name, ".")
	nsName, _, _ := strings.Cut(nsSvc.Metadata.Name, ".")

	require.True(t, len(serviceAddrs(rootSvc, dns.TypeA)) > 0,
		"the Service %s has no IPv4 address", rootSvc.Metadata.Name)

	h.Connect(t, harness.ConnectOpts{
		Root: true,
		Args: []string{"--no-dns"},
	})

	c := h.DNSClient(t)

	zap.L().Info("Querying the Cluster DNS",
		zap.String("server", c.Server), zap.String("source", c.Source))

	t.Run("Hostnames", func(t *testing.T) {
		want := serviceAddrs(rootSvc, dns.TypeA)

		for _, name := range []string{
			fmt.Sprintf("%s.local", rootName),
			fmt.Sprintf("%s.default.local", rootName),
			fmt.Sprintf("%s.local.%s", rootName, h.Domain),
			fmt.Sprintf("%s.default.local.%s", rootName, h.Domain),
			fmt.Sprintf("%s.%s.local", rootName, h.Domain),
			fmt.Sprintf("%s.default.%s.local", rootName, h.Domain),
		} {
			waitDNSAnswer(t, h, c, name, dns.TypeA, want)
		}
	})

	t.Run("Namespaced", func(t *testing.T) {
		want := serviceAddrs(nsSvc, dns.TypeA)

		for _, name := range []string{
			fmt.Sprintf("%s.%s.local", nsName, ns.Metadata.Name),
			fmt.Sprintf("%s.%s.local.%s", nsName, ns.Metadata.Name, h.Domain),
		} {
			waitDNSAnswer(t, h, c, name, dns.TypeA, want)
		}

		waitDNSRcode(t, h, c, fmt.Sprintf("%s.local", nsName),
			dns.TypeA, dns.RcodeNameError)
	})

	t.Run("IPv6", func(t *testing.T) {
		h.Require(t, capIPv6)

		want := serviceAddrs(rootSvc, dns.TypeAAAA)
		if len(want) == 0 {
			t.Skipf("the Service %s has no IPv6 address", rootSvc.Metadata.Name)
		}

		waitDNSAnswer(t, h, c, fmt.Sprintf("%s.default.local", rootName),
			dns.TypeAAAA, want)
	})

	t.Run("UnknownService", func(t *testing.T) {
		waitDNSRcode(t, h, c,
			fmt.Sprintf("%s.default.local", utilrand.GetRandomStringCanonical(10)),
			dns.TypeA, dns.RcodeNameError)
	})

	t.Run("Lifecycle", func(t *testing.T) {
		svc := h.NewPublicService(t, "default")
		svc = h.GetService(t, svc.Metadata.Name)

		name, _, _ := strings.Cut(svc.Metadata.Name, ".")
		fqdn := fmt.Sprintf("%s.default.local", name)

		waitDNSAnswer(t, h, c, fqdn, dns.TypeA, serviceAddrs(svc, dns.TypeA))

		h.DeleteService(t, svc)

		waitDNSRcode(t, h, c, fqdn, dns.TypeA, dns.RcodeNameError)
	})

	t.Run("NonAddressQueryIsProxied", func(t *testing.T) {
		msg, err := c.Exchange(t.Context(),
			fmt.Sprintf("%s.default.local", rootName), dns.TypeMX)
		if err != nil {
			t.Skipf("the fallback zone is not reachable from this Cluster: %+v", err)
		}

		assert.False(t, msg.Authoritative,
			"only address queries are answered from the Cluster Service zone, "+
				"everything else must be handed to the fallback zone")
	})
}
