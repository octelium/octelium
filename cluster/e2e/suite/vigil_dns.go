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
	"testing"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func waitDNSAnswerAt(t *testing.T, h *harness.H, c *harness.DNSClient,
	name string, qtype uint16, want string) {
	t.Helper()

	h.Eventually(t, fmt.Sprintf("the DNS Service to resolve %s", name),
		harness.ConnectBudget, func(ctx context.Context) error {
			msg, err := c.Exchange(ctx, name, qtype)
			if err != nil {
				return err
			}
			if msg.Rcode != dns.RcodeSuccess {
				return errors.Errorf("%s returned %s", name, dns.RcodeToString[msg.Rcode])
			}

			got := harness.DNSAnswerAddrs(msg)
			if len(got) != 1 || got[0] != want {
				return errors.Errorf("%s resolved to %v, want %s", name, got, want)
			}
			return nil
		})
}

func testVigilDNS(t *testing.T, h *harness.H) {
	h.Require(t, capRootTUN)

	upstream := h.StartDNSUpstream(t, nil)

	const (
		allowedName = "allowed.e2e.octelium."
		blockedName = "blocked.e2e.octelium."
	)

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_DNS,
			Port: 53,
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Name: "deny-dns",
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								harness.MatchRule("deny-name", 0,
									corev1.Policy_Spec_Rule_DENY,
									fmt.Sprintf(`ctx.request.dns.name == %q`, blockedName)),
								harness.MatchRule("deny-aaaa", 0,
									corev1.Policy_Spec_Rule_DENY,
									fmt.Sprintf(`ctx.request.dns.typeID == %d`, dns.TypeAAAA)),
							},
						},
					},
				},
			},
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("udp://127.0.0.1:%d", upstream.Port),
					},
					User: "root",
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	h.Connect(t, harness.ConnectOpts{
		Root:  true,
		Serve: []string{svc.Metadata.Name},
		Args:  []string{"--no-dns", "--ip-mode v4"},
	})

	svc = h.GetService(t, svc.Metadata.Name)

	c := h.DNSClientForService(t, svc)

	t.Run("Allowed", func(t *testing.T) {
		waitDNSAnswerAt(t, h, c, allowedName, dns.TypeA, upstream.AddrV4)

		assert.True(t, upstream.Queries() > 0,
			"the DNS Service did not reach the served upstream")
	})

	t.Run("DeniedName", func(t *testing.T) {
		h.Eventually(t, "the Service policy to refuse the blocked name",
			harness.DecisionBudget, func(ctx context.Context) error {
				msg, err := c.Exchange(ctx, blockedName, dns.TypeA)
				if err != nil {
					return err
				}
				if msg.Rcode != dns.RcodeRefused {
					return errors.Errorf("%s returned %s, want %s", blockedName,
						dns.RcodeToString[msg.Rcode],
						dns.RcodeToString[dns.RcodeRefused])
				}
				return nil
			})
	})

	t.Run("DeniedQueryType", func(t *testing.T) {
		msg, err := c.Exchange(t.Context(), allowedName, dns.TypeAAAA)
		require.Nil(t, err)
		assert.Equal(t, dns.RcodeRefused, msg.Rcode,
			"the AAAA queries must be refused by the Service policy")
	})

	t.Run("AllowedAfterDenials", func(t *testing.T) {
		waitDNSAnswerAt(t, h, c, allowedName, dns.TypeA, upstream.AddrV4)
	})
}
