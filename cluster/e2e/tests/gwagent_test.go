//go:build e2e

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

package tests

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func testGatewayResource(t *testing.T, h *harness.H) {
	gws := h.Gateways(t)
	require.True(t, len(gws) > 0, "the Cluster has no Gateways")

	for _, gw := range gws {
		require.NotNil(t, gw.Status, "the Gateway %s has no status", gw.Metadata.Name)

		assert.NotNil(t, gw.Status.RegionRef)
		assert.NotNil(t, gw.Status.NodeRef)
		assert.NotEmpty(t, gw.Status.Id)

		require.NotNil(t, gw.Status.Cidr, "the Gateway %s has no CIDR", gw.Metadata.Name)
		assert.NotEmpty(t, gw.Status.Cidr.V4)
		assert.NotEmpty(t, gw.Status.Cidr.V6)

		require.NotNil(t, gw.Status.Wireguard,
			"the Gateway %s has no WireGuard status", gw.Metadata.Name)
		assert.True(t, gw.Status.Wireguard.Port > 0)
		assert.NotEmpty(t, gw.Status.Wireguard.PublicKey)

		assert.True(t, slices.Contains(gw.Status.PublicIPs, h.ExternalIP),
			"the Gateway %s publishes %v, want it to contain the Region address %s",
			gw.Metadata.Name, gw.Status.PublicIPs, h.ExternalIP)

		if h.Scenario.Caps.Has(capQUICv0) {
			require.NotNil(t, gw.Status.Quicv0,
				"the Gateway %s has no QUICv0 status", gw.Metadata.Name)
			assert.True(t, gw.Status.Quicv0.Port > 0)
		}
	}

	if h.Scenario.Caps.Has(capMultiNode) {
		assert.True(t, len(gws) > 1,
			"a multi-node scenario should expose more than one Gateway, got %d", len(gws))
	}
}

func waitConnectionState(t *testing.T, h *harness.H,
	sessName string, check func(c *corev1.Session_Status_Connection) error) time.Duration {
	t.Helper()

	return h.Within(t, "the Session connection state to settle", harness.DecisionBudget,
		func(ctx context.Context) error {
			sess, err := h.CoreC().GetSession(ctx, &metav1.GetOptions{Name: sessName})
			if err != nil {
				return err
			}
			return check(sess.Status.Connection)
		})
}

func testGatewayConnection(t *testing.T, h *harness.H) {
	svc := h.NewPublicService(t, "default")

	for _, tunnel := range []struct {
		name string
		mode string
		want corev1.Session_Status_Connection_Type
		caps []scenario.Capability
	}{
		{
			name: "WireGuard",
			mode: "",
			want: corev1.Session_Status_Connection_WIREGUARD,
		},
		{
			name: "QUICv0",
			mode: "quicv0",
			want: corev1.Session_Status_Connection_QUICV0,
			caps: []scenario.Capability{capQUICv0},
		},
	} {
		t.Run(tunnel.name, func(t *testing.T) {
			h.Require(t, tunnel.caps...)

			port := h.Port()
			conn := h.Connect(t, harness.ConnectOpts{
				TunnelMode: tunnel.mode,
				Publish:    map[string]int{svc.Metadata.Name: port},
			})

			sessName := h.Status(t).Session.Metadata.Name

			established := waitConnectionState(t, h, sessName,
				func(c *corev1.Session_Status_Connection) error {
					if c == nil {
						return errors.Errorf("the Session has no connection yet")
					}
					if c.Type != tunnel.want {
						return errors.Errorf("the connection type is %s, want %s",
							c.Type, tunnel.want)
					}
					if len(c.Addresses) == 0 {
						return errors.Errorf("the connection has no assigned addresses")
					}
					return nil
				})

			sess := h.GetSession(t, sessName)
			require.NotNil(t, sess.Status.Connection)

			addr := sess.Status.Connection.Addresses[0]
			assert.NotEmpty(t, addr.V4, "the connection has no IPv4 address")
			assert.NotEmpty(t, addr.V6, "the connection has no IPv6 address")

			if tunnel.want == corev1.Session_Status_Connection_WIREGUARD {
				assert.NotEmpty(t, sess.Status.Connection.X25519PublicKey,
					"a WireGuard connection must publish an x25519 public key")
			}

			assert.True(t, slices.ContainsFunc(sess.Status.Connection.PublishedServices,
				func(p *corev1.Session_Status_Connection_PublishedService) bool {
					return p.ServiceRef != nil && p.ServiceRef.Name == svc.Metadata.Name
				}), "the published Service is missing from the connection state")

			h.GetStatus(t, h.HTTP(), conn.URL(svc.Metadata.Name), http.StatusOK)

			require.Nil(t, conn.Disconnect())

			released := waitConnectionState(t, h, sessName,
				func(c *corev1.Session_Status_Connection) error {
					if c != nil {
						return errors.Errorf("the Session is still connected")
					}
					return nil
				})

			zap.L().Info("Gateway connection lifecycle",
				zap.String("tunnel", tunnel.name),
				zap.Duration("established", established),
				zap.Duration("released", released))

			assert.Less(t, released, propagationBudget,
				"releasing the connection took %s, budget is %s",
				released, propagationBudget)
		})
	}
}

func testGatewayL3(t *testing.T, h *harness.H) {
	h.Require(t, capRootTUN)

	svc := h.NewPublicService(t, "default")
	svc = h.GetService(t, svc.Metadata.Name)

	require.True(t, len(svc.Status.Addresses) > 0)
	require.True(t, svc.Status.Port > 0)

	addr := svc.Status.Addresses[0].DualStackIP
	require.NotNil(t, addr)

	h.Connect(t, harness.ConnectOpts{
		Root: true,
		Args: []string{"--no-dns"},
	})

	get := func(t *testing.T, host string) {
		t.Helper()

		url := fmt.Sprintf("http://%s",
			net.JoinHostPort(host, fmt.Sprintf("%d", svc.Status.Port)))

		h.Eventually(t, fmt.Sprintf("GET %s to succeed over the tunnel", url),
			harness.ConnectBudget, func(ctx context.Context) error {
				res, err := h.HTTP().R().SetContext(ctx).Get(url)
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
				}
				return nil
			})
	}

	t.Run("IPv4", func(t *testing.T) {
		if addr.Ipv4 == "" {
			t.Skip("the Service has no IPv4 address")
		}
		get(t, addr.Ipv4)
	})

	t.Run("IPv6", func(t *testing.T) {
		h.Require(t, capIPv6)
		if addr.Ipv6 == "" {
			t.Skip("the Service has no IPv6 address")
		}
		get(t, addr.Ipv6)
	})

	t.Run("Routes", func(t *testing.T) {
		out, err := h.Output(t.Context(), "ip route show table all")
		require.Nil(t, err)

		assert.Contains(t, string(out), "octelium",
			"no Octelium route was installed on the host")
	})
}
