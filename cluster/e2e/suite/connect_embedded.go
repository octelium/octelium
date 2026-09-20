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
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

const (
	eSSHServiceName    = "essh.octelium"
	eSOCKS5ServiceName = "socks5.octelium"

	eSSHDefaultPort    = 22022
	eSOCKS5DefaultPort = 1080

	sshBudget = 60 * time.Second
)

func testConnectESSH(t *testing.T, h *harness.H) {
	h.Require(t, capIPv6)
	h.MustWaitService(t, eSSHServiceName)

	port := h.Port()
	h.Connect(t, harness.ConnectOpts{
		UseESSH: true,
		Publish: map[string]int{eSSHServiceName: port},
		Args:    []string{"--ip-mode both"},
	})

	sessName := h.Status(t).Session.Metadata.Name

	sess := h.GetSession(t, sessName)
	require.NotNil(t, sess.Status.Connection)
	assert.True(t, sess.Status.Connection.ESSHEnable,
		"the Session does not advertise eSSH")
	assert.Equal(t, int32(eSSHDefaultPort), sess.Status.Connection.ESSHPort)

	t.Run("OpenSSH", func(t *testing.T) {
		nonce := utilrand.GetRandomStringCanonical(12)

		h.Eventually(t, "the eSSH server to run a remote command on the own Session",
			harness.ConnectBudget, func(ctx context.Context) error {
				out, err := h.Output(ctx, fmt.Sprintf(
					"ssh -o BatchMode=yes -o ConnectTimeout=10 -p %d %s@localhost 'echo %s'",
					port, sessName, nonce))
				if err != nil {
					return errors.Errorf("ssh failed: %+v: %s", err, out)
				}
				if !strings.Contains(string(out), nonce) {
					return errors.Errorf("the remote command returned %q", out)
				}
				return nil
			})
	})

	t.Run("LocalForward", func(t *testing.T) {
		upstream := h.StartHTTPUpstream(t, nil)
		local := h.Port()

		h.StartBackground(t, fmt.Sprintf(
			"ssh -o BatchMode=yes -o ConnectTimeout=10 -N -p %d -L %d:127.0.0.1:%d %s@localhost",
			port, local, upstream.Port, sessName))

		require.Nil(t, harness.WaitPortOpen(local, sshBudget),
			"ssh did not open the local forwarding port")

		h.WaitGetStatus(t, h.HTTP(), fmt.Sprintf("http://localhost:%d", local),
			http.StatusOK)
	})

	t.Run("UnknownSession", func(t *testing.T) {
		h.MustFailWithin(t, fmt.Sprintf(
			"ssh -o BatchMode=yes -o ConnectTimeout=10 -p %d %s@localhost true",
			port, utilrand.GetRandomStringCanonical(10)), sshBudget)
	})
}

func socks5Client(t *testing.T, addr, sessName string) *http.Client {
	t.Helper()

	dialer, err := proxy.SOCKS5("tcp", addr, &proxy.Auth{
		User:     sessName,
		Password: utilrand.GetRandomStringCanonical(8),
	}, proxy.Direct)
	require.Nil(t, err)

	ctxDialer, ok := dialer.(proxy.ContextDialer)
	require.True(t, ok, "the SOCKS5 dialer does not support contexts")

	return &http.Client{
		Timeout:   harness.DecisionBudget,
		Transport: &http.Transport{DialContext: ctxDialer.DialContext},
	}
}

func testConnectESOCKS5(t *testing.T, h *harness.H) {
	h.MustWaitService(t, eSOCKS5ServiceName)

	upstream := h.StartHTTPUpstream(t, nil)
	upstream.SetServeFn(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("socks5"))
	})

	port := h.Port()
	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{eSOCKS5ServiceName: port},
		Args:    []string{"--esocks5"},
	})

	sessName := h.Status(t).Session.Metadata.Name

	sess := h.GetSession(t, sessName)
	require.NotNil(t, sess.Status.Connection)
	assert.True(t, sess.Status.Connection.ESOCKS5Enable,
		"the Session does not advertise an embedded SOCKS5 server")
	assert.Equal(t, int32(eSOCKS5DefaultPort), sess.Status.Connection.ESOCKS5Port)

	target := fmt.Sprintf("http://%s",
		net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", upstream.Port)))

	t.Run("Connect", func(t *testing.T) {
		c := socks5Client(t, conn.Addr(eSOCKS5ServiceName), sessName)

		h.Eventually(t, "the embedded SOCKS5 server to reach the target",
			harness.ConnectBudget, func(ctx context.Context) error {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				if err != nil {
					return err
				}

				res, err := c.Do(req)
				if err != nil {
					return err
				}
				defer res.Body.Close()

				if res.StatusCode != http.StatusOK {
					return errUnexpectedStatus(res.StatusCode, http.StatusOK)
				}

				body, err := io.ReadAll(res.Body)
				if err != nil {
					return err
				}
				if string(body) != "socks5" {
					return errors.Errorf("the target returned %q, want %q",
						string(body), "socks5")
				}
				return nil
			})
	})

	t.Run("UnknownSession", func(t *testing.T) {
		c := socks5Client(t, conn.Addr(eSOCKS5ServiceName),
			utilrand.GetRandomStringCanonical(10))

		ctx, cancel := context.WithTimeout(t.Context(), harness.DecisionBudget)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		require.Nil(t, err)

		res, err := c.Do(req)
		if err == nil {
			res.Body.Close()
		}

		assert.NotNil(t, err,
			"the embedded SOCKS5 Service must refuse unknown upstream Sessions")
	})
}
