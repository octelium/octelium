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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sshOpts = "-o BatchMode=yes -o ConnectTimeout=10"

func newESSHService(t *testing.T, h *harness.H,
	cfg *corev1.Service_Spec_Config_SSH) *corev1.Service {
	t.Helper()

	cfg.ESSHMode = true

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_SSH,
			Config: &corev1.Service_Spec_Config{
				Type: &corev1.Service_Spec_Config_Ssh{Ssh: cfg},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	return svc
}

func testVigilSSH(t *testing.T, h *harness.H) {
	h.Require(t, capIPv6)

	full := newESSHService(t, h, &corev1.Service_Spec_Config_SSH{
		EnableSubsystem:           true,
		EnableLocalPortForwarding: true,
	})
	restricted := newESSHService(t, h, &corev1.Service_Spec_Config_SSH{})

	fullPort := h.Port()
	restrictedPort := h.Port()

	h.Connect(t, harness.ConnectOpts{
		UseESSH: true,
		Publish: map[string]int{
			full.Metadata.Name:       fullPort,
			restricted.Metadata.Name: restrictedPort,
		},
		Args: []string{"--ip-mode both"},
	})

	sessName := h.Status(t).Session.Metadata.Name

	ssh := func(port int, command string) string {
		return fmt.Sprintf("ssh %s -p %d %s@localhost %s",
			sshOpts, port, sessName, command)
	}

	t.Run("Exec", func(t *testing.T) {
		nonce := utilrand.GetRandomStringCanonical(12)

		h.Eventually(t, "the SSH Service to execute a remote command",
			harness.ConnectBudget, func(ctx context.Context) error {
				out, err := h.Output(ctx, ssh(fullPort, fmt.Sprintf("'echo %s'", nonce)))
				if err != nil {
					return errors.Errorf("ssh failed: %+v: %s", err, out)
				}
				if !strings.Contains(string(out), nonce) {
					return errors.Errorf("the remote command returned %q", out)
				}
				return nil
			})
	})

	t.Run("ExitStatus", func(t *testing.T) {
		out := h.MustOutputWithin(t,
			fmt.Sprintf("%s; echo status=$?", ssh(fullPort, "'exit 7'")), sshBudget)

		assert.Contains(t, string(out), "status=7",
			"the exit status of the remote command was not propagated")
	})

	t.Run("Stdin", func(t *testing.T) {
		nonce := utilrand.GetRandomStringCanonical(12)

		out := h.MustOutputWithin(t,
			fmt.Sprintf("echo %s | %s", nonce, ssh(fullPort, "cat")), sshBudget)

		assert.Contains(t, string(out), nonce)
	})

	t.Run("Subsystem", func(t *testing.T) {
		dir := t.TempDir()

		src := filepath.Join(dir, "src")
		dst := filepath.Join(dir, "dst")
		nonce := utilrand.GetRandomStringCanonical(24)

		require.Nil(t, os.WriteFile(src, []byte(nonce), 0o600))

		sftp := func(port int) string {
			return fmt.Sprintf("printf 'put %s %s\\n' | sftp -q %s -P %d -b - %s@localhost",
				src, dst, sshOpts, port, sessName)
		}

		h.MustOutputWithin(t, sftp(fullPort), sshBudget)

		got, err := os.ReadFile(dst)
		require.Nil(t, err, "the file was not copied over SFTP")
		assert.Equal(t, nonce, string(got))

		h.MustFailWithin(t, sftp(restrictedPort), sshBudget)
	})

	t.Run("LocalPortForwarding", func(t *testing.T) {
		upstream := h.StartHTTPUpstream(t, nil)

		forward := func(t *testing.T, port, local int) {
			t.Helper()

			h.StartBackground(t, fmt.Sprintf("ssh %s -N -p %d -L %d:127.0.0.1:%d %s@localhost",
				sshOpts, port, local, upstream.Port, sessName))

			require.Nil(t, harness.WaitPortOpen(local, sshBudget),
				"ssh did not open the local forwarding port")
		}

		allowed := h.Port()
		forward(t, fullPort, allowed)

		h.WaitGetStatus(t, h.HTTP(),
			fmt.Sprintf("http://localhost:%d", allowed), http.StatusOK)

		denied := h.Port()
		forward(t, restrictedPort, denied)

		h.Consistently(t, "the Service without local port forwarding to refuse the channel",
			decisionSettle, func(ctx context.Context) error {
				res, err := h.HTTPNoRetry().R().SetContext(ctx).
					Get(fmt.Sprintf("http://localhost:%d", denied))
				if err != nil {
					return nil
				}
				return errors.Errorf("the forwarded request returned status %d",
					res.StatusCode())
			})
	})

	t.Run("Authorization", func(t *testing.T) {
		restricted.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Name: "deny-ssh-user",
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							harness.MatchRule("deny-user", 0, corev1.Policy_Spec_Rule_DENY,
								fmt.Sprintf(`ctx.request.ssh.connect.user == %q`, sessName)),
						},
					},
				},
			},
		}
		restricted = h.UpdateService(t, restricted)

		h.Eventually(t, "the Service policy to deny the SSH user",
			harness.DecisionBudget, func(ctx context.Context) error {
				if out, err := h.Output(ctx,
					ssh(restrictedPort, "'echo denied'")); err == nil {
					return errors.Errorf("the SSH user is still allowed: %s", out)
				}
				return nil
			})

		restricted.Spec.Authorization = nil
		restricted = h.UpdateService(t, restricted)

		nonce := utilrand.GetRandomStringCanonical(12)

		h.Eventually(t, "the SSH user to be allowed again", harness.DecisionBudget,
			func(ctx context.Context) error {
				out, err := h.Output(ctx,
					ssh(restrictedPort, fmt.Sprintf("'echo %s'", nonce)))
				if err != nil {
					return errors.Errorf("ssh failed: %+v: %s", err, out)
				}
				if !strings.Contains(string(out), nonce) {
					return errors.Errorf("the remote command returned %q", out)
				}
				return nil
			})
	})
}
