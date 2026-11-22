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
	"os"
	"os/user"
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

const sshdPath = "/usr/sbin/sshd"

func getManagedSSHCA(home string) (string, error) {
	content, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		return "", err
	}

	for line := range strings.Lines(string(content)) {
		fields := strings.Fields(line)
		if len(fields) == 4 && fields[0] == "cert-authority" &&
			strings.HasPrefix(fields[3], "octelium-managed:") {
			return fmt.Sprintf("%s %s", fields[1], fields[2]), nil
		}
	}

	return "", errors.Errorf("the Cluster SSH CA is not in the authorized_keys file yet")
}

func testVigilSSHUpstreamCertificate(t *testing.T, h *harness.H) {
	if _, err := os.Stat(sshdPath); err != nil {
		t.Skipf("%s is not available", sshdPath)
	}

	usr, err := user.Current()
	require.Nil(t, err)

	home := t.TempDir()
	require.Nil(t, os.Mkdir(filepath.Join(home, ".ssh"), 0o700))

	dir := t.TempDir()
	hostKeyPath := filepath.Join(dir, "host_key")
	h.MustRun(t, fmt.Sprintf("ssh-keygen -q -t ed25519 -N '' -f %s", hostKeyPath))
	hostKey, err := os.ReadFile(hostKeyPath + ".pub")
	require.Nil(t, err)

	sshdPort := h.Port()

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_SSH,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("ssh://localhost:%d", sshdPort),
					},
					User: "root",
				},
				Type: &corev1.Service_Spec_Config_Ssh{
					Ssh: &corev1.Service_Spec_Config_SSH{
						User: usr.Username,
						UpstreamHostKey: &corev1.Service_Spec_Config_SSH_UpstreamHostKey{
							Type: &corev1.Service_Spec_Config_SSH_UpstreamHostKey_Key{
								Key: strings.TrimSpace(string(hostKey)),
							},
						},
					},
				},
			},
		},
	})
	h.MustWaitService(t, svc.Metadata.Name)

	port := h.Port()
	h.Connect(t, harness.ConnectOpts{
		Serve:   []string{svc.Metadata.Name},
		Publish: map[string]int{svc.Metadata.Name: port},
		Env:     []string{fmt.Sprintf("OCTELIUM_USER_HOME=%s", home)},
	})

	var ca string
	h.Eventually(t, "the client to add the Cluster SSH CA to the authorized_keys file",
		harness.ConnectBudget, func(ctx context.Context) error {
			ca, err = getManagedSSHCA(home)
			return err
		})

	writeFile := func(t *testing.T, name, content string) string {
		t.Helper()

		ret := filepath.Join(t.TempDir(), name)
		require.Nil(t, os.WriteFile(ret, []byte(content+"\n"), 0o644))
		return ret
	}

	startSSHD := func(t *testing.T, config string) string {
		t.Helper()

		logPath := filepath.Join(t.TempDir(), "sshd.log")
		configPath := writeFile(t, "sshd_config", fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
HostKey %s
PidFile none
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
LogLevel INFO
%s`, sshdPort, hostKeyPath, config))

		h.StartBackground(t, fmt.Sprintf("exec %s -D -f %s -E %s", sshdPath, configPath, logPath))
		require.Nil(t, harness.WaitPortOpen(sshdPort, sshBudget), "sshd did not start")

		return logPath
	}

	ssh := func(command string) string {
		return fmt.Sprintf("ssh %s -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s -p %d %s@localhost %s",
			sshOpts, filepath.Join(home, ".ssh", "known_hosts"), port, usr.Username, command)
	}

	mustLogin := func(t *testing.T, logPath string) {
		t.Helper()

		nonce := utilrand.GetRandomStringCanonical(12)
		h.Eventually(t, "the SSH Service to log in to the upstream", sshBudget,
			func(ctx context.Context) error {
				out, err := h.Output(ctx, ssh(fmt.Sprintf("'echo %s'", nonce)))
				if err != nil {
					return errors.Errorf("ssh failed: %+v: %s", err, out)
				}
				if !strings.Contains(string(out), nonce) {
					return errors.Errorf("the remote command returned %q", out)
				}
				return nil
			})

		logs, err := os.ReadFile(logPath)
		require.Nil(t, err)
		assert.Contains(t, string(logs), fmt.Sprintf("Accepted publickey for %s", usr.Username))
		assert.NotContains(t, string(logs), "Refusing certificate",
			"the upstream must accept the first certificate:\n%s", logs)
	}

	t.Run("AuthorizedKeys", func(t *testing.T) {
		mustLogin(t, startSSHD(t, fmt.Sprintf("AuthorizedKeysFile %s",
			filepath.Join(home, ".ssh", "authorized_keys"))))
	})

	t.Run("TrustedUserCAKeys", func(t *testing.T) {
		mustLogin(t, startSSHD(t, fmt.Sprintf("AuthorizedKeysFile none\nTrustedUserCAKeys %s",
			writeFile(t, "user_ca.pub", ca))))
	})

	t.Run("AuthorizedPrincipalsFile", func(t *testing.T) {
		mustLogin(t, startSSHD(t, fmt.Sprintf("AuthorizedKeysFile none\nTrustedUserCAKeys %s\nAuthorizedPrincipalsFile %s",
			writeFile(t, "user_ca.pub", ca), writeFile(t, "principals", usr.Username))))
	})

	t.Run("OtherPrincipal", func(t *testing.T) {
		startSSHD(t, fmt.Sprintf("AuthorizedKeysFile none\nTrustedUserCAKeys %s\nAuthorizedPrincipalsFile %s",
			writeFile(t, "user_ca.pub", ca), writeFile(t, "principals", "someone-else")))

		h.MustFailWithin(t, ssh("'echo denied'"), sshBudget)
	})
}
