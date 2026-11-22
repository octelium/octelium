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

func newUpstreamSSHService(port int, user, hostKey string) *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_SSH,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("ssh://localhost:%d", port),
					},
					User: "root",
				},
				Type: &corev1.Service_Spec_Config_Ssh{
					Ssh: &corev1.Service_Spec_Config_SSH{
						User: user,
						UpstreamHostKey: &corev1.Service_Spec_Config_SSH_UpstreamHostKey{
							Type: &corev1.Service_Spec_Config_SSH_UpstreamHostKey_Key{
								Key: hostKey,
							},
						},
					},
				},
			},
		},
	}
}

func writeSSHDFile(t *testing.T, name, content string) string {
	t.Helper()

	ret := filepath.Join(t.TempDir(), name)
	require.Nil(t, os.WriteFile(ret, []byte(content+"\n"), 0o644))
	return ret
}

func startUpstreamSSHD(t *testing.T, h *harness.H, port int, config string) string {
	t.Helper()

	logPath := filepath.Join(t.TempDir(), "sshd.log")
	configPath := writeSSHDFile(t, "sshd_config", fmt.Sprintf(`Port %d
ListenAddress 127.0.0.1
PidFile none
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
%s`, port, config))

	h.StartBackground(t, fmt.Sprintf("exec %s -D -f %s -E %s", sshdPath, configPath, logPath))
	require.Nil(t, harness.WaitPortOpen(port, sshBudget), "sshd did not start")

	return logPath
}

func getUpstreamSSHCommand(home string, port int, user, command string) string {
	return fmt.Sprintf("ssh %s -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%s -p %d %s@localhost %s",
		sshOpts, filepath.Join(home, ".ssh", "known_hosts"), port, user, command)
}

func mustUpstreamSSHLogin(t *testing.T, h *harness.H, home string, port int, user string) {
	t.Helper()

	nonce := utilrand.GetRandomStringCanonical(12)
	h.Eventually(t, "the SSH Service to log in to the upstream", sshBudget,
		func(ctx context.Context) error {
			out, err := h.Output(ctx, getUpstreamSSHCommand(home, port, user, fmt.Sprintf("'echo %s'", nonce)))
			if err != nil {
				return errors.Errorf("ssh failed: %+v: %s", err, out)
			}
			if !strings.Contains(string(out), nonce) {
				return errors.Errorf("the remote command returned %q", out)
			}
			return nil
		})
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

	svc := h.CreateService(t, newUpstreamSSHService(sshdPort, usr.Username, strings.TrimSpace(string(hostKey))))
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

	startSSHD := func(t *testing.T, config string) string {
		t.Helper()

		return startUpstreamSSHD(t, h, sshdPort, fmt.Sprintf("HostKey %s\nLogLevel INFO\n%s", hostKeyPath, config))
	}

	mustLogin := func(t *testing.T, logPath string) {
		t.Helper()

		mustUpstreamSSHLogin(t, h, home, port, usr.Username)

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
			writeSSHDFile(t, "user_ca.pub", ca))))
	})

	t.Run("AuthorizedPrincipalsFile", func(t *testing.T) {
		mustLogin(t, startSSHD(t, fmt.Sprintf("AuthorizedKeysFile none\nTrustedUserCAKeys %s\nAuthorizedPrincipalsFile %s",
			writeSSHDFile(t, "user_ca.pub", ca), writeSSHDFile(t, "principals", usr.Username))))
	})

	t.Run("OtherPrincipal", func(t *testing.T) {
		startSSHD(t, fmt.Sprintf("AuthorizedKeysFile none\nTrustedUserCAKeys %s\nAuthorizedPrincipalsFile %s",
			writeSSHDFile(t, "user_ca.pub", ca), writeSSHDFile(t, "principals", "someone-else")))

		h.MustFailWithin(t, getUpstreamSSHCommand(home, port, usr.Username, "'echo denied'"), sshBudget)
	})
}

func testVigilSSHUpstreamHostKey(t *testing.T, h *harness.H) {
	if _, err := os.Stat(sshdPath); err != nil {
		t.Skipf("%s is not available", sshdPath)
	}

	usr, err := user.Current()
	require.Nil(t, err)

	home := t.TempDir()
	require.Nil(t, os.Mkdir(filepath.Join(home, ".ssh"), 0o700))

	dir := t.TempDir()
	generateKey := func(name, typ string) (string, string) {
		path := filepath.Join(dir, name)
		h.MustRun(t, fmt.Sprintf("ssh-keygen -q -t %s -N '' -f %s", typ, path))
		pub, err := os.ReadFile(path + ".pub")
		require.Nil(t, err)
		return path, strings.TrimSpace(string(pub))
	}

	rsaPath, rsaKey := generateKey("rsa", "rsa")
	ecdsaPath, ecdsaKey := generateKey("ecdsa", "ecdsa")
	ed25519Path, ed25519Key := generateKey("ed25519", "ed25519")
	_, otherKey := generateKey("other", "ed25519")

	sshdPort := h.Port()

	tcs := []struct {
		name string
		key  string
		algo string
		svc  *corev1.Service
		port int
	}{
		{name: "Ed25519", key: ed25519Key, algo: "ssh-ed25519"},
		{name: "ECDSA", key: ecdsaKey, algo: "ecdsa-sha2-nistp256"},
		{name: "RSA", key: rsaKey, algo: "rsa-sha2-256"},
		{name: "OtherKey", key: otherKey},
	}

	var names []string
	publish := map[string]int{}
	for i := range tcs {
		tcs[i].svc = h.CreateService(t, newUpstreamSSHService(sshdPort, usr.Username, tcs[i].key))
		tcs[i].port = h.Port()
		names = append(names, tcs[i].svc.Metadata.Name)
		publish[tcs[i].svc.Metadata.Name] = tcs[i].port
	}
	h.MustWaitService(t, names...)

	h.Connect(t, harness.ConnectOpts{
		Serve:   names,
		Publish: publish,
		Env:     []string{fmt.Sprintf("OCTELIUM_USER_HOME=%s", home)},
	})

	h.Eventually(t, "the client to add the Cluster SSH CA to the authorized_keys file",
		harness.ConnectBudget, func(ctx context.Context) error {
			_, err := getManagedSSHCA(home)
			return err
		})

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			logPath := startUpstreamSSHD(t, h, sshdPort,
				fmt.Sprintf("HostKey %s\nHostKey %s\nHostKey %s\nLogLevel DEBUG1\nAuthorizedKeysFile %s",
					rsaPath, ecdsaPath, ed25519Path, filepath.Join(home, ".ssh", "authorized_keys")))

			if tc.algo == "" {
				h.MustFailWithin(t, getUpstreamSSHCommand(home, tc.port, usr.Username, "'echo denied'"), sshBudget)

				h.Eventually(t, "the upstream to log the host key exchange", sshBudget,
					func(ctx context.Context) error {
						logs, err := os.ReadFile(logPath)
						if err != nil {
							return err
						}
						if !strings.Contains(string(logs), "kex: host key algorithm: ssh-ed25519") {
							return errors.Errorf("no host key exchange in the sshd log yet")
						}
						return nil
					})

				logs, err := os.ReadFile(logPath)
				require.Nil(t, err)
				assert.NotContains(t, string(logs), "Accepted publickey")
				return
			}

			mustUpstreamSSHLogin(t, h, home, tc.port, usr.Username)

			logs, err := os.ReadFile(logPath)
			require.Nil(t, err)
			assert.Contains(t, string(logs), fmt.Sprintf("kex: host key algorithm: %s", tc.algo))
			assert.Contains(t, string(logs), fmt.Sprintf("Accepted publickey for %s", usr.Username))
			for _, algo := range []string{"ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-256", "rsa-sha2-512"} {
				if algo != tc.algo {
					assert.NotContains(t, string(logs), fmt.Sprintf("kex: host key algorithm: %s", algo))
				}
			}
		})
	}
}
