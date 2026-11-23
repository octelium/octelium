//go:build !windows
// +build !windows

// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package serviceconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestCmdSSHApplyAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root to manage the SSH config of another OS user")
	}

	const nobodyID = 65534

	ca := newTstCA(t).PublicKey()
	startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse(newTstSSHConfig(ca))})
	homeDir := newTstUserHome(t, true)
	sshDir := filepath.Join(homeDir, ".ssh")
	require.NoError(t, os.Chmod(filepath.Dir(homeDir), 0755))
	require.NoError(t, os.Chmod(homeDir, 0700))
	for _, filePath := range []string{homeDir, sshDir} {
		require.NoError(t, os.Chown(filePath, nobodyID, nobodyID))
	}

	out, err := executeTstCmd(t, "svc1")
	require.NoError(t, err)
	assert.Contains(t, out, "Configuration successfully applied for Service: svc1\n")

	for name, line := range map[string]string{
		"known_hosts":     fmt.Sprintf("@cert-authority * %s %s", getTstPublicKeyLine(ca), tstMarker),
		"authorized_keys": fmt.Sprintf("cert-authority %s %s", getTstPublicKeyLine(ca), tstMarker),
	} {
		filePath := filepath.Join(sshDir, name)
		assert.Equal(t, []string{line}, readTstLines(t, filePath))

		fi, err := os.Lstat(filePath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), fi.Mode().Perm(), filePath)
		st, ok := fi.Sys().(*syscall.Stat_t)
		require.True(t, ok)
		assert.Equal(t, uint32(nobodyID), st.Uid, filePath)
	}
}

func getTstOpenSSHPaths(t *testing.T) (string, string) {
	t.Helper()

	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh is not available")
	}

	for _, sshdPath := range []string{"sshd", "/usr/sbin/sshd"} {
		if ret, err := exec.LookPath(sshdPath); err == nil {
			return sshPath, ret
		}
	}

	t.Skip("sshd is not available")
	return "", ""
}

func writeTstSSHKey(t *testing.T, filePath string, signer ssh.Signer, priv ed25519.PrivateKey, cert *ssh.Certificate) {
	t.Helper()

	block, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filePath, pem.EncodeToMemory(block), 0600))
	require.NoError(t, os.WriteFile(filePath+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0644))
	require.NoError(t, os.WriteFile(filePath+"-cert.pub", ssh.MarshalAuthorizedKey(cert), 0644))
}

func newTstSSHKey(t *testing.T, filePath string, ca ssh.Signer, certType uint32, principal string) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	cert := &ssh.Certificate{
		Key:             signer.PublicKey(),
		CertType:        certType,
		KeyId:           principal,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(time.Now().Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	require.NoError(t, cert.SignCert(rand.Reader, ca))

	writeTstSSHKey(t, filePath, signer, priv, cert)
}

func startTstSSHD(t *testing.T, sshdPath, hostKeyPath, config string) string {
	t.Helper()

	dir := t.TempDir()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := lis.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	require.NoError(t, lis.Close())

	configPath := filepath.Join(dir, "sshd_config")
	require.NoError(t, os.WriteFile(configPath, []byte(fmt.Sprintf(`Port %s
ListenAddress 127.0.0.1
PidFile none
UsePAM no
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
HostKey %s
HostCertificate %s-cert.pub
%s
`, port, hostKeyPath, hostKeyPath, config)), 0644))

	cmd := exec.Command(sshdPath, "-D", "-e", "-f", configPath)
	logs := &strings.Builder{}
	cmd.Stdout, cmd.Stderr = logs, logs
	require.NoError(t, cmd.Start())
	exitCh := make(chan struct{})
	go func() {
		cmd.Wait()
		close(exitCh)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-exitCh
	})

	require.Eventually(t, func() bool {
		select {
		case <-exitCh:
			return true
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 10*time.Second, 20*time.Millisecond)

	select {
	case <-exitCh:
		t.Skipf("sshd could not be started: %s", logs.String())
	default:
	}

	return port
}

func TestPrintedSSHConfigsOpenSSH(t *testing.T) {
	sshPath, sshdPath := getTstOpenSSHPaths(t)

	usr, err := user.Current()
	require.NoError(t, err)

	caSigner := newTstCA(t)
	otherCASigner := newTstCA(t)
	startTstConfigAPI(t, &tstConfigAPI{resp: newTstResponse(newTstSSHConfig(caSigner.PublicKey()))})
	newTstUserHome(t, true)

	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0755))

	getServiceConfig := func(t *testing.T, name string, cmdLineArgs ...string) string {
		t.Helper()

		out, err := executeTstCmd(t, append([]string{"svc1"}, cmdLineArgs...)...)
		require.NoError(t, err)
		ret := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(ret, []byte(out), 0644))
		return ret
	}

	knownHostsPath := getServiceConfig(t, "known_hosts", "--ssh-format", "known-hosts")
	authorizedKeysPath := getServiceConfig(t, "authorized_keys", "--ssh-format", "authorized-keys")
	caPath := getServiceConfig(t, "ca.pub", "--ssh-format", "ca-public-key")

	hostKeyPath := filepath.Join(dir, "host_key")
	newTstSSHKey(t, hostKeyPath, caSigner, ssh.HostCert, "127.0.0.1")
	otherHostKeyPath := filepath.Join(dir, "other_host_key")
	newTstSSHKey(t, otherHostKeyPath, otherCASigner, ssh.HostCert, "127.0.0.1")

	userKeyPath := filepath.Join(dir, "id")
	newTstSSHKey(t, userKeyPath, caSigner, ssh.UserCert, usr.Username)
	otherUserKeyPath := filepath.Join(dir, "other_id")
	newTstSSHKey(t, otherUserKeyPath, otherCASigner, ssh.UserCert, usr.Username)

	runSSH := func(t *testing.T, port, keyPath string) (string, error) {
		t.Helper()

		out, err := exec.CommandContext(t.Context(), sshPath, "-F", "/dev/null",
			"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
			"-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
			"-o", fmt.Sprintf("UserKnownHostsFile=%s", knownHostsPath),
			"-i", keyPath, "-o", fmt.Sprintf("CertificateFile=%s-cert.pub", keyPath),
			"-p", port, fmt.Sprintf("%s@127.0.0.1", usr.Username), "echo upstream-ok").CombinedOutput()
		return string(out), err
	}

	for _, tc := range []struct {
		name        string
		hostKeyPath string
		userKeyPath string
		config      string
		fail        string
	}{
		{
			name:        "AuthorizedKeys",
			hostKeyPath: hostKeyPath,
			userKeyPath: userKeyPath,
			config:      fmt.Sprintf("AuthorizedKeysFile %s", authorizedKeysPath),
		},
		{
			name:        "TrustedUserCAKeys",
			hostKeyPath: hostKeyPath,
			userKeyPath: userKeyPath,
			config:      fmt.Sprintf("AuthorizedKeysFile none\nTrustedUserCAKeys %s", caPath),
		},
		{
			name:        "AuthorizedKeysOtherCA",
			hostKeyPath: hostKeyPath,
			userKeyPath: otherUserKeyPath,
			config:      fmt.Sprintf("AuthorizedKeysFile %s", authorizedKeysPath),
			fail:        "Permission denied",
		},
		{
			name:        "TrustedUserCAKeysOtherCA",
			hostKeyPath: hostKeyPath,
			userKeyPath: otherUserKeyPath,
			config:      fmt.Sprintf("AuthorizedKeysFile none\nTrustedUserCAKeys %s", caPath),
			fail:        "Permission denied",
		},
		{
			name:        "KnownHostsOtherCA",
			hostKeyPath: otherHostKeyPath,
			userKeyPath: userKeyPath,
			config:      fmt.Sprintf("AuthorizedKeysFile %s", authorizedKeysPath),
			fail:        "Host key verification failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := startTstSSHD(t, sshdPath, tc.hostKeyPath, tc.config)

			out, err := runSSH(t, port, tc.userKeyPath)
			if tc.fail != "" {
				require.Error(t, err, out)
				assert.Contains(t, out, tc.fail)
				assert.NotContains(t, out, "upstream-ok")
				return
			}
			require.NoError(t, err, out)
			assert.Contains(t, out, "upstream-ok")
		})
	}
}
