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

package controller

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const testSSHUnknownUID, testSSHUnknownGID = 54321, 54322

func getFileOwner(t *testing.T, filePath string) (uint32, uint32) {
	fi, err := os.Stat(filePath)
	assert.Nil(t, err)

	st, ok := fi.Sys().(*syscall.Stat_t)
	assert.True(t, ok)

	return st.Uid, st.Gid
}

func TestServiceConfigSSHFileOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to change file ownership")
	}

	const usrUID, usrGID = 1000, 1000

	homeDir := t.TempDir()
	assert.Nil(t, os.Chmod(filepath.Dir(homeDir), 0755))
	t.Setenv("OCTELIUM_USER_HOME", homeDir)

	sshDir := path.Join(homeDir, ".ssh")
	assert.Nil(t, os.MkdirAll(sshDir, 0700))
	assert.Nil(t, os.Chown(sshDir, usrUID, usrGID))
	expectedGID := getSSHConfigUserCredential(usrUID, usrGID).Gid

	c := newTestSSHCtlForDomain("example.com")

	assert.Nil(t, c.setServiceConfigs())

	for _, name := range []string{"authorized_keys", "known_hosts"} {
		uid, gid := getFileOwner(t, path.Join(sshDir, name))
		assert.Equal(t, uint32(usrUID), uid)
		assert.Equal(t, expectedGID, gid)
	}

	assert.Nil(t, c.unsetServiceConfigs())

	for _, name := range []string{"authorized_keys", "known_hosts"} {
		uid, gid := getFileOwner(t, path.Join(sshDir, name))
		assert.Equal(t, uint32(usrUID), uid)
		assert.Equal(t, expectedGID, gid)
	}
}

func newTestSSHUserHome(t *testing.T, uid, gid int) string {
	t.Helper()
	homeDir := t.TempDir()
	require.NoError(t, os.Chmod(filepath.Dir(homeDir), 0755))
	require.NoError(t, os.Chmod(homeDir, 0700))
	require.NoError(t, os.Mkdir(filepath.Join(homeDir, ".ssh"), 0700))
	for _, filePath := range []string{homeDir, filepath.Join(homeDir, ".ssh")} {
		require.NoError(t, os.Chown(filePath, uid, gid))
	}
	return homeDir
}

func TestGetSSHConfigUserCredential(t *testing.T) {
	assert.Equal(t, &syscall.Credential{Uid: testSSHUnknownUID, Gid: testSSHUnknownGID},
		getSSHConfigUserCredential(testSSHUnknownUID, testSSHUnknownGID))

	usr, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Skip("The current OS user is not in the user database")
	}
	uid, err := strconv.ParseUint(usr.Uid, 10, 32)
	require.NoError(t, err)
	gid, err := strconv.ParseUint(usr.Gid, 10, 32)
	require.NoError(t, err)
	assert.Equal(t, &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
		getSSHConfigUserCredential(uint32(uid), testSSHUnknownGID))
}

func TestGetSSHConfigCredential(t *testing.T) {
	if os.Geteuid() != 0 {
		for _, sshDir := range []string{filepath.Join(t.TempDir(), ".ssh"), "/", filepath.Join(t.TempDir(), "missing", ".ssh")} {
			cred, err := getSSHConfigCredential(sshDir)
			assert.NoError(t, err)
			assert.Nil(t, cred)
		}
		return
	}

	newSSHDir := func(t *testing.T, homeMode, sshDirMode os.FileMode) string {
		homeDir := newTestCleanupPath(t, filepath.Join(t.TempDir(), "home"), os.ModeDir|homeMode)
		return newTestCleanupPath(t, filepath.Join(homeDir, ".ssh"), os.ModeDir|sshDirMode)
	}

	for _, modes := range [][2]os.FileMode{{0700, 0700}, {0755, 0700}, {0755, 0755}} {
		cred, err := getSSHConfigCredential(newSSHDir(t, modes[0], modes[1]))
		assert.NoError(t, err, modes)
		assert.Nil(t, cred, modes)
	}

	for _, modes := range [][2]os.FileMode{
		{0775, 0700}, {0757, 0700}, {os.ModeSticky | 0777, 0700}, {0755, 0770}, {0755, 0707}, {0755, os.ModeSticky | 0777},
	} {
		cred, err := getSSHConfigCredential(newSSHDir(t, modes[0], modes[1]))
		assert.Error(t, err, modes)
		assert.False(t, os.IsNotExist(err), modes)
		assert.Nil(t, cred, modes)
	}

	_, err := getSSHConfigCredential(filepath.Join(t.TempDir(), "missing", ".ssh"))
	assert.True(t, os.IsNotExist(err))
	_, err = getSSHConfigCredential(filepath.Join(filepath.Dir(newSSHDir(t, 0700, 0700)), "missing"))
	assert.True(t, os.IsNotExist(err))

	sshDir := newSSHDir(t, 0777, 0777)
	require.NoError(t, os.Chown(filepath.Dir(sshDir), testSSHUnknownUID, testSSHUnknownGID))
	cred, err := getSSHConfigCredential(sshDir)
	require.NoError(t, err)
	assert.Equal(t, &syscall.Credential{Uid: testSSHUnknownUID, Gid: testSSHUnknownGID}, cred)

	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(filepath.Dir(sshDir), link))
	cred, err = getSSHConfigCredential(filepath.Join(link, ".ssh"))
	require.NoError(t, err)
	assert.Equal(t, &syscall.Credential{Uid: testSSHUnknownUID, Gid: testSSHUnknownGID}, cred)

	sshDir = newSSHDir(t, 0755, 0700)
	require.NoError(t, os.Chown(sshDir, testCleanupNobodyID, testSSHUnknownGID))
	cred, err = getSSHConfigCredential(sshDir)
	require.NoError(t, err)
	assert.Equal(t, getSSHConfigUserCredential(testCleanupNobodyID, testSSHUnknownGID), cred)
	assert.Equal(t, uint32(testCleanupNobodyID), cred.Uid)
}

func TestSSHConfigCmdOutput(t *testing.T) {
	output := &sshConfigCmdOutput{}
	n, err := output.Write([]byte("error"))
	assert.NoError(t, err)
	assert.Equal(t, 5, n)
	n, err = output.Write([]byte(strings.Repeat("a", 2*sshConfigCmdMaxOutput)))
	assert.NoError(t, err)
	assert.Equal(t, 2*sshConfigCmdMaxOutput, n)
	n, err = output.Write([]byte("b"))
	assert.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, sshConfigCmdMaxOutput, output.buf.Len())
	assert.True(t, strings.HasPrefix(output.buf.String(), "erroraaa"))
	assert.NotContains(t, output.buf.String(), "b")
}

func TestServiceConfigSSHAsOtherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root to manage the SSH config of another OS user")
	}

	const domain = "example.com"
	marker := managedMarkerPrefix + domain
	homeDir := newTestSSHUserHome(t, testCleanupNobodyID, testCleanupNobodyID)
	t.Setenv("OCTELIUM_USER_HOME", homeDir)
	sshDir := filepath.Join(homeDir, ".ssh")
	knownHosts := filepath.Join(sshDir, "known_hosts")
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	expectedGID := getSSHConfigUserCredential(testCleanupNobodyID, testCleanupNobodyID).Gid

	rootDir := t.TempDir()
	require.NoError(t, os.Chmod(rootDir, 0700))
	sentinel := filepath.Join(rootDir, "sentinel")
	victim := filepath.Join(rootDir, "victim")
	victimContent := fmt.Sprintf("root\n%s %s\n", testAuthorizedKeyLine(testOtherCAKey), marker)
	require.NoError(t, os.WriteFile(victim, []byte(victimContent), 0644))
	require.NoError(t, os.Symlink(sentinel, knownHosts))
	require.NoError(t, os.Symlink(victim, authorizedKeys))
	for _, filePath := range []string{knownHosts, authorizedKeys} {
		require.NoError(t, os.Lchown(filePath, testCleanupNobodyID, testCleanupNobodyID))
	}

	c := newTestSSHCtlForDomain(domain)
	assert.NoError(t, c.setServiceConfigs())
	assert.Error(t, c.unsetServiceConfigs())
	assert.Error(t, reconcileSSHCleanup(&cliconfigv1.ConnectionCleanup_SSH{
		Marker:    marker,
		FilePaths: []string{knownHosts, authorizedKeys},
	}))

	_, err := os.Lstat(sentinel)
	assert.True(t, os.IsNotExist(err), "root must not create files through the SSH directory of another user")
	b, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, victimContent, string(b), "root must not modify files through the SSH directory of another user")
	uid, gid := getFileOwner(t, victim)
	assert.Equal(t, uint32(0), uid)
	assert.Equal(t, uint32(0), gid)

	require.NoError(t, os.Remove(knownHosts))
	require.NoError(t, os.Remove(authorizedKeys))
	dotfilesDir := filepath.Join(homeDir, "dotfiles")
	require.NoError(t, os.Mkdir(dotfilesDir, 0700))
	dotKnownHosts := filepath.Join(dotfilesDir, "known_hosts")
	original := "example.net ssh-ed25519 AAAA\n"
	require.NoError(t, os.WriteFile(dotKnownHosts, []byte(original), 0640))
	require.NoError(t, os.Symlink(dotKnownHosts, knownHosts))
	for _, filePath := range []string{dotfilesDir, dotKnownHosts} {
		require.NoError(t, os.Chown(filePath, testCleanupNobodyID, testCleanupNobodyID))
	}
	require.NoError(t, os.Lchown(knownHosts, testCleanupNobodyID, testCleanupNobodyID))

	assertOwner := func(filePath string, mode os.FileMode) {
		t.Helper()
		fi, err := os.Lstat(filePath)
		require.NoError(t, err)
		assert.Equal(t, mode, fi.Mode().Perm(), filePath)
		uid, gid := getFileOwner(t, filePath)
		assert.Equal(t, uint32(testCleanupNobodyID), uid, filePath)
		assert.Equal(t, expectedGID, gid, filePath)
	}

	assert.NoError(t, c.setServiceConfigs())
	assert.Equal(t, 1, countLinesContaining(t, dotKnownHosts, marker))
	assert.Equal(t, 1, countLinesContaining(t, authorizedKeys, marker))
	fi, err := os.Lstat(knownHosts)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink, fi.Mode().Type())
	assertOwner(authorizedKeys, 0600)

	assert.NoError(t, c.unsetServiceConfigs())
	b, err = os.ReadFile(dotKnownHosts)
	require.NoError(t, err)
	assert.Equal(t, original, string(b))
	assert.Empty(t, readLines(t, authorizedKeys))
	fi, err = os.Lstat(knownHosts)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink, fi.Mode().Type())
	assertOwner(dotKnownHosts, 0640)
	assertOwner(authorizedKeys, 0600)
}

func TestSetManagedSSHConfigAsOtherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root to manage the SSH config of another OS user")
	}

	const domain = "example.com"
	marker := managedMarkerPrefix + domain
	homeDir := newTestSSHUserHome(t, testCleanupNobodyID, testCleanupNobodyID)
	t.Setenv("OCTELIUM_USER_HOME", homeDir)
	sshDir := filepath.Join(homeDir, ".ssh")
	knownHosts := filepath.Join(sshDir, "known_hosts")
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	expectedGID := getSSHConfigUserCredential(testCleanupNobodyID, testCleanupNobodyID).Gid

	assert.NoError(t, SetManagedSSHConfig(domain, knownHosts, []string{testKnownHostLine(testCAKey)}))
	assert.NoError(t, SetManagedSSHConfig(domain, authorizedKeys, []string{testAuthorizedKeyLine(testCAKey)}))

	for _, filePath := range []string{knownHosts, authorizedKeys} {
		assert.Equal(t, 1, countLinesContaining(t, filePath, marker), filePath)
		fi, err := os.Lstat(filePath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), fi.Mode().Perm(), filePath)
		uid, gid := getFileOwner(t, filePath)
		assert.Equal(t, uint32(testCleanupNobodyID), uid, filePath)
		assert.Equal(t, expectedGID, gid, filePath)
	}

	rootDir := t.TempDir()
	require.NoError(t, os.Chmod(rootDir, 0700))
	victim := filepath.Join(rootDir, "victim")
	require.NoError(t, os.WriteFile(victim, []byte("root\n"), 0644))
	require.NoError(t, os.Remove(authorizedKeys))
	require.NoError(t, os.Symlink(victim, authorizedKeys))
	require.NoError(t, os.Lchown(authorizedKeys, testCleanupNobodyID, testCleanupNobodyID))

	assert.Error(t, SetManagedSSHConfig(domain, authorizedKeys, []string{testAuthorizedKeyLine(testCAKey)}))
	b, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, "root\n", string(b), "root must not modify files through the SSH directory of another user")

	c := newTestSSHCtlForDomain(domain)
	assert.Error(t, c.unsetServiceConfigs())
	assert.Empty(t, readLines(t, knownHosts))
}

func TestServiceConfigSSHTrustUsersLookup(t *testing.T) {
	c := newTestSSHCtlForDomain("example.com")

	_, err := c.getSSHTrustUserFile("octelium-missing-user-7f3a")
	assert.EqualError(t, err, "The OS user does not exist")

	usr, err := user.Current()
	require.NoError(t, err)
	if !sshTrustUserRegex.MatchString(usr.Username) || !filepath.IsAbs(usr.HomeDir) {
		t.Skip("The current OS user cannot be used as an SSH trust user")
	}

	filePath, err := c.getSSHTrustUserFile(usr.Username)
	sshDir := filepath.Join(usr.HomeDir, ".ssh")
	if fi, statErr := os.Stat(sshDir); statErr == nil && fi.IsDir() {
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(sshDir, "authorized_keys"), filePath)
	} else {
		assert.Error(t, err)
		assert.Empty(t, filePath)
	}
}

func TestServiceConfigSSHTrustUsersPermissions(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the file permissions")
	}

	const domain = "example.com"
	marker := managedMarkerPrefix + domain

	_, sshDir := newTestSSHCtl(t, domain, true)
	noAccessHome, readOnlyHome, okHome := newTestSSHTrustHome(t), newTestSSHTrustHome(t), newTestSSHTrustHome(t)
	readOnlySSHDir := filepath.Join(readOnlyHome, ".ssh")
	require.NoError(t, os.Chmod(noAccessHome, 0))
	require.NoError(t, os.Chmod(readOnlySSHDir, 0500))
	t.Cleanup(func() {
		os.Chmod(noAccessHome, 0700)
		os.Chmod(readOnlySSHDir, 0700)
	})
	okKeys := filepath.Join(okHome, ".ssh", "authorized_keys")

	c := newTestSSHTrustCtl(domain, map[string]string{
		"noaccess": noAccessHome,
		"readonly": readOnlyHome,
		"ok":       okHome,
	}, "noaccess", "readonly", "ok")

	dbC, err := db.Open("memory")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, dbC.Close()) })
	c.dbC = dbC
	c.prepareCleanup()
	require.NotNil(t, c.cleanup)

	out := captureTestStdout(t, func() {
		assert.NoError(t, c.setServiceConfigs())
	})

	assert.Contains(t, out, fmt.Sprintf("Could not trust the Cluster SSH CA for the OS user noaccess: Could not access the SSH directory %s: ",
		filepath.Join(noAccessHome, ".ssh")))
	assert.Contains(t, out, fmt.Sprintf("Could not trust the Cluster SSH CA for the OS user readonly in %s: ",
		filepath.Join(readOnlySSHDir, "authorized_keys")))
	assert.Contains(t, out, "permission denied")
	assert.Contains(t, out, fmt.Sprintf("Trusted the Cluster SSH CA for the OS user ok in %s while connected\n", okKeys))
	assert.Equal(t, 1, countLinesContaining(t, okKeys, marker))
	assert.Equal(t, []string{okKeys}, c.sshTrustFilePaths)

	cleanup, err := dbC.GetConnectionCleanup(domain)
	require.NoError(t, err)
	assert.Equal(t, []string{
		filepath.Join(sshDir, "known_hosts"),
		filepath.Join(sshDir, "authorized_keys"),
		okKeys,
	}, cleanup.GetSsh().GetFilePaths())

	assert.NoError(t, c.unsetServiceConfigs())
	assert.Equal(t, 0, countLinesContaining(t, okKeys, marker))
}

func TestServiceConfigSSHTrustUsersAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root to manage the SSH config of other OS users")
	}

	const domain = "example.com"
	marker := managedMarkerPrefix + domain
	expectedGID := getSSHConfigUserCredential(testCleanupNobodyID, testCleanupNobodyID).Gid

	defaultHome := newTestSSHUserHome(t, testCleanupNobodyID, testCleanupNobodyID)
	t.Setenv("OCTELIUM_USER_HOME", defaultHome)
	rootHome := newTestSSHUserHome(t, 0, 0)
	usrHome := newTestSSHUserHome(t, testCleanupNobodyID, testCleanupNobodyID)
	victimHome := newTestSSHUserHome(t, testCleanupNobodyID, testCleanupNobodyID)

	rootDir := t.TempDir()
	require.NoError(t, os.Chmod(rootDir, 0700))
	victim := filepath.Join(rootDir, "victim")
	require.NoError(t, os.WriteFile(victim, []byte("root\n"), 0644))
	victimKeys := filepath.Join(victimHome, ".ssh", "authorized_keys")
	require.NoError(t, os.Symlink(victim, victimKeys))
	require.NoError(t, os.Lchown(victimKeys, testCleanupNobodyID, testCleanupNobodyID))

	rootKeys := filepath.Join(rootHome, ".ssh", "authorized_keys")
	usrKeys := filepath.Join(usrHome, ".ssh", "authorized_keys")
	defaultKeys := filepath.Join(defaultHome, ".ssh", "authorized_keys")

	c := newTestSSHTrustCtl(domain, map[string]string{
		"root":   rootHome,
		"usr":    usrHome,
		"victim": victimHome,
	}, "root", "victim", "usr")

	out := captureTestStdout(t, func() {
		assert.NoError(t, c.setServiceConfigs())
	})
	assert.Contains(t, out, fmt.Sprintf("Trusted the Cluster SSH CA for the OS user root in %s while connected\n", rootKeys))
	assert.Contains(t, out, fmt.Sprintf("Trusted the Cluster SSH CA for the OS user usr in %s while connected\n", usrKeys))
	assert.Contains(t, out, fmt.Sprintf("Could not trust the Cluster SSH CA for the OS user victim in %s: ", victimKeys))
	assert.Equal(t, []string{rootKeys, usrKeys}, c.sshTrustFilePaths)

	b, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, "root\n", string(b), "root must not modify files through the SSH directory of another user")

	assertFile := func(filePath string, uid, gid uint32) {
		t.Helper()
		assert.Equal(t, 1, countLinesContaining(t, filePath, marker), filePath)
		fi, err := os.Lstat(filePath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), fi.Mode().Perm(), filePath)
		fUID, fGID := getFileOwner(t, filePath)
		assert.Equal(t, uid, fUID, filePath)
		assert.Equal(t, gid, fGID, filePath)
	}

	assertFile(rootKeys, 0, 0)
	assertFile(usrKeys, testCleanupNobodyID, expectedGID)
	assertFile(defaultKeys, testCleanupNobodyID, expectedGID)

	assert.NoError(t, c.unsetServiceConfigs())
	for _, filePath := range []string{rootKeys, usrKeys, defaultKeys} {
		assert.Empty(t, readLines(t, filePath), filePath)
	}
	uid, gid := getFileOwner(t, usrKeys)
	assert.Equal(t, uint32(testCleanupNobodyID), uid)
	assert.Equal(t, expectedGID, gid)
}

func TestServiceConfigSSHTrustUsersOpenSSH(t *testing.T) {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh is not available")
	}
	var sshdPath string
	for _, arg := range []string{"sshd", "/usr/sbin/sshd"} {
		if ret, err := exec.LookPath(arg); err == nil {
			sshdPath = ret
			break
		}
	}
	if sshdPath == "" {
		t.Skip("sshd is not available")
	}

	usr, err := user.Current()
	require.NoError(t, err)
	if !sshTrustUserRegex.MatchString(usr.Username) {
		t.Skip("The current OS user cannot be used as an SSH trust user")
	}

	const domain = "example.com"
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0755))

	newSigner := func() (ssh.Signer, ed25519.PrivateKey) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signer, err := ssh.NewSignerFromKey(priv)
		require.NoError(t, err)
		return signer, priv
	}

	caSigner, _ := newSigner()
	hostSigner, hostPriv := newSigner()
	hostKeyPath := filepath.Join(dir, "host_key")
	block, err := ssh.MarshalPrivateKey(hostPriv, "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(hostKeyPath, pem.EncodeToMemory(block), 0600))
	knownHostsPath := filepath.Join(dir, "known_hosts")
	require.NoError(t, os.WriteFile(knownHostsPath,
		[]byte(fmt.Sprintf("[127.0.0.1]:* %s", ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))), 0644))

	userSigner, userPriv := newSigner()
	cert := &ssh.Certificate{
		Key:             userSigner.PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           usr.Username,
		ValidPrincipals: []string{usr.Username},
		ValidAfter:      uint64(time.Now().Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	require.NoError(t, cert.SignCert(rand.Reader, caSigner))
	userKeyPath := filepath.Join(dir, "id")
	block, err = ssh.MarshalPrivateKey(userPriv, "")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(userKeyPath, pem.EncodeToMemory(block), 0600))
	require.NoError(t, os.WriteFile(userKeyPath+"-cert.pub", ssh.MarshalAuthorizedKey(cert), 0644))

	homesDir := filepath.Join(dir, "homes")
	trustHome := filepath.Join(homesDir, usr.Username)
	require.NoError(t, os.MkdirAll(filepath.Join(trustHome, ".ssh"), 0700))
	defaultHome := newTestSSHTrustHome(t)
	t.Setenv("OCTELIUM_USER_HOME", defaultHome)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(lis.Addr().String())
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
AuthorizedKeysFile %s/%%u/.ssh/authorized_keys
`, port, hostKeyPath, homesDir)), 0644))

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
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
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

	runSSH := func(t *testing.T) (string, error) {
		t.Helper()
		out, err := exec.CommandContext(t.Context(), sshPath, "-F", "/dev/null",
			"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
			"-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
			"-o", fmt.Sprintf("UserKnownHostsFile=%s", knownHostsPath),
			"-i", userKeyPath, "-o", fmt.Sprintf("CertificateFile=%s-cert.pub", userKeyPath),
			"-p", port, fmt.Sprintf("%s@127.0.0.1", usr.Username), "echo upstream-ok").CombinedOutput()
		return string(out), err
	}

	newCtl := func(trustUsers ...string) *Controller {
		c := newTestSSHTrustCtl(domain, map[string]string{usr.Username: trustHome}, trustUsers...)
		c.c.Connection.ServiceConfigs[0].GetSsh().AuthorizedKeys = []string{
			fmt.Sprintf("cert-authority %s", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(caSigner.PublicKey())))),
		}
		return c
	}

	c := newCtl()
	captureTestStdout(t, func() {
		require.NoError(t, c.setServiceConfigs())
	})
	assert.Equal(t, 1, countLinesContaining(t, filepath.Join(defaultHome, ".ssh", "authorized_keys"), "cert-authority"))
	out, err := runSSH(t)
	require.Error(t, err, out)
	assert.Contains(t, out, "Permission denied")
	require.NoError(t, c.unsetServiceConfigs())

	c = newCtl(usr.Username)
	captureTestStdout(t, func() {
		require.NoError(t, c.setServiceConfigs())
	})
	out, err = runSSH(t)
	require.NoError(t, err, out)
	assert.Contains(t, out, "upstream-ok")

	require.NoError(t, c.unsetServiceConfigs())
	out, err = runSSH(t)
	require.Error(t, err, out)
	assert.Contains(t, out, "Permission denied")
	assert.NotContains(t, out, "upstream-ok")
}
