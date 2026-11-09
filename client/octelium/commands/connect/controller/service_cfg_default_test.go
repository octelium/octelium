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
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
