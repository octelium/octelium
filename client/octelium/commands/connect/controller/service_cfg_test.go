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
	"path"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
)

const (
	testCAKey      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6mZ0Ck0dPl0hLQ1nLnLnQ0Q1lQ0lQ0lQ0lQ0lQ0lQ0"
	testOtherCAKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAaZaZaZaZaZaZaZaZaZaZaZaZaZaZaZaZaZaZaZaZaZ"
)

func testAuthorizedKeyLine(k string) string {
	return fmt.Sprintf("cert-authority %s", k)
}

func testKnownHostLine(k string) string {
	return fmt.Sprintf("@cert-authority * %s", k)
}

func newTestSSHCtl(t *testing.T, domain string, hasSSHDir bool) (*Controller, string) {
	homeDir := t.TempDir()
	t.Setenv("OCTELIUM_USER_HOME", homeDir)

	sshDir := path.Join(homeDir, ".ssh")
	if hasSSHDir {
		assert.Nil(t, os.MkdirAll(sshDir, 0700))
	}

	return newTestSSHCtlForDomain(domain), sshDir
}

func newTestSSHCtlForDomain(domain string) *Controller {
	return &Controller{
		c: &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				ServiceConfigs: []*userv1.ConnectionState_ServiceConfig{
					{
						Type: &userv1.ConnectionState_ServiceConfig_Ssh{
							Ssh: &userv1.ConnectionState_ServiceConfig_SSH{
								KnownHosts:     []string{testKnownHostLine(testCAKey)},
								AuthorizedKeys: []string{testAuthorizedKeyLine(testCAKey)},
							},
						},
					},
				},
			},
			Info: &cliconfigv1.Connection_Info{
				Cluster: &cliconfigv1.Connection_Info_Cluster{
					Domain: domain,
				},
			},
		},
	}
}

func readLines(t *testing.T, filePath string) []string {
	b, err := os.ReadFile(filePath)
	assert.Nil(t, err)

	var ret []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			ret = append(ret, line)
		}
	}

	return ret
}

func countLinesContaining(t *testing.T, filePath, substr string) int {
	var ret int
	for _, line := range readLines(t, filePath) {
		if strings.Contains(line, substr) {
			ret++
		}
	}

	return ret
}

func TestServiceConfigSSHSetAndUnset(t *testing.T) {
	c, sshDir := newTestSSHCtl(t, "example.com", true)

	authorizedKeysPath := path.Join(sshDir, "authorized_keys")
	knownHostsPath := path.Join(sshDir, "known_hosts")

	assert.Nil(t, c.setServiceConfigs())

	for _, filePath := range []string{authorizedKeysPath, knownHostsPath} {
		assert.Equal(t, 1, countLinesContaining(t, filePath, testCAKey))
		assert.Equal(t, 1, countLinesContaining(t, filePath, "octelium-managed:example.com"))
	}

	for _, filePath := range []string{authorizedKeysPath, knownHostsPath} {
		for _, line := range readLines(t, filePath) {
			assert.True(t, isManagedLine(line, "octelium-managed:example.com"),
				"unmarked line written to %s: %q", filePath, line)
		}
	}

	assert.Nil(t, c.unsetServiceConfigs())

	for _, filePath := range []string{authorizedKeysPath, knownHostsPath} {
		assert.Equal(t, 0, countLinesContaining(t, filePath, testCAKey))
	}
}

func TestServiceConfigSSHIsIdempotent(t *testing.T) {
	c, sshDir := newTestSSHCtl(t, "example.com", true)
	authorizedKeysPath := path.Join(sshDir, "authorized_keys")

	for i := 0; i < 5; i++ {
		assert.Nil(t, c.setServiceConfigs())
		assert.Equal(t, 1, countLinesContaining(t, authorizedKeysPath, testCAKey),
			"duplicate entry after %d calls", i+1)
	}
}

func TestServiceConfigSSHReAddedOnReconnect(t *testing.T) {
	c, sshDir := newTestSSHCtl(t, "example.com", true)
	authorizedKeysPath := path.Join(sshDir, "authorized_keys")

	for i := 0; i < 3; i++ {
		assert.Nil(t, c.setServiceConfigs())
		assert.Equal(t, 1, countLinesContaining(t, authorizedKeysPath, testCAKey),
			"entry missing after reconnect %d", i)

		assert.Nil(t, c.unsetServiceConfigs())
		assert.Equal(t, 0, countLinesContaining(t, authorizedKeysPath, testCAKey),
			"entry not removed on close %d", i)
	}

	assert.Nil(t, c.setServiceConfigs())
	assert.Equal(t, 1, countLinesContaining(t, authorizedKeysPath, testCAKey))
}

func TestServiceConfigSSHKeepsUserEntries(t *testing.T) {
	c, sshDir := newTestSSHCtl(t, "example.com", true)
	authorizedKeysPath := path.Join(sshDir, "authorized_keys")

	userKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQtest user@laptop"
	otherClusterLine := fmt.Sprintf("%s octelium-managed:other.example.net",
		testAuthorizedKeyLine(testOtherCAKey))

	assert.Nil(t, os.WriteFile(authorizedKeysPath,
		[]byte(fmt.Sprintf("# my keys\n%s\n%s", otherClusterLine, userKey)), 0600))

	assert.Nil(t, c.setServiceConfigs())
	assert.Nil(t, c.unsetServiceConfigs())

	lines := readLines(t, authorizedKeysPath)
	assert.Equal(t, 3, len(lines), "lines: %q", lines)
	assert.Equal(t, "# my keys", lines[0])
	assert.Equal(t, otherClusterLine, lines[1])
	assert.Equal(t, userKey, lines[2])
}

func TestServiceConfigSSHKeepsPreExistingCA(t *testing.T) {
	c, sshDir := newTestSSHCtl(t, "example.com", true)
	authorizedKeysPath := path.Join(sshDir, "authorized_keys")

	preExisting := testAuthorizedKeyLine(testCAKey)
	assert.Nil(t, os.WriteFile(authorizedKeysPath, []byte(preExisting+"\n"), 0600))

	assert.Nil(t, c.setServiceConfigs())
	assert.Equal(t, 0, countLinesContaining(t, authorizedKeysPath, "octelium-managed:"))

	assert.Nil(t, c.unsetServiceConfigs())

	lines := readLines(t, authorizedKeysPath)
	assert.Equal(t, []string{preExisting}, lines)
}

func TestServiceConfigSSHRemovesStaleEntry(t *testing.T) {
	c, sshDir := newTestSSHCtl(t, "example.com", true)
	authorizedKeysPath := path.Join(sshDir, "authorized_keys")

	stale := fmt.Sprintf("%s octelium-managed:example.com", testAuthorizedKeyLine(testCAKey))
	assert.Nil(t, os.WriteFile(authorizedKeysPath, []byte(stale+"\n"), 0600))

	assert.Nil(t, c.setServiceConfigs())
	assert.Equal(t, 1, countLinesContaining(t, authorizedKeysPath, testCAKey),
		"the stale entry got duplicated")

	assert.Nil(t, c.unsetServiceConfigs())
	assert.Equal(t, 0, countLinesContaining(t, authorizedKeysPath, testCAKey))
}

func TestServiceConfigSSHNoSSHDir(t *testing.T) {
	c, sshDir := newTestSSHCtl(t, "example.com", false)

	assert.Nil(t, c.setServiceConfigs())
	assert.Nil(t, c.unsetServiceConfigs())

	_, err := os.Stat(sshDir)
	assert.True(t, os.IsNotExist(err))
}

func TestServiceConfigSSHRejectsMultiLineEntry(t *testing.T) {
	c, sshDir := newTestSSHCtl(t, "example.com", true)
	authorizedKeysPath := path.Join(sshDir, "authorized_keys")

	injected := fmt.Sprintf("%s\n%s", testAuthorizedKeyLine(testCAKey),
		testAuthorizedKeyLine(testOtherCAKey))
	c.c.Connection.ServiceConfigs[0].GetSsh().AuthorizedKeys = []string{injected}

	assert.Nil(t, c.setServiceConfigs())

	_, err := os.Stat(authorizedKeysPath)
	assert.True(t, os.IsNotExist(err))
}

func TestServiceConfigSSHPreservesFileMode(t *testing.T) {
	c, sshDir := newTestSSHCtl(t, "example.com", true)
	authorizedKeysPath := path.Join(sshDir, "authorized_keys")

	assert.Nil(t, os.WriteFile(authorizedKeysPath, []byte("# my keys\n"), 0640))

	assert.Nil(t, c.setServiceConfigs())
	assert.Nil(t, c.unsetServiceConfigs())

	fi, err := os.Stat(authorizedKeysPath)
	assert.Nil(t, err)
	assert.Equal(t, os.FileMode(0640), fi.Mode().Perm())
}

func TestServiceConfigSSHCreatesFileNotWorldReadable(t *testing.T) {
	c, sshDir := newTestSSHCtl(t, "example.com", true)

	assert.Nil(t, c.setServiceConfigs())

	for _, name := range []string{"authorized_keys", "known_hosts"} {
		fi, err := os.Stat(path.Join(sshDir, name))
		assert.Nil(t, err)
		assert.Equal(t, os.FileMode(0), fi.Mode().Perm()&0o077)
	}
}

func TestIsManagedLine(t *testing.T) {
	marker := "octelium-managed:example.com"

	assert.True(t, isManagedLine(
		fmt.Sprintf("%s %s", testAuthorizedKeyLine(testCAKey), marker), marker))
	assert.True(t, isManagedLine(
		fmt.Sprintf("%s %s  \t", testAuthorizedKeyLine(testCAKey), marker), marker))
	assert.True(t, isManagedLine(
		fmt.Sprintf("%s %s\r", testAuthorizedKeyLine(testCAKey), marker), marker))

	assert.False(t, isManagedLine(testAuthorizedKeyLine(testCAKey), marker))
	assert.False(t, isManagedLine(
		fmt.Sprintf("%s octelium-managed:other.example.net", testAuthorizedKeyLine(testCAKey)),
		marker))
	assert.False(t, isManagedLine(
		fmt.Sprintf("%s %s trailing", testAuthorizedKeyLine(testCAKey), marker), marker))
}
