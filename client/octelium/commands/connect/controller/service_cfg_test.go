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
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/client/octelium/internal/userexec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	userexec.Init()
	os.Exit(m.Run())
}

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
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not support Unix file permissions")
	}
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not support Unix file permissions")
	}
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

func TestRunSSHConfigCmd(t *testing.T) {
	marker := "octelium-managed:example.com"
	sshDir := filepath.Join(t.TempDir(), ".ssh")
	require.NoError(t, os.Mkdir(sshDir, 0700))
	knownHostsPath := filepath.Join(sshDir, "known_hosts")
	line := testKnownHostLine(testCAKey)

	assert.NoError(t, runSSHConfigCmd(strings.NewReader(
		fmt.Sprintf(`{"filePath":%q,"marker":%q,"lines":[%q]}`, knownHostsPath, marker, line))))
	assert.Equal(t, []string{fmt.Sprintf("%s %s", line, marker)}, readLines(t, knownHostsPath))

	assert.NoError(t, runSSHConfigCmd(strings.NewReader(
		fmt.Sprintf(`{"filePath":%q,"marker":%q,"remove":true}`, knownHostsPath, marker))))
	assert.Empty(t, readLines(t, knownHostsPath))

	for _, req := range []string{
		"",
		"{",
		fmt.Sprintf(`{"filePath":%q,"marker":%q,"lines":[%q]}`, "known_hosts", marker, line),
		fmt.Sprintf(`{"filePath":%q,"marker":%q,"lines":[%q]}`, filepath.Join(sshDir, "config"), marker, line),
		fmt.Sprintf(`{"filePath":%q,"marker":%q,"lines":[%q]}`, filepath.Join(t.TempDir(), "known_hosts"), marker, line),
		fmt.Sprintf(`{"filePath":%q,"lines":[%q]}`, knownHostsPath, line),
		fmt.Sprintf(`{"filePath":%q,"marker":%q,"lines":[%q]}`, knownHostsPath, "example.com", line),
		fmt.Sprintf(`{"filePath":%q,"marker":%q,"lines":[%q]}`, knownHostsPath, marker+" x", line),
		fmt.Sprintf(`{"filePath":%q,"marker":%q,"lines":[%q]}`, knownHostsPath, marker+"\n"+line, line),
	} {
		assert.Error(t, runSSHConfigCmd(strings.NewReader(req)), req)
	}
	assert.Empty(t, readLines(t, knownHostsPath))
	_, err := os.Stat(filepath.Join(sshDir, "config"))
	assert.True(t, os.IsNotExist(err))
}

func TestDoSSHConfigOpWithoutSSHDir(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "missing", ".ssh", "known_hosts")
	marker := "octelium-managed:example.com"

	assert.NoError(t, doSSHConfigOp(&sshConfigOp{FilePath: filePath, Marker: marker, Remove: true}))
	assert.Error(t, doSSHConfigOp(&sshConfigOp{
		FilePath: filePath,
		Marker:   marker,
		Lines:    []string{testKnownHostLine(testCAKey)},
	}))
	_, err := os.Stat(filepath.Dir(filePath))
	assert.True(t, os.IsNotExist(err))
}

func TestSetManagedSSHConfig(t *testing.T) {
	c, sshDir := newTestSSHCtl(t, "example.com", true)
	authorizedKeysPath := path.Join(sshDir, "authorized_keys")
	knownHostsPath := path.Join(sshDir, "known_hosts")
	marker := "octelium-managed:example.com"

	userKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQtest user@laptop"
	otherClusterLine := fmt.Sprintf("%s octelium-managed:other.example.net",
		testAuthorizedKeyLine(testOtherCAKey))
	assert.Nil(t, os.WriteFile(authorizedKeysPath,
		[]byte(fmt.Sprintf("%s\n%s\n", userKey, otherClusterLine)), 0600))

	for i := 0; i < 3; i++ {
		assert.Nil(t, SetManagedSSHConfig("example.com", authorizedKeysPath,
			[]string{testAuthorizedKeyLine(testCAKey)}))
		assert.Nil(t, SetManagedSSHConfig("example.com", knownHostsPath,
			[]string{testKnownHostLine(testCAKey)}))
	}

	assert.Equal(t, []string{
		userKey,
		otherClusterLine,
		fmt.Sprintf("%s %s", testAuthorizedKeyLine(testCAKey), marker),
	}, readLines(t, authorizedKeysPath))
	assert.Equal(t, []string{
		fmt.Sprintf("%s %s", testKnownHostLine(testCAKey), marker),
	}, readLines(t, knownHostsPath))

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(knownHostsPath)
		assert.Nil(t, err)
		assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
	}

	assert.Nil(t, c.setServiceConfigs())
	for _, filePath := range []string{authorizedKeysPath, knownHostsPath} {
		assert.Equal(t, 1, countLinesContaining(t, filePath, testCAKey), filePath)
	}

	assert.Nil(t, c.unsetServiceConfigs())
	assert.Equal(t, []string{userKey, otherClusterLine}, readLines(t, authorizedKeysPath))
	assert.Empty(t, readLines(t, knownHostsPath))

	assert.Nil(t, c.setServiceConfigs())
	assert.Nil(t, SetManagedSSHConfig("example.com", authorizedKeysPath,
		[]string{testAuthorizedKeyLine(testCAKey), testAuthorizedKeyLine(testOtherCAKey)}))
	assert.Equal(t, 1, countLinesContaining(t, authorizedKeysPath, testCAKey))
	assert.Equal(t, 1, countLinesContaining(t, authorizedKeysPath, testOtherCAKey))

	assert.Nil(t, reconcileSSHCleanup(&cliconfigv1.ConnectionCleanup_SSH{
		Marker:    marker,
		FilePaths: []string{knownHostsPath, authorizedKeysPath},
	}))
	assert.Equal(t, []string{userKey, otherClusterLine}, readLines(t, authorizedKeysPath))
	assert.Empty(t, readLines(t, knownHostsPath))
}

func TestSetManagedSSHConfigInvalid(t *testing.T) {
	_, sshDir := newTestSSHCtl(t, "example.com", true)
	authorizedKeysPath := path.Join(sshDir, "authorized_keys")

	for _, domain := range []string{"", "example .com", "example.com\n", "\texample.com", "example.com\r"} {
		assert.Error(t, SetManagedSSHConfig(domain, authorizedKeysPath,
			[]string{testAuthorizedKeyLine(testCAKey)}), "%q", domain)
	}

	assert.Error(t, SetManagedSSHConfig("example.com", authorizedKeysPath,
		[]string{fmt.Sprintf("%s\n%s", testAuthorizedKeyLine(testCAKey), testAuthorizedKeyLine(testOtherCAKey))}))
	assert.Error(t, SetManagedSSHConfig("example.com",
		filepath.Join(t.TempDir(), "missing", ".ssh", "authorized_keys"),
		[]string{testAuthorizedKeyLine(testCAKey)}))

	_, err := os.Stat(authorizedKeysPath)
	assert.True(t, os.IsNotExist(err))

	assert.Nil(t, SetManagedSSHConfig("example.com", authorizedKeysPath, nil))
	assert.Nil(t, SetManagedSSHConfig("example.com", authorizedKeysPath, []string{"", " "}))
	_, err = os.Stat(authorizedKeysPath)
	assert.True(t, os.IsNotExist(err))
}

func TestGetManagedMarker(t *testing.T) {
	marker, err := newTestSSHCtlForDomain("example.com").getManagedMarker()
	assert.Nil(t, err)
	assert.Equal(t, "octelium-managed:example.com", marker)

	marker, err = getManagedMarkerFromDomain("example.com")
	assert.Nil(t, err)
	assert.Equal(t, "octelium-managed:example.com", marker)

	for _, domain := range []string{"", "example .com", "example.com\n"} {
		_, err := newTestSSHCtlForDomain(domain).getManagedMarker()
		assert.Error(t, err, "%q", domain)
		_, err = getManagedMarkerFromDomain(domain)
		assert.Error(t, err, "%q", domain)
	}

	_, err = (&Controller{c: &cliconfigv1.Connection{}}).getManagedMarker()
	assert.Error(t, err)
}

func TestSetManagedSSHConfigWaitsForLock(t *testing.T) {
	_, sshDir := newTestSSHCtl(t, "example.com", true)
	authorizedKeysPath := path.Join(sshDir, "authorized_keys")

	lock, err := acquireFileLock(sshConfigLockName)
	require.NoError(t, err)
	if lock == nil {
		t.Skip("There is no usable lock directory")
	}

	done := make(chan error, 1)
	go func() {
		done <- SetManagedSSHConfig("example.com", authorizedKeysPath, []string{testAuthorizedKeyLine(testCAKey)})
	}()

	select {
	case err := <-done:
		releaseFileLock(lock)
		t.Fatalf("SetManagedSSHConfig did not wait for the lock: %+v", err)
	case <-time.After(300 * time.Millisecond):
	}

	_, err = os.Stat(authorizedKeysPath)
	assert.True(t, os.IsNotExist(err))

	releaseFileLock(lock)
	require.NoError(t, <-done)
	assert.Equal(t, 1, countLinesContaining(t, authorizedKeysPath, testCAKey))
}

func newTestSSHTrustCtl(domain string, users map[string]string, trustUsers ...string) *Controller {
	c := newTestSSHCtlForDomain(domain)
	c.c.Preferences = &cliconfigv1.Connection_Preferences{
		ServeOpts: &cliconfigv1.Connection_Preferences_ServeOpts{
			IsEnabled: true,
			Ssh: &cliconfigv1.Connection_Preferences_ServeOpts_SSH{
				TrustUsers: trustUsers,
			},
		},
	}
	c.lookupUser = func(name string) (*user.User, error) {
		homeDir, ok := users[name]
		if !ok {
			return nil, user.UnknownUserError(name)
		}
		return &user.User{
			Username: name,
			HomeDir:  homeDir,
		}, nil
	}

	return c
}

func newTestSSHTrustHome(t *testing.T) string {
	t.Helper()
	homeDir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(homeDir, ".ssh"), 0700))
	return homeDir
}

func captureTestStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err)

	stdout, colorOutput := os.Stdout, color.Output
	os.Stdout, color.Output = w, w
	restore := func() {
		os.Stdout, color.Output = stdout, colorOutput
	}
	defer restore()

	outC := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		outC <- string(b)
	}()

	fn()
	restore()
	require.NoError(t, w.Close())

	return <-outC
}

func TestValidateSSHTrustUsers(t *testing.T) {
	for _, tc := range []struct {
		users []string
		want  []string
	}{
		{},
		{users: []string{}},
		{users: []string{"root"}, want: []string{"root"}},
		{users: []string{"root", " ubuntu ", "root", "ubuntu", "\troot"}, want: []string{"root", "ubuntu"}},
		{
			users: []string{"ec2-user", "_svc", "user.name", "alice@corp.example.com", "1000", "A_b-c.d"},
			want:  []string{"ec2-user", "_svc", "user.name", "alice@corp.example.com", "1000", "A_b-c.d"},
		},
		{users: []string{strings.Repeat("a", 256)}, want: []string{strings.Repeat("a", 256)}},
	} {
		got, err := ValidateSSHTrustUsers(tc.users)
		require.NoError(t, err, "%q", tc.users)
		assert.Equal(t, tc.want, got, "%q", tc.users)
	}

	for _, name := range []string{
		"", " ", "-root", ".", "..", "../root", ".ssh", "a/b", "/root", "a b", "a:b", "a,b",
		"a\nb", "a\x00b", `a\b`, "$root", "root$", "a*", "~root", strings.Repeat("a", 257),
	} {
		got, err := ValidateSSHTrustUsers([]string{"root", name})
		assert.ErrorContains(t, err, "Invalid SSH trust user", "%q", name)
		assert.Nil(t, got, "%q", name)
	}

	var users []string
	for i := 0; i < maxSSHTrustUsers; i++ {
		users = append(users, fmt.Sprintf("usr%d", i))
	}
	got, err := ValidateSSHTrustUsers(append(slices.Clone(users), users[0], " usr1"))
	require.NoError(t, err)
	assert.Equal(t, users, got)

	got, err = ValidateSSHTrustUsers(append(slices.Clone(users), "usr"))
	assert.ErrorContains(t, err, "Too many SSH trust users")
	assert.Nil(t, got)
}

func TestServiceConfigSSHTrustUsers(t *testing.T) {
	const domain = "example.com"
	marker := managedMarkerPrefix + domain
	managedLine := fmt.Sprintf("%s %s", testAuthorizedKeyLine(testCAKey), marker)

	_, sshDir := newTestSSHCtl(t, domain, true)
	rootHome, usrHome := newTestSSHTrustHome(t), newTestSSHTrustHome(t)
	c := newTestSSHTrustCtl(domain, map[string]string{
		"root": rootHome,
		"usr1": usrHome,
	}, "root", "usr1")

	rootKeys := filepath.Join(rootHome, ".ssh", "authorized_keys")
	usrKeys := filepath.Join(usrHome, ".ssh", "authorized_keys")
	adminKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdmin admin@laptop"
	require.NoError(t, os.WriteFile(rootKeys, []byte(adminKey+"\n"), 0600))

	out := captureTestStdout(t, func() {
		for i := 0; i < 3; i++ {
			assert.NoError(t, c.setServiceConfigs())
		}
	})

	assert.Equal(t, []string{adminKey, managedLine}, readLines(t, rootKeys))
	assert.Equal(t, []string{managedLine}, readLines(t, usrKeys))
	for _, homeDir := range []string{rootHome, usrHome} {
		_, err := os.Stat(filepath.Join(homeDir, ".ssh", "known_hosts"))
		assert.True(t, os.IsNotExist(err), homeDir)
	}
	for _, name := range []string{"known_hosts", "authorized_keys"} {
		assert.Equal(t, 1, countLinesContaining(t, filepath.Join(sshDir, name), marker), name)
	}
	assert.Equal(t, []string{rootKeys, usrKeys}, c.sshTrustFilePaths)
	assert.Equal(t, 3, strings.Count(out, fmt.Sprintf("Trusted the Cluster SSH CA for the OS user root in %s while connected\n", rootKeys)))
	assert.Equal(t, 3, strings.Count(out, fmt.Sprintf("Trusted the Cluster SSH CA for the OS user usr1 in %s while connected\n", usrKeys)))
	assert.NotContains(t, out, "Could not")

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(usrKeys)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
	}

	assert.NoError(t, c.unsetServiceConfigs())
	assert.Equal(t, []string{adminKey}, readLines(t, rootKeys))
	assert.Empty(t, readLines(t, usrKeys))
	for _, name := range []string{"known_hosts", "authorized_keys"} {
		assert.Equal(t, 0, countLinesContaining(t, filepath.Join(sshDir, name), marker), name)
	}

	assert.NoError(t, c.unsetServiceConfigs())
	assert.Equal(t, []string{adminKey}, readLines(t, rootKeys))
}

func TestServiceConfigSSHTrustUsersWarnings(t *testing.T) {
	const domain = "example.com"
	marker := managedMarkerPrefix + domain

	_, sshDir := newTestSSHCtl(t, domain, true)
	okHome, keysDirHome := newTestSSHTrustHome(t), newTestSSHTrustHome(t)
	noSSHHome, sshFileHome := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(sshFileHome, ".ssh"), nil, 0600))
	keysDir := filepath.Join(keysDirHome, ".ssh", "authorized_keys")
	require.NoError(t, os.Mkdir(keysDir, 0700))
	okKeys := filepath.Join(okHome, ".ssh", "authorized_keys")

	c := newTestSSHTrustCtl(domain, map[string]string{
		"ok":      okHome,
		"nohome":  "",
		"relhome": "home/relhome",
		"nossh":   noSSHHome,
		"sshfile": sshFileHome,
		"keysdir": keysDirHome,
	}, "missing", "nohome", "relhome", "nossh", "sshfile", "lookuperr", "bad/name", "keysdir", "ok")
	lookupUser := c.lookupUser
	c.lookupUser = func(name string) (*user.User, error) {
		if name == "lookuperr" {
			return nil, errors.New("user database is unavailable")
		}
		return lookupUser(name)
	}

	dbC, err := db.Open("memory")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, dbC.Close()) })
	c.dbC = dbC
	c.prepareCleanup()
	require.NotNil(t, c.cleanup)

	out := captureTestStdout(t, func() {
		assert.NoError(t, c.setServiceConfigs())
	})

	for _, msg := range []string{
		"Could not trust the Cluster SSH CA for the OS user missing: The OS user does not exist\n",
		"Could not trust the Cluster SSH CA for the OS user nohome: The OS user does not have a valid home directory: \"\"\n",
		"Could not trust the Cluster SSH CA for the OS user relhome: The OS user does not have a valid home directory: \"home/relhome\"\n",
		fmt.Sprintf("Could not trust the Cluster SSH CA for the OS user nossh: The SSH directory %s does not exist\n",
			filepath.Join(noSSHHome, ".ssh")),
		fmt.Sprintf("Could not trust the Cluster SSH CA for the OS user sshfile: The SSH directory %s is not a directory\n",
			filepath.Join(sshFileHome, ".ssh")),
		"Could not trust the Cluster SSH CA for the OS user lookuperr: Could not find the OS user: user database is unavailable\n",
		"Could not trust the Cluster SSH CA for the OS user bad/name: Invalid OS user name\n",
		fmt.Sprintf("Could not trust the Cluster SSH CA for the OS user keysdir in %s: ", keysDir),
		fmt.Sprintf("Trusted the Cluster SSH CA for the OS user ok in %s while connected\n", okKeys),
	} {
		assert.Equal(t, 1, strings.Count(out, msg), "%q not in %q", msg, out)
	}
	assert.Equal(t, 1, strings.Count(out, "Trusted the Cluster SSH CA"))

	assert.Equal(t, []string{fmt.Sprintf("%s %s", testAuthorizedKeyLine(testCAKey), marker)}, readLines(t, okKeys))
	_, err = os.Stat(filepath.Join(noSSHHome, ".ssh"))
	assert.True(t, os.IsNotExist(err))
	fi, err := os.Stat(keysDir)
	require.NoError(t, err)
	assert.True(t, fi.IsDir())
	assert.Equal(t, []string{okKeys}, c.sshTrustFilePaths)

	cleanup, err := dbC.GetConnectionCleanup(domain)
	require.NoError(t, err)
	assert.Equal(t, marker, cleanup.GetSsh().GetMarker())
	assert.Equal(t, []string{
		filepath.Join(sshDir, "known_hosts"),
		filepath.Join(sshDir, "authorized_keys"),
		okKeys,
	}, cleanup.GetSsh().GetFilePaths())

	assert.NoError(t, c.unsetServiceConfigs())
	assert.Empty(t, readLines(t, okKeys))
	assert.NoError(t, reconcileSSHCleanup(cleanup.GetSsh()))
}

func TestServiceConfigSSHTrustUsersCleanupRecord(t *testing.T) {
	const domain = "example.com"
	marker := managedMarkerPrefix + domain

	_, sshDir := newTestSSHCtl(t, domain, true)
	rootHome := newTestSSHTrustHome(t)
	rootKeys := filepath.Join(rootHome, ".ssh", "authorized_keys")
	c := newTestSSHTrustCtl(domain, map[string]string{"root": rootHome}, "root")

	dbC, err := db.Open("memory")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, dbC.Close()) })
	c.dbC = dbC
	c.prepareCleanup()
	require.NotNil(t, c.cleanup)

	captureTestStdout(t, func() {
		assert.NoError(t, c.setServiceConfigs())
	})
	assert.Equal(t, 1, countLinesContaining(t, rootKeys, marker))

	cleanup, err := dbC.GetConnectionCleanup(domain)
	require.NoError(t, err)
	filePaths := []string{
		filepath.Join(sshDir, "known_hosts"),
		filepath.Join(sshDir, "authorized_keys"),
		rootKeys,
	}
	assert.Equal(t, filePaths, cleanup.GetSsh().GetFilePaths())

	sanitizeConnectionCleanup(cleanup, domain)
	assert.Equal(t, filePaths, cleanup.GetSsh().GetFilePaths())

	assert.NoError(t, reconcileSSHCleanup(cleanup.GetSsh()))
	for _, filePath := range filePaths {
		assert.Equal(t, 0, countLinesContaining(t, filePath, marker), filePath)
	}
}

func TestServiceConfigSSHTrustUsersWithoutDefaultSSHDir(t *testing.T) {
	const domain = "example.com"
	marker := managedMarkerPrefix + domain

	_, sshDir := newTestSSHCtl(t, domain, false)
	rootHome := newTestSSHTrustHome(t)
	rootKeys := filepath.Join(rootHome, ".ssh", "authorized_keys")
	c := newTestSSHTrustCtl(domain, map[string]string{"root": rootHome}, "root")

	dbC, err := db.Open("memory")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, dbC.Close()) })
	c.dbC = dbC
	c.prepareCleanup()

	out := captureTestStdout(t, func() {
		assert.NoError(t, c.setServiceConfigs())
	})
	assert.Contains(t, out, "Trusted the Cluster SSH CA for the OS user root")
	assert.Equal(t, 1, countLinesContaining(t, rootKeys, marker))
	_, err = os.Stat(sshDir)
	assert.True(t, os.IsNotExist(err))

	cleanup, err := dbC.GetConnectionCleanup(domain)
	require.NoError(t, err)
	assert.Equal(t, []string{rootKeys}, cleanup.GetSsh().GetFilePaths())

	assert.NoError(t, c.unsetServiceConfigs())
	assert.Equal(t, 0, countLinesContaining(t, rootKeys, marker))
	_, err = os.Stat(sshDir)
	assert.True(t, os.IsNotExist(err))
}

func TestServiceConfigSSHTrustUsersSameFile(t *testing.T) {
	const domain = "example.com"
	marker := managedMarkerPrefix + domain

	_, sshDir := newTestSSHCtl(t, domain, true)
	rootHome := newTestSSHTrustHome(t)
	rootKeys := filepath.Join(rootHome, ".ssh", "authorized_keys")
	defaultKeys := filepath.Join(sshDir, "authorized_keys")
	c := newTestSSHTrustCtl(domain, map[string]string{
		"root":  rootHome,
		"toor":  rootHome,
		"alice": filepath.Dir(sshDir),
	}, "alice", "root", "toor")

	out := captureTestStdout(t, func() {
		assert.NoError(t, c.setServiceConfigs())
	})
	assert.Equal(t, 1, countLinesContaining(t, defaultKeys, marker))
	assert.Equal(t, 1, countLinesContaining(t, rootKeys, marker))
	assert.Equal(t, []string{rootKeys}, c.sshTrustFilePaths)
	assert.Equal(t, 1, strings.Count(out, "Trusted the Cluster SSH CA"))
	assert.NotContains(t, out, "Could not")

	assert.NoError(t, c.unsetServiceConfigs())
	assert.Equal(t, 0, countLinesContaining(t, defaultKeys, marker))
	assert.Equal(t, 0, countLinesContaining(t, rootKeys, marker))
}

func TestServiceConfigSSHTrustUsersIgnored(t *testing.T) {
	const domain = "example.com"

	_, sshDir := newTestSSHCtl(t, domain, true)
	rootHome := newTestSSHTrustHome(t)
	rootKeys := filepath.Join(rootHome, ".ssh", "authorized_keys")

	for _, tc := range []struct {
		name string
		fn   func(c *Controller)
		out  string
	}{
		{
			name: "NotServing",
			fn: func(c *Controller) {
				c.c.Preferences.ServeOpts.IsEnabled = false
			},
		},
		{
			name: "NoServeOpts",
			fn: func(c *Controller) {
				c.c.Preferences.ServeOpts = nil
			},
		},
		{
			name: "NoTrustUsers",
			fn: func(c *Controller) {
				c.c.Preferences.ServeOpts.Ssh = nil
			},
		},
		{
			name: "NoAuthorizedKeys",
			fn: func(c *Controller) {
				c.c.Connection.ServiceConfigs[0].GetSsh().AuthorizedKeys = nil
			},
		},
		{
			name: "NoClusterSSHConfig",
			fn: func(c *Controller) {
				c.c.Connection.ServiceConfigs = nil
			},
			out: "The Cluster did not provide its SSH CA. Could not trust it for the OS users: root, usr1\n",
		},
		{
			name: "NoClusterSSHConfigNotServing",
			fn: func(c *Controller) {
				c.c.Connection.ServiceConfigs = nil
				c.c.Preferences.ServeOpts.IsEnabled = false
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestSSHTrustCtl(domain, map[string]string{"root": rootHome}, "root", "usr1")
			tc.fn(c)

			out := captureTestStdout(t, func() {
				assert.NoError(t, c.setServiceConfigs())
			})
			assert.Equal(t, tc.out, out)
			assert.Empty(t, c.sshTrustFilePaths)
			_, err := os.Stat(rootKeys)
			assert.True(t, os.IsNotExist(err))

			assert.NoError(t, c.unsetServiceConfigs())
			for _, name := range []string{"known_hosts", "authorized_keys"} {
				assert.Equal(t, 0, countLinesContaining(t, filepath.Join(sshDir, name), managedMarkerPrefix), name)
			}
		})
	}
}
