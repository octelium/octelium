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

package connect

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSystemdVersion(t *testing.T) {
	for _, tc := range []struct {
		arg      string
		expected int
	}{
		{"systemd 219\n+PAM +AUDIT +SELINUX +IMA", 219},
		{"systemd 237\n+PAM +AUDIT +SELINUX +IMA", 237},
		{"systemd 239 (239-82.el8_10.19)\n+PAM +AUDIT", 239},
		{"systemd 245 (245.4-4ubuntu3.24)\n+PAM +AUDIT", 245},
		{"systemd 262 (262.1-1-arch)\n+PAM +AUDIT", 262},
		{"", 0},
		{"systemd", 0},
		{"systemd abc", 0},
		{"systemd 257~rc1 (257~rc1-1)", 0},
		{"systemd -1", 0},
		{"busybox 245", 0},
	} {
		assert.Equal(t, tc.expected, parseSystemdVersion(tc.arg), "arg=%q", tc.arg)
	}
}

func TestGetSystemdUnitName(t *testing.T) {
	assert.Equal(t, "octelium-connect-example.com.service", getSystemdUnitName("example.com"))
	assert.Equal(t, "octelium-connect-sub-1.example_x.com.service", getSystemdUnitName("Sub-1.Example_X.COM"))

	for _, domain := range []string{
		"", "example.com:8443", "example com", "exämple.com", "Kexample.com", `example\x2ecom`,
		"example.com/x", "example@com",
	} {
		assert.Equal(t, "", getSystemdUnitName(domain), "domain=%q", domain)
	}

	maxDomain := strings.Repeat("a", maxSystemdUnitNameLen-len("octelium-connect-.service"))
	assert.Equal(t, fmt.Sprintf("octelium-connect-%s.service", maxDomain), getSystemdUnitName(maxDomain))
	assert.Equal(t, "", getSystemdUnitName(maxDomain+"a"))
}

func TestGetSystemdRunArgs(t *testing.T) {
	octeliumCmd := []string{"/usr/bin/octelium", "connect", "--domain=example.com", "--homedir=/home/user/.config/octelium"}
	env := map[string]string{
		"OCTELIUM_USER_HOME": "/home/user",
		"OCTELIUM_A":         `a "b" \c`,
	}
	envArgs := []string{
		"-p", `Environment="OCTELIUM_A=a \"b\" \\c"`,
		"-p", `Environment="OCTELIUM_USER_HOME=/home/user"`,
	}
	managedArgs := []string{
		"systemd-run", "--unit=octelium-connect-example.com.service",
		"--description=Octelium connection for example.com", "--collect",
		"-p", "User=root", "-p", "Restart=on-failure",
	}

	for _, version := range []int{0, 219, 235} {
		assert.Equal(t,
			slices.Concat([]string{"systemd-run", "-p", "User=root", "-p", "Restart=on-failure"}, envArgs, octeliumCmd),
			getSystemdRunArgs(version, "example.com", octeliumCmd, env), "version=%d", version)
	}

	for _, version := range []int{236, 242} {
		assert.Equal(t,
			slices.Concat(managedArgs, envArgs, octeliumCmd),
			getSystemdRunArgs(version, "example.com", octeliumCmd, env), "version=%d", version)
	}

	for _, version := range []int{243, 262} {
		assert.Equal(t,
			slices.Concat(managedArgs, []string{"-p", "OOMPolicy=continue"}, envArgs, octeliumCmd),
			getSystemdRunArgs(version, "example.com", octeliumCmd, env), "version=%d", version)
	}

	assert.Equal(t,
		slices.Concat([]string{
			"systemd-run", "--description=Octelium connection for example.com:8443", "--collect",
			"-p", "User=root", "-p", "Restart=on-failure", "-p", "OOMPolicy=continue",
		}, octeliumCmd),
		getSystemdRunArgs(262, "example.com:8443", octeliumCmd, nil))
}

func TestEscapeSystemdQuoted(t *testing.T) {
	assert.Equal(t, "", escapeSystemdQuoted(""))
	assert.Equal(t, "A=/home/user name", escapeSystemdQuoted("A=/home/user name"))
	assert.Equal(t, `A=\"a\" 'b' \\n \\\" $HOME %h`, escapeSystemdQuoted(`A="a" 'b' \n \" $HOME %h`))
}

func TestRunSystemdDetached(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to run systemd-run")
	}

	if st, err := os.Stat("/run/systemd/system"); err != nil || !st.IsDir() {
		t.Skip("systemd is not running")
	}

	version := getSystemdVersion()
	if version < systemdVersionCollect {
		t.Skipf("systemd %d does not get a named unit", version)
	}

	dir := t.TempDir()
	environPath := filepath.Join(dir, "environ")

	scriptPath := filepath.Join(dir, "octelium")
	require.NoError(t, os.WriteFile(scriptPath,
		[]byte("#!/bin/sh\ncat /proc/$$/environ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"\nexec sleep 600\n"), 0755))

	failingScriptPath := filepath.Join(dir, "octelium-failing")
	require.NoError(t, os.WriteFile(failingScriptPath, []byte("#!/bin/sh\nexit 1\n"), 0755))

	domain := fmt.Sprintf("test-%d.example.com", time.Now().UnixNano())
	unitName := getSystemdUnitName(domain)
	require.NotEmpty(t, unitName)

	t.Cleanup(func() {
		exec.Command("systemctl", "stop", unitName).Run()
		exec.Command("systemctl", "reset-failed", unitName).Run()
	})

	env := map[string]string{
		"OCTELIUM_TEST_SPACES":    " a b  c ",
		"OCTELIUM_TEST_QUOTES":    `"a" 'b' "`,
		"OCTELIUM_TEST_BACKSLASH": `a\b\\c\n\x41\"\`,
		"OCTELIUM_TEST_SPECIAL":   `$HOME ${HOME} %h %% ; | & é`,
		"OCTELIUM_TEST_EMPTY":     "",
	}

	runSystemd := func(octeliumCmd ...string) error {
		out, err := exec.Command("systemd-run",
			getSystemdRunArgs(version, domain, octeliumCmd, env)[1:]...).CombinedOutput()
		if err != nil {
			return errors.Errorf("%s: %+v", string(out), err)
		}
		return nil
	}

	getUnitProperty := func(name string) string {
		out, _ := exec.Command("systemctl", "show", "-p", name, unitName).Output()
		return strings.TrimPrefix(strings.TrimSpace(string(out)), name+"=")
	}

	isCollected := func() bool {
		return getUnitProperty("LoadState") == "not-found"
	}

	require.NoError(t, runSystemd(scriptPath, environPath))

	require.Eventually(t, func() bool {
		_, err := os.Stat(environPath)
		return err == nil
	}, 30*time.Second, 50*time.Millisecond)

	environ, err := os.ReadFile(environPath)
	require.NoError(t, err)

	childEnv := make(map[string]string)
	for _, envVar := range strings.Split(string(environ), "\x00") {
		if k, v, ok := strings.Cut(envVar, "="); ok && strings.HasPrefix(k, "OCTELIUM_TEST_") {
			childEnv[k] = v
		}
	}
	assert.Equal(t, env, childEnv)

	assert.Equal(t, "active", getUnitProperty("ActiveState"))
	assert.Equal(t, "on-failure", getUnitProperty("Restart"))
	assert.Equal(t, "root", getUnitProperty("User"))
	assert.Equal(t, fmt.Sprintf("Octelium connection for %s", domain), getUnitProperty("Description"))
	assert.Equal(t, "inactive-or-failed", getUnitProperty("CollectMode"))

	assert.Equal(t, "simple", getUnitProperty("Type"))

	if version >= systemdVersionOOMPolicy {
		assert.Equal(t, "continue", getUnitProperty("OOMPolicy"))
	}

	assert.NotNil(t, runSystemd(scriptPath, environPath))
	assert.Equal(t, "active", getUnitProperty("ActiveState"))

	require.NoError(t, exec.Command("systemctl", "stop", unitName).Run())
	require.Eventually(t, isCollected, 30*time.Second, 50*time.Millisecond)

	require.NoError(t, runSystemd(failingScriptPath))
	require.Eventually(t, isCollected, 30*time.Second, 50*time.Millisecond)

	require.NoError(t, runSystemd(scriptPath, environPath))
	assert.Equal(t, "active", getUnitProperty("ActiveState"))

	require.NoError(t, exec.Command("systemctl", "stop", unitName).Run())
	require.Eventually(t, isCollected, 30*time.Second, 50*time.Millisecond)
}
