//go:build linux || darwin

package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testOSCommands struct {
	dir string
	log string
}

func newTestOSCommands(t *testing.T, commands map[string]string) *testOSCommands {
	t.Helper()
	ret := &testOSCommands{dir: t.TempDir()}
	ret.log = filepath.Join(ret.dir, "commands.log")
	for name, body := range commands {
		content := fmt.Sprintf("#!/bin/sh\n{ printf '%%s' '%s'; for arg in \"$@\"; do printf '\\t%%s' \"$arg\"; done; printf '\\n'; } >> \"$OCTELIUM_TEST_COMMAND_LOG\"\n%s\n", name, body)
		if !assert.Nil(t, os.WriteFile(filepath.Join(ret.dir, name), []byte(content), 0755)) {
			t.FailNow()
		}
	}
	t.Setenv("PATH", ret.dir)
	t.Setenv("OCTELIUM_TEST_COMMAND_LOG", ret.log)
	return ret
}

func (c *testOSCommands) calls(t *testing.T) [][]string {
	t.Helper()
	content, err := os.ReadFile(c.log)
	if os.IsNotExist(err) {
		return nil
	}
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	var ret [][]string
	for _, line := range strings.Split(strings.TrimSuffix(string(content), "\n"), "\n") {
		ret = append(ret, strings.Split(line, "\t"))
	}
	return ret
}

func TestOSCommandOutputAndInput(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{
		"controller-command": "/bin/cat\nprintf 'stderr output' >&2",
	})
	out, err := runOSCmdInput("stdin payload\n", "controller-command", "an argument with spaces", "fd00::1")
	assert.Nil(t, err)
	assert.Equal(t, "stdin payload\nstderr output", string(out))
	assert.Equal(t, [][]string{{"controller-command", "an argument with spaces", "fd00::1"}}, commands.calls(t))
}

func TestOSCommandFailuresIncludeOutput(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{
		"controller-command": "printf 'command failed' >&2\nexit 7",
	})
	out, err := runOSCmdOutput("controller-command", "first")
	assert.NotNil(t, err)
	assert.Equal(t, "command failed", string(out))
	err = runOSCmd("controller-command", "second")
	if assert.NotNil(t, err) {
		assert.Contains(t, err.Error(), "controller-command")
		assert.Contains(t, err.Error(), "command failed")
	}
	assert.Len(t, commands.calls(t), 2)
	_, err = runOSCmdOutput("controller-missing-command")
	assert.NotNil(t, err)
}
