//go:build linux || darwin

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
