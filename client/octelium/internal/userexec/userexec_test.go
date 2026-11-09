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

package userexec

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	Register("test-args", func(args []string) error {
		fmt.Print(strings.Join(args, ","))
		return nil
	})
	Register("test-error", func(args []string) error {
		return errors.Errorf("test error")
	})
	Register("test-identity", func(args []string) error {
		groups, err := os.Getgroups()
		if err != nil {
			return err
		}
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		fmt.Printf("%d %d %v %s %v", os.Getuid(), os.Getgid(), groups, wd, os.Environ())
		return nil
	})
	Init()
	os.Exit(m.Run())
}

func runTestInternalCmd(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	executable, err := os.Executable()
	require.NoError(t, err)

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(executable, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return stdout.String(), stderr.String(), exitErr.ExitCode()
	}
	require.NoError(t, err)
	return stdout.String(), stderr.String(), 0
}

func TestInit(t *testing.T) {
	stdout, stderr, exitCode := runTestInternalCmd(t, cmdArg, "test-args", "a", "b c")
	assert.Equal(t, 0, exitCode, stderr)
	assert.Equal(t, "a,b c", stdout)

	stdout, _, exitCode = runTestInternalCmd(t, cmdArg, "test-args")
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "", stdout)

	_, stderr, exitCode = runTestInternalCmd(t, cmdArg, "test-error")
	assert.Equal(t, 1, exitCode)
	assert.Equal(t, "test error\n", stderr)

	_, stderr, exitCode = runTestInternalCmd(t, cmdArg, "unknown")
	assert.Equal(t, 2, exitCode)
	assert.Equal(t, "Unknown internal command: unknown\n", stderr)
}

func TestInitWithoutInternalCmd(t *testing.T) {
	args := os.Args
	t.Cleanup(func() {
		os.Args = args
	})

	for _, tc := range [][]string{
		{"octelium"},
		{"octelium", cmdArg},
		{"octelium", "connect", "test-args"},
		{"octelium", "test-args", cmdArg},
	} {
		os.Args = tc
		Init()
	}
}
