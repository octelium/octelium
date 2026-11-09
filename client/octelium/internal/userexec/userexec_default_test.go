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

package userexec

import (
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetExecutable(t *testing.T) {
	executable, err := getExecutable()
	require.NoError(t, err)
	if runtime.GOOS == "linux" {
		assert.Equal(t, "/proc/self/exe", executable)
		return
	}
	expected, err := os.Executable()
	require.NoError(t, err)
	assert.Equal(t, expected, executable)
}

func TestCommand(t *testing.T) {
	_, err := Command(t.Context(), nil, "test-args")
	assert.Error(t, err)

	executable, err := getExecutable()
	require.NoError(t, err)
	t.Setenv("OCTELIUM_TEST_ENV", "secret")
	cred := &syscall.Credential{Uid: uint32(os.Getuid()), Gid: uint32(os.Getgid())}
	cmd, err := Command(t.Context(), cred, "test-args", "a", "b")
	require.NoError(t, err)
	assert.Equal(t, executable, cmd.Path)
	assert.Equal(t, []string{executable, cmdArg, "test-args", "a", "b"}, cmd.Args)
	assert.NotNil(t, cmd.Env)
	assert.Empty(t, cmd.Environ())
	assert.Equal(t, "/", cmd.Dir)
	assert.Same(t, cred, cmd.SysProcAttr.Credential)
	assert.True(t, cmd.SysProcAttr.Setpgid)
	assert.Equal(t, waitDelay, cmd.WaitDelay)
	assert.Nil(t, cmd.ExtraFiles)
}

func TestCommandAsOtherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root to run a command as another OS user")
	}
	t.Setenv("OCTELIUM_TEST_ENV", "secret")
	cmd, err := Command(t.Context(), &syscall.Credential{Uid: 65534, Gid: 65534}, "test-identity")
	require.NoError(t, err)
	out, err := cmd.Output()
	require.NoError(t, err)
	assert.Equal(t, "65534 65534 [] / []", string(out))

	cmd, err = Command(t.Context(), &syscall.Credential{Uid: 65534, Gid: 65534}, "test-error")
	require.NoError(t, err)
	out, err = cmd.CombinedOutput()
	assert.Error(t, err)
	assert.Equal(t, "test error\n", string(out))
}
