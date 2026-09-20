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

package essh

import (
	"bufio"
	"bytes"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const tstShellTimeout = 30 * time.Second

func tstWaitSession(t *testing.T, sess *ssh.Session) error {
	t.Helper()

	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Wait()
	}()

	select {
	case err := <-errCh:
		return err
	case <-time.After(tstShellTimeout):
		t.Fatalf("Timed out while waiting for the shell session to end")
	}

	return nil
}

type tstShellResult struct {
	stdout string
	stderr string
	err    error
}

func tstRunShell(t *testing.T, sshC *ssh.Client, script string) *tstShellResult {
	t.Helper()

	sess, err := sshC.NewSession()
	require.NoError(t, err)
	t.Cleanup(func() {
		sess.Close()
	})

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	stdinPipe, err := sess.StdinPipe()
	require.NoError(t, err)

	require.NoError(t, sess.Shell())

	_, err = stdinPipe.Write([]byte(script))
	require.NoError(t, err)

	require.NoError(t, stdinPipe.Close())

	err = tstWaitSession(t, sess)

	return &tstShellResult{
		stdout: stdout.String(),
		stderr: stderr.String(),
		err:    err,
	}
}

func TestShellNoPTYStdinEOF(t *testing.T) {
	_, sshC := newTestServer(t)

	outNonce := utilrand.GetRandomStringCanonical(12)
	errNonce := utilrand.GetRandomStringCanonical(12)

	res := tstRunShell(t, sshC,
		"sleep 1\necho "+outNonce+"\necho "+errNonce+" >&2\n")

	require.NoError(t, res.err,
		"the shell must not be killed by the downstream stdin EOF")
	assert.Contains(t, res.stdout, outNonce,
		"the shell stdout written after the stdin EOF was lost")
	assert.Contains(t, res.stderr, errNonce,
		"the shell stderr written after the stdin EOF was lost")
}

func TestShellNoPTYExitStatus(t *testing.T) {
	_, sshC := newTestServer(t)

	res := tstRunShell(t, sshC, "sleep 1\nexit 7\n")

	exitErr, ok := res.err.(*ssh.ExitError)
	require.True(t, ok, "%+v", res.err)
	assert.Equal(t, 7, exitErr.ExitStatus())
	assert.Empty(t, exitErr.Signal(),
		"the shell exited naturally and must not be reported as signaled")
}

func TestShellNoPTYExitSignal(t *testing.T) {
	_, sshC := newTestServer(t)

	res := tstRunShell(t, sshC, "sleep 1\nkill -TERM $$\n")

	exitErr, ok := res.err.(*ssh.ExitError)
	require.True(t, ok, "%+v", res.err)
	assert.Equal(t, "TERM", exitErr.Signal())
}

func TestShellNoPTYProcessGroupCleanup(t *testing.T) {
	_, sshC := newTestServer(t)

	sess, err := sshC.NewSession()
	require.NoError(t, err)

	stdoutPipe, err := sess.StdoutPipe()
	require.NoError(t, err)

	stdinPipe, err := sess.StdinPipe()
	require.NoError(t, err)

	require.NoError(t, sess.Shell())

	_, err = stdinPipe.Write([]byte("sleep 30 & echo $!\nwait\n"))
	require.NoError(t, err)

	scanner := bufio.NewScanner(stdoutPipe)
	require.True(t, scanner.Scan())

	pid, err := strconv.Atoi(scanner.Text())
	require.NoError(t, err)

	require.NoError(t, stdinPipe.Close())

	assert.Never(t, func() bool {
		return syscall.Kill(pid, 0) == syscall.ESRCH
	}, 2*time.Second, 100*time.Millisecond,
		"the downstream stdin EOF must not kill the shell process group")

	require.NoError(t, sess.Close())

	require.Eventually(t, func() bool {
		return syscall.Kill(pid, 0) == syscall.ESRCH
	}, 5*time.Second, 10*time.Millisecond,
		"closing the session must kill the shell process group")
}
