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
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/octelium/octelium/client/octelium/internal/userexec"
	"github.com/pkg/sftp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type tstGoNetCtl struct {
}

func (c *tstGoNetCtl) GetGoNet() ccommon.GoNet {
	return nil
}

func newTestOpts(t *testing.T) (*Opts, ssh.Signer) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privSigner, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)

	_, privk, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	ca, err := ssh.NewSignerFromKey(privk)
	require.NoError(t, err)

	return &Opts{
		Signer:      privSigner,
		CAPubKey:    ca.PublicKey(),
		ListenAddrs: []string{"127.0.0.1:0"},
		GoNetCtl:    &tstGoNetCtl{},
	}, ca
}

func TestMain(m *testing.M) {
	userexec.Init()
	os.Exit(m.Run())
}

func newTestServer(t *testing.T) (*Server, *ssh.Client) {
	t.Helper()

	opts, caSigner := newTestOpts(t)

	return newTestServerWithOpts(t, opts, caSigner)
}

func newTestServerWithOpts(t *testing.T, opts *Opts, caSigner ssh.Signer) (*Server, *ssh.Client) {
	t.Helper()

	srv, err := NewServer(opts)
	require.NoError(t, err)

	ctx, cancelFn := context.WithCancel(context.Background())
	require.NoError(t, srv.Start(ctx))
	t.Cleanup(func() {
		cancelFn()
		require.NoError(t, srv.Close())
	})

	srvAddr := srv.listeners[0].Addr().String()
	c, err := net.Dial("tcp", srvAddr)
	require.NoError(t, err)

	crt, err := makeHostCert(caSigner, ssh.UserCert)
	require.NoError(t, err)
	clientConfig := &ssh.ClientConfig{
		User:            "user",
		HostKeyCallback: ssh.FixedHostKey(opts.Signer.PublicKey()),
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(crt),
		},
	}

	clientConn, clientChans, clientReqs, err := ssh.NewClientConn(c, srvAddr, clientConfig)
	require.NoError(t, err)
	sshC := ssh.NewClient(clientConn, clientChans, clientReqs)
	t.Cleanup(func() {
		sshC.Close()
	})

	return srv, sshC
}

func TestServer(t *testing.T) {
	undo := zap.ReplaceGlobals(zap.NewNop())
	t.Cleanup(undo)

	_, sshC := newTestServer(t)
	sess, err := sshC.NewSession()
	require.NoError(t, err)
	defer sess.Close()

	require.NoError(t, sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}))
	stdoutPipe, err := sess.StdoutPipe()
	require.NoError(t, err)
	stdinPipe, err := sess.StdinPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Shell())
	_, err = stdinPipe.Write([]byte("printf 'ready:%s\\n' \"$SSH_TTY\"; exit\r\n"))
	require.NoError(t, err)
	require.NoError(t, sess.Wait())
	output, err := io.ReadAll(stdoutPipe)
	require.NoError(t, err)
	assert.Contains(t, string(output), "ready:/")
}

func TestExecAndSignalExit(t *testing.T) {
	_, sshC := newTestServer(t)

	for i := 0; i < 20; i++ {
		sess, err := sshC.NewSession()
		require.NoError(t, err)
		require.NoError(t, sess.Run("true"))
	}

	sess, err := sshC.NewSession()
	require.NoError(t, err)
	err = sess.Run("kill -TERM $$")
	var exitErr *ssh.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, "TERM", exitErr.Signal())
}

func TestExecEnv(t *testing.T) {
	_, sshC := newTestServer(t)

	sess, err := sshC.NewSession()
	require.NoError(t, err)
	require.NoError(t, sess.Setenv("GIT_PROTOCOL", "version=2"))
	output, err := sess.Output("printf '%s\\n%s\\n%s\\n' \"$SHELL\" \"$SSH_CONNECTION\" \"$GIT_PROTOCOL\"")
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	require.Len(t, lines, 3)
	assert.NotEmpty(t, lines[0])
	assert.Len(t, strings.Fields(lines[1]), 4)
	assert.Equal(t, "version=2", lines[2])
}

func TestExecProcessGroupCleanup(t *testing.T) {
	_, sshC := newTestServer(t)

	sess, err := sshC.NewSession()
	require.NoError(t, err)
	stdoutPipe, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Start("sleep 30 & echo $!; wait"))

	scanner := bufio.NewScanner(stdoutPipe)
	require.True(t, scanner.Scan())
	pid, err := strconv.Atoi(scanner.Text())
	require.NoError(t, err)
	require.NoError(t, sess.Close())

	require.Eventually(t, func() bool {
		return syscall.Kill(pid, 0) == syscall.ESRCH
	}, 5*time.Second, 10*time.Millisecond)
}

func TestServerCloseProcessCleanup(t *testing.T) {
	srv, sshC := newTestServer(t)

	sess, err := sshC.NewSession()
	require.NoError(t, err)
	stdoutPipe, err := sess.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, sess.Start("sleep 30 & echo $!; wait"))

	scanner := bufio.NewScanner(stdoutPipe)
	require.True(t, scanner.Scan())
	pid, err := strconv.Atoi(scanner.Text())
	require.NoError(t, err)
	require.NoError(t, srv.Close())
	require.Eventually(t, func() bool {
		return syscall.Kill(pid, 0) == syscall.ESRCH
	}, 5*time.Second, 10*time.Millisecond)
}

func TestSFTPSubsystemReply(t *testing.T) {
	_, sshC := newTestServer(t)

	ch, reqs, err := sshC.OpenChannel("session", nil)
	require.NoError(t, err)
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	payload := struct{ Value string }{Value: "sftp"}
	ok, err := ch.SendRequest("subsystem", true, ssh.Marshal(&payload))
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = ch.SendRequest("unsupported", true, nil)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSFTP(t *testing.T) {
	srv, sshC := newTestServer(t)

	c, err := sftp.NewClient(sshC)
	require.NoError(t, err)
	defer c.Close()

	wd, err := c.Getwd()
	require.NoError(t, err)
	assert.Equal(t, srv.usr.HomeDir, wd)

	filePath := filepath.Join(t.TempDir(), "file")
	f, err := c.Create(filePath)
	require.NoError(t, err)
	_, err = f.Write([]byte("octelium"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	content, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, "octelium", string(content))
}

func TestSFTPAsOtherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("This test requires root to run SFTP as another OS user")
	}

	usr, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("This test requires the nobody OS user")
	}
	uid, err := strconv.ParseUint(usr.Uid, 10, 32)
	if err != nil {
		t.Skip("This test requires a numeric uid for the nobody OS user")
	}
	gid, err := strconv.ParseUint(usr.Gid, 10, 32)
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.Chmod(filepath.Dir(dir), 0755))
	require.NoError(t, os.Chmod(dir, 0755))
	ownedDir := filepath.Join(dir, "owned")
	require.NoError(t, os.Mkdir(ownedDir, 0700))
	require.NoError(t, os.Chown(ownedDir, int(uid), int(gid)))
	secretPath := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(secretPath, []byte("secret"), 0600))

	opts, caSigner := newTestOpts(t)
	opts.User = usr.Username
	srv, sshC := newTestServerWithOpts(t, opts, caSigner)
	require.False(t, srv.sameUser)

	c, err := sftp.NewClient(sshC)
	require.NoError(t, err)
	defer c.Close()

	wd, err := c.Getwd()
	require.NoError(t, err)
	assert.Equal(t, filepath.Clean(usr.HomeDir), wd)

	filePath := filepath.Join(ownedDir, "file")
	f, err := c.Create(filePath)
	require.NoError(t, err)
	_, err = f.Write([]byte("octelium"))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	fi, err := os.Stat(filePath)
	require.NoError(t, err)
	st, ok := fi.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Equal(t, uint32(uid), st.Uid)
	assert.Equal(t, uint32(gid), st.Gid)

	_, err = c.Open(secretPath)
	assert.ErrorIs(t, err, os.ErrPermission)
	_, err = c.Create(filepath.Join(dir, "new"))
	assert.ErrorIs(t, err, os.ErrPermission)
	assert.ErrorIs(t, c.Remove(secretPath), os.ErrPermission)
	assert.NoFileExists(t, filepath.Join(dir, "new"))

	content, err := os.ReadFile(secretPath)
	require.NoError(t, err)
	assert.Equal(t, "secret", string(content))
}

func TestSFTPServerCmd(t *testing.T) {
	assert.Error(t, runSFTPServerCmd(nil))
	assert.Error(t, runSFTPServerCmd([]string{""}))
	assert.Error(t, runSFTPServerCmd([]string{"/", "/"}))

	dir := t.TempDir()
	cmd, err := userexec.Command(t.Context(), &syscall.Credential{
		Uid:         uint32(os.Getuid()),
		Gid:         uint32(os.Getgid()),
		NoSetGroups: true,
	}, sftpServerCmdName, dir)
	require.NoError(t, err)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	c, err := sftp.NewClientPipe(stdout, stdin)
	require.NoError(t, err)

	wd, err := c.Getwd()
	require.NoError(t, err)
	assert.Equal(t, dir, wd)

	f, err := c.Create("file")
	require.NoError(t, err)
	_, err = f.Write([]byte("octelium"))
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, c.Close())
	require.NoError(t, cmd.Wait())

	content, err := os.ReadFile(filepath.Join(dir, "file"))
	require.NoError(t, err)
	assert.Equal(t, "octelium", string(content))
}

func TestServerLifecycle(t *testing.T) {
	opts, _ := newTestOpts(t)
	srv, err := NewServer(opts)
	require.NoError(t, err)
	require.NoError(t, srv.Close())
	require.NoError(t, srv.Close())
	require.Error(t, srv.Start(context.Background()))

	opts, _ = newTestOpts(t)
	srv, err = NewServer(opts)
	require.NoError(t, err)
	ctx, cancelFn := context.WithCancel(context.Background())
	require.NoError(t, srv.Start(ctx))
	addr := srv.listeners[0].Addr().String()
	cancelFn()
	require.NoError(t, srv.Close())
	conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if conn != nil {
		conn.Close()
	}
	assert.Error(t, err)
}

func TestNewServerValidation(t *testing.T) {
	_, err := NewServer(nil)
	assert.Error(t, err)

	opts, _ := newTestOpts(t)
	opts.Signer = nil
	_, err = NewServer(opts)
	assert.Error(t, err)

	opts, _ = newTestOpts(t)
	opts.CAPubKey = nil
	_, err = NewServer(opts)
	assert.Error(t, err)

	opts, _ = newTestOpts(t)
	opts.GoNetCtl = nil
	_, err = NewServer(opts)
	assert.Error(t, err)

	opts, _ = newTestOpts(t)
	opts.ListenAddrs = nil
	_, err = NewServer(opts)
	assert.Error(t, err)
}

func TestEnvValidation(t *testing.T) {
	key, val, err := parseEnv(ssh.Marshal(&struct{ Key, Value string }{"TERM", "xterm"}))
	require.NoError(t, err)
	assert.Equal(t, "TERM", key)
	assert.Equal(t, "xterm", val)
	key, val, err = parseEnv(ssh.Marshal(&struct{ Key, Value string }{"OCTELIUM_TEST", "octelium"}))
	require.NoError(t, err)
	assert.Equal(t, "OCTELIUM_TEST", key)
	assert.Equal(t, "octelium", val)
	key, val, err = parseEnv(ssh.Marshal(&struct{ Key, Value string }{"CORDIUM_TEST", "cordium"}))
	require.NoError(t, err)
	assert.Equal(t, "CORDIUM_TEST", key)
	assert.Equal(t, "cordium", val)

	t.Setenv("OCTELIUM_ESSH_ALLOW_ANY_ENV", "true")
	_, _, err = parseEnv(ssh.Marshal(&struct{ Key, Value string }{"SSH_AUTH_SOCK", "/tmp/agent.sock"}))
	assert.Error(t, err)
	_, _, err = parseEnv(ssh.Marshal(&struct{ Key, Value string }{"INVALID=KEY", "value"}))
	assert.Error(t, err)
	_, _, err = parseEnv(ssh.Marshal(&struct{ Key, Value string }{"1INVALID", "value"}))
	assert.Error(t, err)

	usr, err := user.Current()
	require.NoError(t, err)
	t.Setenv("OCTELIUM_DOMAIN", "example.com")
	t.Setenv("OCTELIUM_DOMAIN_SECRET", "secret")
	t.Setenv("CORDIUM_SANDBOX", "sandbox")
	t.Setenv("UNRELATED_ENV_VAR", "value")
	dctx := &dctx{usr: usr}
	env := dctx.getEnv(nil)
	assert.Contains(t, env, "OCTELIUM_DOMAIN=example.com")
	assert.Contains(t, env, "OCTELIUM_DOMAIN_SECRET=secret")
	assert.Contains(t, env, "CORDIUM_SANDBOX=sandbox")
	assert.NotContains(t, env, "UNRELATED_ENV_VAR=value")
}

func TestSecretEnvVars(t *testing.T) {
	for _, key := range secretEnvVars {
		t.Setenv(key, "connector-secret")
	}
	t.Setenv("OCTELIUM_DOMAIN", "example.com")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "/var/run/octelium-proxy.sock")
	t.Setenv("OCTELIUM_AUTH_TOKEN_SAVE_PATH", "/tmp/token")
	t.Setenv("CORDIUM_NAME", "ws")

	usr, err := user.Current()
	require.NoError(t, err)

	for _, sameUser := range []bool{true, false} {
		dctx := &dctx{usr: usr, sameUser: sameUser}
		env := dctx.getEnv(nil)
		for _, keyVal := range env {
			assert.NotContains(t, keyVal, "connector-secret")
		}
		assert.Contains(t, env, "OCTELIUM_DOMAIN=example.com")
		assert.Contains(t, env, "OCTELIUM_AUTH_PROXY_SOCKET=/var/run/octelium-proxy.sock")
		assert.Contains(t, env, "OCTELIUM_AUTH_TOKEN_SAVE_PATH=/tmp/token")
		assert.Contains(t, env, "CORDIUM_NAME=ws")

		env = dctx.getEnv([]*envVar{{key: "OCTELIUM_AUTH_TOKEN", val: "client-value"}})
		assert.Contains(t, env, "OCTELIUM_AUTH_TOKEN=client-value")
	}

	_, sshC := newTestServer(t)
	sess, err := sshC.NewSession()
	require.NoError(t, err)
	output, err := sess.Output("env")
	require.NoError(t, err)
	assert.NotContains(t, string(output), "connector-secret")
	assert.Contains(t, string(output), "OCTELIUM_DOMAIN=example.com")
	assert.Contains(t, string(output), "OCTELIUM_AUTH_PROXY_SOCKET=/var/run/octelium-proxy.sock")
	assert.Contains(t, string(output), "CORDIUM_NAME=ws")
}

func TestSSHAuthSockEnv(t *testing.T) {
	usr, err := user.Current()
	require.NoError(t, err)
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	lis, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer lis.Close()

	t.Setenv("SSH_AUTH_SOCK", sockPath)
	dctx := &dctx{usr: usr, sameUser: true}
	assert.NotContains(t, dctx.getEnv(nil), "SSH_AUTH_SOCK="+sockPath)

	t.Setenv("OCTELIUM_ESSH_INHERIT_SSH_AUTH_SOCK", "true")
	assert.Contains(t, dctx.getEnv(nil), "SSH_AUTH_SOCK="+sockPath)

	dctx.sameUser = false
	assert.NotContains(t, dctx.getEnv(nil), "SSH_AUTH_SOCK="+sockPath)

	dctx.sameUser = true
	missingSockPath := filepath.Join(t.TempDir(), "missing.sock")
	t.Setenv("SSH_AUTH_SOCK", missingSockPath)
	assert.NotContains(t, dctx.getEnv(nil), "SSH_AUTH_SOCK="+missingSockPath)
}

func makeCert(priv ssh.Signer, signer ssh.Signer, typ int) (*ssh.Certificate, error) {
	var err error
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	cert := &ssh.Certificate{
		Nonce:        nonce,
		KeyId:        uuid.New().String(),
		Key:          priv.PublicKey(),
		CertType:     uint32(typ),
		SignatureKey: signer.PublicKey(),
		ValidAfter:   uint64(time.Now().Unix()),
		ValidBefore:  uint64(time.Now().Add(24 * 30 * 12 * 10 * time.Hour).Unix()),
	}

	bytesForSigning := cert.Marshal()
	bytesForSigning = bytesForSigning[:len(bytesForSigning)-4]

	cert.Signature, err = signer.Sign(rand.Reader, bytesForSigning)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func makeHostCertWithPrivSigner(priv ssh.Signer, signer ssh.Signer, typ int) (ssh.Signer, error) {
	cert, err := makeCert(priv, signer, typ)
	if err != nil {
		return nil, err
	}

	return ssh.NewCertSigner(cert, priv)
}

func makeHostCert(signer ssh.Signer, typ int) (ssh.Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	privSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}

	return makeHostCertWithPrivSigner(privSigner, signer, typ)
}
