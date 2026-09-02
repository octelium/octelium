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
	"os/user"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
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

func newTestServer(t *testing.T) (*Server, *ssh.Client) {
	t.Helper()

	opts, caSigner := newTestOpts(t)

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
	_, err = stdinPipe.Write([]byte("printf 'ready\\n'; exit\r\n"))
	require.NoError(t, err)
	require.NoError(t, sess.Wait())
	output, err := io.ReadAll(stdoutPipe)
	require.NoError(t, err)
	assert.Contains(t, string(output), "ready")
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

	t.Setenv("OCTELIUM_ESSH_ALLOW_ANY_ENV", "true")
	_, _, err = parseEnv(ssh.Marshal(&struct{ Key, Value string }{"INVALID=KEY", "value"}))
	assert.Error(t, err)
	_, _, err = parseEnv(ssh.Marshal(&struct{ Key, Value string }{"1INVALID", "value"}))
	assert.Error(t, err)

	usr, err := user.Current()
	require.NoError(t, err)
	t.Setenv("OCTELIUM_DOMAIN", "example.com")
	t.Setenv("OCTELIUM_DOMAIN_SECRET", "secret")
	dctx := &dctx{usr: usr}
	env := dctx.getEnv(nil)
	assert.Contains(t, env, "OCTELIUM_DOMAIN=example.com")
	assert.NotContains(t, env, "OCTELIUM_DOMAIN_SECRET=secret")
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
