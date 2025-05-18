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

//go:build !windows
// +build !windows


package essh

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type tstGoNetCtl struct {
}

func (c *tstGoNetCtl) GetGoNet() ccommon.GoNet {
	return nil
}

func TestServer(t *testing.T) {
	zapCfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.DebugLevel),
		Development:      true,
		Encoding:         "console",
		EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := zapCfg.Build()
	assert.Nil(t, err)

	zap.ReplaceGlobals(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	privSigner, err := ssh.NewSignerFromKey(priv)
	assert.Nil(t, err)

	_, privk, err := ed25519.GenerateKey(nil)
	assert.Nil(t, err)

	ca, err := ssh.NewSignerFromKey(privk)
	assert.Nil(t, err)

	opts := &Opts{
		Signer:   privSigner,
		CAPubKey: ca.PublicKey(),

		ListenAddrs: []string{
			"127.0.0.1:3022",
		},
		GoNetCtl: &tstGoNetCtl{},
	}

	srv, err := NewServer(opts)
	assert.Nil(t, err)

	err = srv.Start(ctx)
	assert.Nil(t, err)

	{

		doConnect := func(srvAddr string) {
			c, err := net.Dial("tcp", srvAddr)
			assert.Nil(t, err, "%+v", err)

			crt, err := makeHostCert(ca, ssh.UserCert)
			assert.Nil(t, err)

			clientConfig := &ssh.ClientConfig{
				User:            "user",
				HostKeyCallback: ssh.FixedHostKey(privSigner.PublicKey()),
				Auth: []ssh.AuthMethod{
					ssh.PublicKeys(crt),
				},
			}

			clientConn, clientChans, clientReqs, err := ssh.NewClientConn(c, srvAddr, clientConfig)
			assert.Nil(t, err, "Could not create ssh client %+v", err)
			sshC := ssh.NewClient(clientConn, clientChans, clientReqs)

			sess, err := sshC.NewSession()
			assert.Nil(t, err, "%+v", err)
			err = sess.RequestPty("xterm", 80, 24, ssh.TerminalModes{
				ssh.ECHO:          0,
				ssh.TTY_OP_ISPEED: 14400,
				ssh.TTY_OP_OSPEED: 14400,
			})
			assert.Nil(t, err)

			stdoutPipe, err := sess.StdoutPipe()
			assert.Nil(t, err)

			stdinPipe, err := sess.StdinPipe()
			assert.Nil(t, err)

			err = sess.Shell()
			assert.Nil(t, err)
			time.Sleep(1 * time.Second)

			_, err = stdinPipe.Write([]byte("ls -la \r\n"))
			assert.Nil(t, err)
			buf := make([]byte, 1024)
			n, err := stdoutPipe.Read(buf)
			assert.Nil(t, err)
			zap.S().Debugf("%s", buf[:n])

			sshC.Close()
			c.Close()
		}

		doConnect("127.0.0.1:3022")
	}

	time.Sleep(2 * time.Second)
	err = srv.Close()
	assert.Nil(t, err)
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
