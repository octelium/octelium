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

package sshcert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type tstConnMetadata struct {
	ssh.ConnMetadata
	user string
}

func (c *tstConnMetadata) User() string {
	return c.user
}

type tstAlgorithmSigner struct {
	ssh.AlgorithmSigner
}

type tstSigner struct {
	ssh.Signer
}

func newECDSASigner(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.Nil(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.Nil(t, err)
	return signer
}

func newEd25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.Nil(t, err)
	return signer
}

func newCert(key ssh.Signer, typ uint32, principals ...string) *ssh.Certificate {
	return &ssh.Certificate{
		Key:             key.PublicKey(),
		CertType:        typ,
		KeyId:           "key-id",
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
}

func newSignedCert(t *testing.T, key, ca ssh.Signer, typ uint32, principals ...string) *ssh.Certificate {
	t.Helper()
	cert := newCert(key, typ, principals...)
	require.Nil(t, Sign(rand.Reader, cert, ca))
	return cert
}

func isKey(key ssh.PublicKey) func(auth ssh.PublicKey) bool {
	return func(auth ssh.PublicKey) bool {
		return bytes.Equal(auth.Marshal(), key.Marshal())
	}
}

func TestSign(t *testing.T) {
	ca := newECDSASigner(t)
	key := newEd25519Signer(t)

	{
		cert := newCert(key, ssh.HostCert)
		err := Sign(rand.Reader, cert, ca)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 32, len(cert.Nonce))
		assert.Equal(t, ca.PublicKey().Marshal(), cert.SignatureKey.Marshal())
		assert.Equal(t, ssh.KeyAlgoECDSA256, cert.Signature.Format)
		assert.Nil(t, ca.PublicKey().Verify(bytesForSigning(cert), cert.Signature))

		pubKey, err := ssh.ParsePublicKey(cert.Marshal())
		require.Nil(t, err, "%+v", err)
		parsed, ok := pubKey.(*ssh.Certificate)
		require.True(t, ok)
		assert.Empty(t, parsed.ValidPrincipals)
		assert.Equal(t, cert.Marshal(), parsed.Marshal())

		assert.Nil(t, (&CertChecker{}).CheckCert("example.com", parsed))
		assert.NotNil(t, (&ssh.CertChecker{}).CheckCert("example.com", parsed))
	}

	{
		c1 := newSignedCert(t, key, ca, ssh.HostCert)
		c2 := newSignedCert(t, key, ca, ssh.HostCert)
		assert.NotEqual(t, c1.Nonce, c2.Nonce)
	}

	{
		cert := newCert(key, ssh.HostCert, "example.com")
		err := Sign(rand.Reader, cert, ca)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, []string{"example.com"}, cert.ValidPrincipals)
		assert.Nil(t, (&ssh.CertChecker{}).CheckCert("example.com", cert))
		assert.NotNil(t, (&ssh.CertChecker{}).CheckCert("other.example.com", cert))
	}

	{
		cert := newCert(key, ssh.HostCert, "example.com", "")
		assert.NotNil(t, Sign(rand.Reader, cert, ca))
		assert.Nil(t, cert.Signature)
	}

	{
		certSigner, err := ssh.NewCertSigner(newSignedCert(t, ca, newECDSASigner(t), ssh.UserCert), ca)
		require.Nil(t, err)
		cert := newCert(key, ssh.HostCert)
		assert.NotNil(t, Sign(rand.Reader, cert, certSigner))
		assert.Nil(t, cert.Signature)
		assert.Nil(t, cert.SignatureKey)
	}

	{
		errRand := errors.New("rand failure")
		cert := newCert(key, ssh.HostCert)
		assert.ErrorIs(t, Sign(iotest.ErrReader(errRand), cert, ca), errRand)
		assert.Nil(t, cert.Signature)
	}
}

func TestSignAlgorithms(t *testing.T) {
	key := newEd25519Signer(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)
	rsaSigner, err := ssh.NewSignerFromKey(rsaKey)
	require.Nil(t, err)
	rsaAlgorithmSigner, ok := rsaSigner.(ssh.AlgorithmSigner)
	require.True(t, ok)
	rsaSHA256Signer, err := ssh.NewSignerWithAlgorithms(rsaAlgorithmSigner, []string{ssh.KeyAlgoRSASHA256})
	require.Nil(t, err)

	for _, tc := range []struct {
		name      string
		authority ssh.Signer
		format    string
	}{
		{"ECDSA", newECDSASigner(t), ssh.KeyAlgoECDSA256},
		{"Ed25519", newEd25519Signer(t), ssh.KeyAlgoED25519},
		{"RSA", rsaSigner, ssh.KeyAlgoRSASHA256},
		{"RSASHA256", rsaSHA256Signer, ssh.KeyAlgoRSASHA256},
		{"RSAAlgorithmSigner", &tstAlgorithmSigner{rsaAlgorithmSigner}, ssh.KeyAlgoRSASHA512},
		{"Signer", &tstSigner{newEd25519Signer(t)}, ssh.KeyAlgoED25519},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withPrincipals := newCert(key, ssh.UserCert, "user")
			require.Nil(t, withPrincipals.SignCert(rand.Reader, tc.authority))

			withoutPrincipals := newCert(key, ssh.UserCert)
			err := Sign(rand.Reader, withoutPrincipals, tc.authority)
			require.Nil(t, err, "%+v", err)

			assert.Equal(t, tc.format, withPrincipals.Signature.Format)
			assert.Equal(t, tc.format, withoutPrincipals.Signature.Format)
			assert.Nil(t, (&CertChecker{}).CheckCert("user", withoutPrincipals))
		})
	}
}

func TestCertCheckerCheckCert(t *testing.T) {
	ca := newECDSASigner(t)
	key := newEd25519Signer(t)
	now := time.Now()

	newChecker := func() *CertChecker {
		return &CertChecker{
			CertChecker: ssh.CertChecker{
				Clock: func() time.Time {
					return now
				},
			},
		}
	}

	{
		cert := newSignedCert(t, key, ca, ssh.UserCert)
		for _, principal := range []string{"root", "user", "example.com", "*"} {
			assert.Nil(t, newChecker().CheckCert(principal, cert), principal)
		}
		assert.NotNil(t, newChecker().CheckCert("", cert))
		assert.Nil(t, (&CertChecker{}).CheckCert("user", cert))
	}

	{
		cert := newSignedCert(t, key, ca, ssh.UserCert, "user")
		assert.Nil(t, newChecker().CheckCert("user", cert))
		assert.NotNil(t, newChecker().CheckCert("root", cert))
	}

	for _, tc := range []struct {
		name  string
		set   func(c *ssh.Certificate)
		valid bool
	}{
		{"Expired", func(c *ssh.Certificate) { c.ValidBefore = uint64(now.Add(-time.Minute).Unix()) }, false},
		{"ExpiresNow", func(c *ssh.Certificate) { c.ValidBefore = uint64(now.Unix()) }, false},
		{"NegativeValidBefore", func(c *ssh.Certificate) { c.ValidBefore = math.MaxInt64 + 1 }, false},
		{"NotYetValid", func(c *ssh.Certificate) { c.ValidAfter = uint64(now.Add(time.Minute).Unix()) }, false},
		{"NegativeValidAfter", func(c *ssh.Certificate) { c.ValidAfter = math.MaxUint64 - 1 }, false},
		{"ValidForever", func(c *ssh.Certificate) { c.ValidBefore = ssh.CertTimeInfinity }, true},
		{"ValidFromEpoch", func(c *ssh.Certificate) { c.ValidAfter = 0 }, true},
		{"UnsupportedCriticalOption", func(c *ssh.Certificate) {
			c.CriticalOptions = map[string]string{"force-command": "true"}
		}, false},
		{"SourceAddress", func(c *ssh.Certificate) {
			c.CriticalOptions = map[string]string{"source-address": "127.0.0.1/32"}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := newCert(key, ssh.UserCert)
			tc.set(cert)
			require.Nil(t, Sign(rand.Reader, cert, ca))
			err := newChecker().CheckCert("user", cert)
			if tc.valid {
				assert.Nil(t, err, "%+v", err)
			} else {
				assert.NotNil(t, err)
			}
		})
	}

	{
		cert := newCert(key, ssh.UserCert)
		cert.CriticalOptions = map[string]string{"force-command": "true"}
		require.Nil(t, Sign(rand.Reader, cert, ca))
		checker := newChecker()
		checker.SupportedCriticalOptions = []string{"force-command"}
		assert.Nil(t, checker.CheckCert("user", cert))
	}

	{
		cert := newSignedCert(t, key, ca, ssh.UserCert)
		checker := newChecker()
		checker.IsRevoked = func(c *ssh.Certificate) bool {
			return c == cert
		}
		assert.NotNil(t, checker.CheckCert("user", cert))
		assert.Nil(t, checker.CheckCert("user", newSignedCert(t, key, ca, ssh.UserCert)))
	}

	{
		cert := newSignedCert(t, key, ca, ssh.UserCert)
		cert.KeyId = "tampered"
		assert.NotNil(t, newChecker().CheckCert("user", cert))
	}

	{
		cert := newSignedCert(t, key, ca, ssh.UserCert)
		cert.Permissions.Extensions = map[string]string{"permit-pty": ""}
		assert.NotNil(t, newChecker().CheckCert("user", cert))
	}

	{
		cert := newSignedCert(t, key, ca, ssh.UserCert)
		cert.SignatureKey = newECDSASigner(t).PublicKey()
		assert.NotNil(t, newChecker().CheckCert("user", cert))
	}

	{
		cert := newSignedCert(t, key, ca, ssh.UserCert)
		cert.Signature = nil
		assert.NotNil(t, newChecker().CheckCert("user", cert))

		cert = newSignedCert(t, key, ca, ssh.UserCert)
		cert.SignatureKey = nil
		assert.NotNil(t, newChecker().CheckCert("user", cert))

		cert = newSignedCert(t, key, ca, ssh.UserCert)
		cert.Key = nil
		assert.NotNil(t, newChecker().CheckCert("user", cert))
	}
}

func TestCertCheckerCheckHostKey(t *testing.T) {
	ca := newECDSASigner(t)
	otherCA := newECDSASigner(t)
	key := newEd25519Signer(t)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	checker := &CertChecker{
		CertChecker: ssh.CertChecker{
			IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
				return isKey(ca.PublicKey())(auth)
			},
		},
	}

	{
		cert := newSignedCert(t, key, ca, ssh.HostCert)
		for _, addr := range []string{
			"example.com:22",
			"svc.default.local.example.com:2022",
			"100.64.0.25:22",
			"[fdee:e61::2e6]:22",
			"localhost:22",
			"custom-client-alias:22",
		} {
			assert.Nil(t, checker.CheckHostKey(addr, remote, cert), addr)
		}

		assert.NotNil(t, checker.CheckHostKey("example.com", remote, cert))
		assert.NotNil(t, checker.CheckHostKey(":22", remote, cert))
		assert.NotNil(t, (&ssh.CertChecker{IsHostAuthority: checker.IsHostAuthority}).CheckHostKey("example.com:22", remote, cert))
	}

	{
		cert := newSignedCert(t, key, ca, ssh.HostCert, "example.com")
		assert.Nil(t, checker.CheckHostKey("example.com:22", remote, cert))
		assert.NotNil(t, checker.CheckHostKey("other.example.com:22", remote, cert))
	}

	assert.NotNil(t, checker.CheckHostKey("example.com:22", remote, newSignedCert(t, key, ca, ssh.UserCert)))
	assert.NotNil(t, checker.CheckHostKey("example.com:22", remote, newSignedCert(t, key, otherCA, ssh.HostCert)))
	assert.NotNil(t, (&CertChecker{}).CheckHostKey("example.com:22", remote, newSignedCert(t, key, ca, ssh.HostCert)))

	{
		cert := newSignedCert(t, key, ca, ssh.HostCert)
		cert.SignatureKey = nil
		assert.NotNil(t, checker.CheckHostKey("example.com:22", remote, cert))
	}

	{
		cert := newSignedCert(t, key, ca, ssh.HostCert)
		cert.ValidBefore = uint64(time.Now().Add(-time.Minute).Unix())
		assert.NotNil(t, checker.CheckHostKey("example.com:22", remote, cert))
	}

	assert.NotNil(t, checker.CheckHostKey("example.com:22", remote, key.PublicKey()))

	{
		var called bool
		checker := &CertChecker{
			CertChecker: ssh.CertChecker{
				IsHostAuthority: checker.IsHostAuthority,
				HostKeyFallback: func(hostname string, remote net.Addr, k ssh.PublicKey) error {
					called = true
					return nil
				},
			},
		}
		assert.Nil(t, checker.CheckHostKey("example.com:22", remote, key.PublicKey()))
		assert.True(t, called)
	}
}

func TestCertCheckerAuthenticate(t *testing.T) {
	ca := newECDSASigner(t)
	otherCA := newECDSASigner(t)
	key := newEd25519Signer(t)
	conn := &tstConnMetadata{user: "user"}

	checker := &CertChecker{
		CertChecker: ssh.CertChecker{
			IsUserAuthority: isKey(ca.PublicKey()),
		},
	}

	{
		cert := newCert(key, ssh.UserCert)
		cert.Permissions.Extensions = map[string]string{"permit-pty": ""}
		require.Nil(t, Sign(rand.Reader, cert, ca))

		for _, user := range []string{"user", "root", "session-name"} {
			perms, err := checker.Authenticate(&tstConnMetadata{user: user}, cert)
			assert.Nil(t, err, "%+v", err)
			assert.Same(t, &cert.Permissions, perms)
		}

		_, err := checker.Authenticate(&tstConnMetadata{}, cert)
		assert.NotNil(t, err)

		_, err = (&ssh.CertChecker{IsUserAuthority: checker.IsUserAuthority}).Authenticate(conn, cert)
		assert.NotNil(t, err)
	}

	{
		cert := newSignedCert(t, key, ca, ssh.UserCert, "user")
		_, err := checker.Authenticate(conn, cert)
		assert.Nil(t, err, "%+v", err)
		_, err = checker.Authenticate(&tstConnMetadata{user: "root"}, cert)
		assert.NotNil(t, err)
	}

	{
		cert := newCert(key, ssh.UserCert)
		cert.CriticalOptions = map[string]string{"source-address": "127.0.0.1/32"}
		require.Nil(t, Sign(rand.Reader, cert, ca))
		perms, err := checker.Authenticate(conn, cert)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "127.0.0.1/32", perms.CriticalOptions["source-address"])
		assert.Empty(t, checker.SupportedCriticalOptions)
	}

	{
		cert := newCert(key, ssh.UserCert)
		cert.CriticalOptions = map[string]string{"force-command": "true"}
		require.Nil(t, Sign(rand.Reader, cert, ca))
		_, err := checker.Authenticate(conn, cert)
		assert.NotNil(t, err)
	}

	{
		_, err := checker.Authenticate(conn, newSignedCert(t, key, ca, ssh.HostCert))
		assert.NotNil(t, err)

		_, err = checker.Authenticate(conn, newSignedCert(t, key, otherCA, ssh.UserCert))
		assert.NotNil(t, err)

		_, err = (&CertChecker{}).Authenticate(conn, newSignedCert(t, key, ca, ssh.UserCert))
		assert.NotNil(t, err)

		cert := newSignedCert(t, key, ca, ssh.UserCert)
		cert.SignatureKey = nil
		_, err = checker.Authenticate(conn, cert)
		assert.NotNil(t, err)

		cert = newSignedCert(t, key, ca, ssh.UserCert)
		cert.KeyId = "tampered"
		_, err = checker.Authenticate(conn, cert)
		assert.NotNil(t, err)
	}

	{
		_, err := checker.Authenticate(conn, key.PublicKey())
		assert.NotNil(t, err)

		perms := &ssh.Permissions{}
		checker := &CertChecker{
			CertChecker: ssh.CertChecker{
				IsUserAuthority: checker.IsUserAuthority,
				UserKeyFallback: func(conn ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
					return perms, nil
				},
			},
		}
		ret, err := checker.Authenticate(conn, key.PublicKey())
		assert.Nil(t, err, "%+v", err)
		assert.Same(t, perms, ret)
	}
}

func TestCertCheckerHandshake(t *testing.T) {
	ca := newECDSASigner(t)

	hostKey := newEd25519Signer(t)
	hostSigner, err := ssh.NewCertSigner(newSignedCert(t, hostKey, ca, ssh.HostCert), hostKey)
	require.Nil(t, err)

	userKey := newEd25519Signer(t)
	userCert := newCert(userKey, ssh.UserCert)
	userCert.Permissions.Extensions = map[string]string{"permit-pty": ""}
	require.Nil(t, Sign(rand.Reader, userCert, ca))
	userSigner, err := ssh.NewCertSigner(userCert, userKey)
	require.Nil(t, err)

	checker := &CertChecker{
		CertChecker: ssh.CertChecker{
			IsUserAuthority: isKey(ca.PublicKey()),
			IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
				return isKey(ca.PublicKey())(auth)
			},
		},
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: checker.Authenticate,
	}
	serverConfig.AddHostKey(hostSigner)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	defer lis.Close()

	type result struct {
		conn *ssh.ServerConn
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		server, err := lis.Accept()
		if err != nil {
			resCh <- result{err: err}
			return
		}
		require.Nil(t, server.SetDeadline(time.Now().Add(10*time.Second)))
		conn, chans, reqs, err := ssh.NewServerConn(server, serverConfig)
		if err != nil {
			server.Close()
		}
		if err == nil {
			go ssh.DiscardRequests(reqs)
			go func() {
				for ch := range chans {
					ch.Reject(ssh.Prohibited, "")
				}
			}()
		}
		resCh <- result{conn: conn, err: err}
	}()

	client, err := net.DialTimeout("tcp", lis.Addr().String(), 5*time.Second)
	require.Nil(t, err)
	defer client.Close()
	require.Nil(t, client.SetDeadline(time.Now().Add(10*time.Second)))

	clientConn, chans, reqs, err := ssh.NewClientConn(client, "custom-client-alias:22", &ssh.ClientConfig{
		User:            "user",
		HostKeyCallback: checker.CheckHostKey,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(userSigner)},
	})
	require.Nil(t, err, "%+v", err)
	defer clientConn.Close()
	go ssh.DiscardRequests(reqs)
	go func() {
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "")
		}
	}()

	res := <-resCh
	require.Nil(t, res.err, "%+v", res.err)
	defer res.conn.Close()
	assert.Equal(t, "user", res.conn.User())
	_, ok := res.conn.Permissions.Extensions["permit-pty"]
	assert.True(t, ok)
}

func writeKnownHosts(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	require.Nil(t, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600))
	return path
}

func knownHostsKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func TestNewKnownHostsCallback(t *testing.T) {
	ca := newECDSASigner(t)
	scopedCA := newECDSASigner(t)
	otherCA := newECDSASigner(t)
	key := newEd25519Signer(t)
	plainKey := newEd25519Signer(t)
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	callback, err := NewKnownHostsCallback(writeKnownHosts(t,
		"# comment",
		"",
		fmt.Sprintf("@cert-authority %s", knownhosts.Line([]string{"*"}, ca.PublicKey())),
		fmt.Sprintf("@cert-authority *.example.com %s", knownHostsKey(scopedCA.PublicKey())),
		fmt.Sprintf("plain.example.com %s", knownHostsKey(plainKey.PublicKey())),
		"invalid entry",
	))
	require.Nil(t, err, "%+v", err)

	{
		cert := newSignedCert(t, key, ca, ssh.HostCert)
		for _, addr := range []string{
			"example.com:22",
			"svc.default.local.example.com:2022",
			"100.64.0.25:22",
			"[fdee:e61::2e6]:22",
			"custom-client-alias:22",
		} {
			assert.Nil(t, callback(addr, remote, cert), addr)
		}
		assert.NotNil(t, callback("example.com", remote, cert))
		assert.NotNil(t, callback("example.com:22", remote, newSignedCert(t, key, ca, ssh.UserCert)))

		expired := newCert(key, ssh.HostCert)
		expired.ValidBefore = uint64(time.Now().Add(-time.Minute).Unix())
		require.Nil(t, Sign(rand.Reader, expired, ca))
		assert.NotNil(t, callback("example.com:22", remote, expired))
	}

	{
		cert := newSignedCert(t, key, ca, ssh.HostCert, "host.example.com")
		assert.Nil(t, callback("host.example.com:22", remote, cert))
		assert.NotNil(t, callback("other.example.com:22", remote, cert))
	}

	{
		assert.NotNil(t, callback("a.example.com:22", remote, newSignedCert(t, key, scopedCA, ssh.HostCert)))

		cert := newSignedCert(t, key, scopedCA, ssh.HostCert, "a.example.com")
		assert.Nil(t, callback("a.example.com:22", remote, cert))
		assert.NotNil(t, callback("a.other.com:22", remote, newSignedCert(t, key, scopedCA, ssh.HostCert, "a.other.com")))
	}

	assert.NotNil(t, callback("example.com:22", remote, newSignedCert(t, key, otherCA, ssh.HostCert)))

	assert.Nil(t, callback("plain.example.com:22", remote, plainKey.PublicKey()))
	assert.NotNil(t, callback("other.example.com:22", remote, plainKey.PublicKey()))
	assert.NotNil(t, callback("plain.example.com:22", remote, key.PublicKey()))

	{
		callback, err := NewKnownHostsCallback(writeKnownHosts(t,
			fmt.Sprintf("@cert-authority * %s", knownHostsKey(ca.PublicKey())),
			fmt.Sprintf("@revoked * %s", knownHostsKey(key.PublicKey())),
		))
		require.Nil(t, err, "%+v", err)
		assert.NotNil(t, callback("example.com:22", remote, newSignedCert(t, key, ca, ssh.HostCert)))
		assert.Nil(t, callback("example.com:22", remote, newSignedCert(t, newEd25519Signer(t), ca, ssh.HostCert)))
	}

	{
		callback, err := NewKnownHostsCallback(writeKnownHosts(t,
			fmt.Sprintf("@cert-authority * %s", knownHostsKey(ca.PublicKey())),
			fmt.Sprintf("@revoked * %s", knownHostsKey(ca.PublicKey())),
		))
		require.Nil(t, err, "%+v", err)
		assert.NotNil(t, callback("example.com:22", remote, newSignedCert(t, key, ca, ssh.HostCert)))
		assert.NotNil(t, callback("example.com:22", remote, newSignedCert(t, key, ca, ssh.HostCert, "example.com")))
	}

	{
		callback, err := NewKnownHostsCallback(
			writeKnownHosts(t, fmt.Sprintf("@cert-authority example.com %s", knownHostsKey(otherCA.PublicKey()))),
			writeKnownHosts(t, fmt.Sprintf("@cert-authority * %s", knownHostsKey(ca.PublicKey()))),
		)
		require.Nil(t, err, "%+v", err)
		assert.Nil(t, callback("example.com:22", remote, newSignedCert(t, key, ca, ssh.HostCert)))
		assert.NotNil(t, callback("example.com:22", remote, newSignedCert(t, key, otherCA, ssh.HostCert)))
	}

	_, err = NewKnownHostsCallback(filepath.Join(t.TempDir(), "missing"))
	assert.NotNil(t, err)
}

func TestSignOpenSSH(t *testing.T) {
	sshKeygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not available")
	}

	ca := newECDSASigner(t)
	key := newEd25519Signer(t)

	run := func(cert *ssh.Certificate) (string, error) {
		path := filepath.Join(t.TempDir(), "cert.pub")
		require.Nil(t, os.WriteFile(path, ssh.MarshalAuthorizedKey(cert), 0600))
		out, err := exec.Command(sshKeygen, "-L", "-f", path).CombinedOutput()
		return string(out), err
	}

	for _, typ := range []uint32{ssh.HostCert, ssh.UserCert} {
		cert := newSignedCert(t, key, ca, typ)
		out, err := run(cert)
		assert.Nil(t, err, "%s", out)
		assert.Contains(t, out, "Principals: (none)")
		assert.Contains(t, out, "Key ID: \"key-id\"")

		cert.KeyId = "tampered"
		out, err = run(cert)
		assert.NotNil(t, err, "%s", out)
	}
}
