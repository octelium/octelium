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
	"io"
	"net"
	"os"
	"slices"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const sourceAddressCriticalOption = "source-address"

func Sign(rand io.Reader, cert *ssh.Certificate, authority ssh.Signer) error {
	if len(cert.ValidPrincipals) > 0 {
		return cert.SignCert(rand, authority)
	}

	if _, ok := authority.PublicKey().(*ssh.Certificate); ok {
		return errors.Errorf("ssh: certificates cannot be used as authority")
	}

	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return err
	}

	cert.Nonce = nonce
	cert.SignatureKey = authority.PublicKey()

	sig, err := sign(rand, authority, bytesForSigning(cert))
	if err != nil {
		return err
	}
	cert.Signature = sig

	return nil
}

func sign(rand io.Reader, authority ssh.Signer, data []byte) (*ssh.Signature, error) {
	if signer, ok := authority.(ssh.MultiAlgorithmSigner); ok {
		if len(signer.Algorithms()) == 0 {
			return nil, errors.Errorf("ssh: authority has no signature algorithm")
		}
		return signer.SignWithAlgorithm(rand, data, signer.Algorithms()[0])
	}

	if signer, ok := authority.(ssh.AlgorithmSigner); ok && signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		return signer.SignWithAlgorithm(rand, data, ssh.KeyAlgoRSASHA512)
	}

	return authority.Sign(rand, data)
}

func bytesForSigning(cert *ssh.Certificate) []byte {
	c := *cert
	c.Signature = nil
	out := c.Marshal()
	return out[:len(out)-4]
}

type CertChecker struct {
	ssh.CertChecker
}

func (c *CertChecker) CheckCert(principal string, cert *ssh.Certificate) error {
	if len(cert.ValidPrincipals) > 0 {
		return c.CertChecker.CheckCert(principal, cert)
	}

	if cert.Key == nil || cert.SignatureKey == nil || cert.Signature == nil {
		return errors.Errorf("ssh: certificate is not signed")
	}

	if c.IsRevoked != nil && c.IsRevoked(cert) {
		return errors.Errorf("ssh: certificate serial %d revoked", cert.Serial)
	}

	for opt := range cert.CriticalOptions {
		if !slices.Contains(c.SupportedCriticalOptions, opt) {
			return errors.Errorf("ssh: unsupported critical option %q in certificate", opt)
		}
	}

	if principal == "" {
		return errors.Errorf("ssh: empty principal")
	}

	clock := c.Clock
	if clock == nil {
		clock = time.Now
	}

	unixNow := clock().Unix()
	if after := int64(cert.ValidAfter); after < 0 || unixNow < after {
		return errors.Errorf("ssh: cert is not yet valid")
	}
	if before := int64(cert.ValidBefore); cert.ValidBefore != uint64(ssh.CertTimeInfinity) &&
		(unixNow >= before || before < 0) {
		return errors.Errorf("ssh: cert has expired")
	}

	if err := cert.SignatureKey.Verify(bytesForSigning(cert), cert.Signature); err != nil {
		return errors.Errorf("ssh: certificate signature does not verify")
	}

	return nil
}

func (c *CertChecker) CheckHostKey(addr string, remote net.Addr, key ssh.PublicKey) error {
	cert, ok := key.(*ssh.Certificate)
	if !ok || len(cert.ValidPrincipals) > 0 {
		return c.CertChecker.CheckHostKey(addr, remote, key)
	}

	if cert.CertType != ssh.HostCert {
		return errors.Errorf("ssh: certificate presented as a host key has type %d", cert.CertType)
	}
	if c.IsHostAuthority == nil {
		return errors.Errorf("ssh: cannot verify certificate, IsHostAuthority not set")
	}
	if cert.SignatureKey == nil || !c.IsHostAuthority(cert.SignatureKey, addr) {
		return errors.Errorf("ssh: no authorities for hostname: %v", addr)
	}

	hostname, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	return c.CheckCert(hostname, cert)
}

func (c *CertChecker) Authenticate(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	cert, ok := key.(*ssh.Certificate)
	if !ok || len(cert.ValidPrincipals) > 0 {
		return c.CertChecker.Authenticate(conn, key)
	}

	if cert.CertType != ssh.UserCert {
		return nil, errors.Errorf("ssh: cert has type %d", cert.CertType)
	}
	if c.IsUserAuthority == nil {
		return nil, errors.Errorf("ssh: cannot verify certificate, IsUserAuthority not set")
	}
	if cert.SignatureKey == nil || !c.IsUserAuthority(cert.SignatureKey) {
		return nil, errors.Errorf("ssh: certificate signed by unrecognized authority")
	}

	cc := *c
	cc.SupportedCriticalOptions = append(slices.Clip(cc.SupportedCriticalOptions), sourceAddressCriticalOption)
	if err := cc.CheckCert(conn.User(), cert); err != nil {
		return nil, err
	}

	return &cert.Permissions, nil
}

func NewKnownHostsCallback(files ...string) (ssh.HostKeyCallback, error) {
	callback, err := knownhosts.New(files...)
	if err != nil {
		return nil, err
	}

	var authorities, revoked [][]byte
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}

		for len(data) > 0 {
			marker, hosts, key, _, rest, err := ssh.ParseKnownHosts(data)
			data = rest
			if err != nil {
				continue
			}

			switch {
			case marker == "cert-authority" && slices.Equal(hosts, []string{"*"}):
				authorities = append(authorities, key.Marshal())
			case marker == "revoked":
				revoked = append(revoked, key.Marshal())
			}
		}
	}

	contains := func(keys [][]byte, key ssh.PublicKey) bool {
		blob := key.Marshal()
		return slices.ContainsFunc(keys, func(k []byte) bool {
			return bytes.Equal(k, blob)
		})
	}

	checker := &CertChecker{
		CertChecker: ssh.CertChecker{
			IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
				return contains(authorities, auth)
			},
			IsRevoked: func(cert *ssh.Certificate) bool {
				return contains(revoked, cert.Key) || contains(revoked, cert.SignatureKey)
			},
		},
	}

	return func(addr string, remote net.Addr, key ssh.PublicKey) error {
		if cert, ok := key.(*ssh.Certificate); ok && len(cert.ValidPrincipals) == 0 {
			return checker.CheckHostKey(addr, remote, key)
		}
		return callback(addr, remote, key)
	}, nil
}
