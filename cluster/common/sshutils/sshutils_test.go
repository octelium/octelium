/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package sshutils

import (
	"net"
	"testing"

	"github.com/octelium/octelium/cluster/common/vutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func TestGenerateSigner(t *testing.T) {

	s1, err := GenerateSigner()
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, s1)

	s2, err := GenerateSigner()
	assert.Nil(t, err, "%+v", err)

	assert.NotEqual(t, s1.PublicKey().Marshal(), s2.PublicKey().Marshal())
	assert.Equal(t, "ecdsa-sha2-nistp256", s1.PublicKey().Type())
}

func TestDeriveEd25519HostKeyDeterministic(t *testing.T) {

	seed := utilrand.GetRandomBytesMust(32)
	svcUID := vutils.UUIDv4()

	s1, err := deriveEd25519HostKey(seed, "host", svcUID)
	assert.Nil(t, err, "%+v", err)

	s2, err := deriveEd25519HostKey(seed, "host", svcUID)
	assert.Nil(t, err, "%+v", err)

	assert.Equal(t, s1.PublicKey().Marshal(), s2.PublicKey().Marshal())
	assert.Equal(t, ssh.KeyAlgoED25519, s1.PublicKey().Type())
}

func TestDeriveEd25519HostKeyDomainSeparation(t *testing.T) {

	seed := utilrand.GetRandomBytesMust(32)

	svcA := vutils.UUIDv4()
	svcB := vutils.UUIDv4()

	hostA, err := deriveEd25519HostKey(seed, "host", svcA)
	assert.Nil(t, err, "%+v", err)

	hostB, err := deriveEd25519HostKey(seed, "host", svcB)
	assert.Nil(t, err, "%+v", err)

	userA, err := deriveEd25519HostKey(seed, "user", svcA)
	assert.Nil(t, err, "%+v", err)

	assert.NotEqual(t, hostA.PublicKey().Marshal(), hostB.PublicKey().Marshal())
	assert.NotEqual(t, hostA.PublicKey().Marshal(), userA.PublicKey().Marshal())
	assert.NotEqual(t, hostB.PublicKey().Marshal(), userA.PublicKey().Marshal())
}

func TestDeriveEd25519HostKeySeedSensitivity(t *testing.T) {

	svcUID := vutils.UUIDv4()

	s1, err := deriveEd25519HostKey(utilrand.GetRandomBytesMust(32), "host", svcUID)
	assert.Nil(t, err, "%+v", err)

	s2, err := deriveEd25519HostKey(utilrand.GetRandomBytesMust(32), "host", svcUID)
	assert.Nil(t, err, "%+v", err)

	assert.NotEqual(t, s1.PublicKey().Marshal(), s2.PublicKey().Marshal())

	{
		s, err := deriveEd25519HostKey(nil, "host", svcUID)
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, s)
	}

	{
		s, err := deriveEd25519HostKey([]byte{}, "host", svcUID)
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, s)
	}
}

func TestDeriveEd25519HostKeySigning(t *testing.T) {

	seed := utilrand.GetRandomBytesMust(32)
	signer, err := deriveEd25519HostKey(seed, "host", vutils.UUIDv4())
	assert.Nil(t, err, "%+v", err)

	data := utilrand.GetRandomBytesMust(64)

	sig, err := signer.Sign(nil, data)
	assert.Nil(t, err, "%+v", err)

	assert.Nil(t, signer.PublicKey().Verify(data, sig))
	assert.NotNil(t, signer.PublicKey().Verify(utilrand.GetRandomBytesMust(64), sig))
}

func TestMakeCert(t *testing.T) {

	caKey, err := utils_cert.GenerateECDSA()
	assert.Nil(t, err, "%+v", err)

	caSigner, err := ssh.NewSignerFromKey(caKey.PrivateKey)
	assert.Nil(t, err, "%+v", err)

	signer, err := GenerateSigner()
	assert.Nil(t, err, "%+v", err)

	{
		cert, err := makeCert(signer, caSigner, ssh.HostCert)
		assert.Nil(t, err, "%+v", err)

		assert.Equal(t, uint32(ssh.HostCert), cert.CertType)
		assert.Equal(t, 32, len(cert.Nonce))
		assert.NotEmpty(t, cert.KeyId)
		assert.Equal(t, signer.PublicKey().Marshal(), cert.Key.Marshal())
		assert.Equal(t, caSigner.PublicKey().Marshal(), cert.SignatureKey.Marshal())
		assert.True(t, cert.ValidBefore > cert.ValidAfter)
		assert.Equal(t, 0, len(cert.Permissions.Extensions))
	}

	{
		cert, err := makeCert(signer, caSigner, ssh.UserCert)
		assert.Nil(t, err, "%+v", err)

		assert.Equal(t, uint32(ssh.UserCert), cert.CertType)
		assert.Equal(t, 5, len(cert.Permissions.Extensions))

		for _, ext := range []string{
			"permit-X11-forwarding",
			"permit-agent-forwarding",
			"permit-port-forwarding",
			"permit-pty",
			"permit-user-rc",
		} {
			_, ok := cert.Permissions.Extensions[ext]
			assert.True(t, ok, ext)
		}
	}

	{
		c1, err := makeCert(signer, caSigner, ssh.HostCert)
		assert.Nil(t, err, "%+v", err)

		c2, err := makeCert(signer, caSigner, ssh.HostCert)
		assert.Nil(t, err, "%+v", err)

		assert.NotEqual(t, c1.KeyId, c2.KeyId)
		assert.NotEqual(t, c1.Nonce, c2.Nonce)
	}
}

func TestMakeCertSigner(t *testing.T) {

	caKey, err := utils_cert.GenerateECDSA()
	assert.Nil(t, err, "%+v", err)

	caSigner, err := ssh.NewSignerFromKey(caKey.PrivateKey)
	assert.Nil(t, err, "%+v", err)

	signer, err := GenerateSigner()
	assert.Nil(t, err, "%+v", err)

	certSigner, err := makeCertSigner(signer, caSigner, ssh.HostCert)
	assert.Nil(t, err, "%+v", err)

	cert, ok := certSigner.PublicKey().(*ssh.Certificate)
	assert.True(t, ok)
	assert.Equal(t, uint32(ssh.HostCert), cert.CertType)
	assert.Equal(t, signer.PublicKey().Marshal(), cert.Key.Marshal())
}

func TestGetHostKeyCACallback(t *testing.T) {

	caKey, err := utils_cert.GenerateECDSA()
	assert.Nil(t, err, "%+v", err)

	caSigner, err := ssh.NewSignerFromKey(caKey.PrivateKey)
	assert.Nil(t, err, "%+v", err)

	hostSigner, err := GenerateSigner()
	assert.Nil(t, err, "%+v", err)

	certSigner, err := makeCertSigner(hostSigner, caSigner, ssh.HostCert)
	assert.Nil(t, err, "%+v", err)

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

	{
		cb := GetHostKeyCACallback(nil)
		assert.NotNil(t, cb)
		assert.NotNil(t, cb("host", addr, hostSigner.PublicKey()))
	}

	{
		cb := GetHostKeyCACallback(caSigner.PublicKey())
		assert.NotNil(t, cb("host", addr, hostSigner.PublicKey()))
	}

	{
		otherCAKey, err := utils_cert.GenerateECDSA()
		assert.Nil(t, err, "%+v", err)

		otherCASigner, err := ssh.NewSignerFromKey(otherCAKey.PrivateKey)
		assert.Nil(t, err, "%+v", err)

		cb := GetHostKeyCACallback(otherCASigner.PublicKey())
		assert.NotNil(t, cb("host", addr, certSigner.PublicKey()))
	}
}
