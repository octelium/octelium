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
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

type sshCoreC struct {
	rcorev1.ResourceServiceClient
	secrets map[string]*corev1.Secret
	err     error
}

func (c *sshCoreC) GetSecret(ctx context.Context, req *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Secret, error) {
	return c.secrets[req.Name], c.err
}

type sshOcteliumC struct {
	octeliumc.ClientInterface
	c *sshCoreC
}

func (c *sshOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.c
}

func TestSSHSecretSigners(t *testing.T) {
	ctx := context.Background()
	key, err := utils_cert.GenerateECDSA()
	assert.Nil(t, err)
	keyPEM, err := utils_cert.GetPrivateKeyPEM(key.PrivateKey)
	assert.Nil(t, err)
	c := &sshCoreC{secrets: map[string]*corev1.Secret{
		"sys:ssh-ca":       {Data: &corev1.Secret_Data{Type: &corev1.Secret_Data_ValueBytes{ValueBytes: keyPEM}}},
		"sys:ssh-svc-seed": {Data: &corev1.Secret_Data{Type: &corev1.Secret_Data_ValueBytes{ValueBytes: []byte("test-master-seed")}}},
	}}
	client := &sshOcteliumC{c: c}
	ca, err := GetCAPublicKey(ctx, client)
	assert.Nil(t, err)
	priv, certificate, pub, err := GenerateHostWithCA(ctx, client)
	assert.Nil(t, err)
	assert.NotNil(t, priv)
	assert.Equal(t, ca.Marshal(), pub.Marshal())
	assert.Nil(t, GetHostKeyCACallback(ca)("example.com:22", &net.TCPAddr{}, certificate))
	signer, err := GenerateSigner()
	assert.Nil(t, err)
	host, err := GenerateHostSigner(ctx, client, signer)
	assert.Nil(t, err)
	assert.EqualValues(t, ssh.HostCert, host.PublicKey().(*ssh.Certificate).CertType)
	user, err := GenerateUserSigner(ctx, client, signer)
	assert.Nil(t, err)
	assert.EqualValues(t, ssh.UserCert, user.PublicKey().(*ssh.Certificate).CertType)
	svc := &corev1.Service{Metadata: &metav1.Metadata{Uid: vutils.UUIDv4()}}
	host, err = GenerateServiceEd25519HostSigner(ctx, client, svc)
	assert.Nil(t, err)
	user, err = GenerateServiceEd25519UserSigner(ctx, client, svc)
	assert.Nil(t, err)
	assert.NotEqual(t, host.PublicKey().Marshal(), user.PublicKey().Marshal())
	again, err := GenerateServiceEd25519HostSigner(ctx, client, svc)
	assert.Nil(t, err)
	assert.Equal(t, host.PublicKey().Marshal(), again.PublicKey().Marshal())
	c.err = fmt.Errorf("secret unavailable")
	_, err = GetCAPublicKey(ctx, client)
	assert.ErrorIs(t, err, c.err)
	_, _, _, err = GenerateHostWithCA(ctx, client)
	assert.ErrorIs(t, err, c.err)
	_, err = GenerateHostSigner(ctx, client, signer)
	assert.ErrorIs(t, err, c.err)
	_, err = GenerateUserSigner(ctx, client, signer)
	assert.ErrorIs(t, err, c.err)
	_, err = GenerateServiceEd25519HostSigner(ctx, client, svc)
	assert.ErrorIs(t, err, c.err)
	_, err = GenerateServiceEd25519UserSigner(ctx, client, svc)
	assert.ErrorIs(t, err, c.err)
	c.err = nil
	c.secrets["sys:ssh-ca"].Data = &corev1.Secret_Data{Type: &corev1.Secret_Data_ValueBytes{ValueBytes: []byte("invalid")}}
	_, err = GetCAPublicKey(ctx, client)
	assert.NotNil(t, err)
}

func TestSSHCertificateValidation(t *testing.T) {
	ca, err := GenerateSigner()
	assert.Nil(t, err)
	host, err := GenerateSigner()
	assert.Nil(t, err)
	callback := GetHostKeyCACallback(ca.PublicKey())
	for _, tc := range []struct {
		name string
		set  func(*ssh.Certificate)
	}{
		{"Expired", func(c *ssh.Certificate) { c.ValidBefore = uint64(time.Now().Add(-time.Hour).Unix()) }},
		{"NotYetValid", func(c *ssh.Certificate) { c.ValidAfter = uint64(time.Now().Add(time.Hour).Unix()) }},
		{"WrongPrincipal", func(c *ssh.Certificate) { c.ValidPrincipals = []string{"other.example.com"} }},
		{"CriticalOption", func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{"unknown": "value"} }},
		{"UserCertificate", func(c *ssh.Certificate) { c.CertType = ssh.UserCert }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, err := makeCert(host, ca, ssh.HostCert)
			assert.Nil(t, err)
			tc.set(cert)
			assert.NotNil(t, callback("example.com:22", &net.TCPAddr{}, cert))
		})
	}
}

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
