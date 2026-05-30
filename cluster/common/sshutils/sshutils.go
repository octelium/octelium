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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

func GenerateHostWithCA(ctx context.Context,
	octeliumC octeliumc.ClientInterface) (*ecdsa.PrivateKey, *ssh.Certificate, ssh.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	privSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, nil, err
	}

	caSigner, err := getCASigner(ctx, octeliumC)
	if err != nil {
		return nil, nil, nil, err
	}

	cert, err := makeCert(privSigner, caSigner, ssh.HostCert)
	if err != nil {
		return nil, nil, nil, err
	}

	return priv, cert, caSigner.PublicKey(), nil
}

func GenerateSigner() (ssh.Signer, error) {
	k, err := utils_cert.GenerateECDSA()
	if err != nil {
		return nil, err
	}

	return ssh.NewSignerFromKey(k.PrivateKey)
}

func GenerateHostSigner(ctx context.Context, octeliumC octeliumc.ClientInterface, signer ssh.Signer) (ssh.Signer, error) {
	caSigner, err := getCASigner(ctx, octeliumC)
	if err != nil {
		return nil, err
	}
	return makeHostCert(signer, caSigner, ssh.HostCert)
}

func GenerateUserSigner(ctx context.Context, octeliumC octeliumc.ClientInterface, signer ssh.Signer) (ssh.Signer, error) {
	caSigner, err := getCASigner(ctx, octeliumC)
	if err != nil {
		return nil, err
	}
	return makeHostCert(signer, caSigner, ssh.UserCert)
}

func GetCAPublicKey(ctx context.Context, octeliumC octeliumc.ClientInterface) (ssh.PublicKey, error) {
	caSigner, err := getCASigner(ctx, octeliumC)
	if err != nil {
		return nil, err
	}
	return caSigner.PublicKey(), nil
}

func getCASigner(ctx context.Context, octeliumC octeliumc.ClientInterface) (ssh.Signer, error) {

	secret, err := octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: "sys:ssh-ca"})
	if err != nil {
		return nil, err
	}

	priv, err := utils_cert.ParseECPrivateKeyFromPEM(ucorev1.ToSecret(secret).GetValueBytes())
	if err != nil {
		return nil, err
	}

	ca, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}

	return ca, nil
}

func makeCert(priv ssh.Signer, signer ssh.Signer, typ int) (*ssh.Certificate, error) {
	var err error
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	cert := &ssh.Certificate{
		Nonce:        nonce,
		KeyId:        vutils.UUIDv4(),
		Key:          priv.PublicKey(),
		CertType:     uint32(typ),
		SignatureKey: signer.PublicKey(),
		ValidAfter:   uint64(time.Now().Unix()),
		ValidBefore:  uint64(time.Now().Add(24 * 30 * 12 * 10 * time.Hour).Unix()),
	}

	if typ == ssh.UserCert {
		cert.Permissions = ssh.Permissions{
			Extensions: map[string]string{
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		}
	}

	bytesForSigning := cert.Marshal()
	bytesForSigning = bytesForSigning[:len(bytesForSigning)-4]

	cert.Signature, err = signer.Sign(rand.Reader, bytesForSigning)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func makeHostCert(signer, caSigner ssh.Signer, typ int) (ssh.Signer, error) {

	cert, err := makeCert(signer, caSigner, typ)
	if err != nil {
		return nil, err
	}

	return ssh.NewCertSigner(cert, signer)
}

func GetHostKeyCACallback(caPubKey ssh.PublicKey) ssh.HostKeyCallback {
	if caPubKey == nil {
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return errors.Errorf("nil SSH CA public key")
		}
	}

	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
			return utils.SecureBytesEqual(auth.Marshal(), caPubKey.Marshal())
		},
	}

	return checker.CheckHostKey
}

func GenerateServiceEd25519HostSigner(ctx context.Context,
	octeliumC octeliumc.ClientInterface, svc *corev1.Service) (ssh.Signer, error) {
	seedSec, err := getSeedSecret(ctx, octeliumC)
	if err != nil {
		return nil, err
	}

	return deriveEd25519HostKey(seedSec, "host", svc.Metadata.Uid)
}

func GenerateServiceEd25519UserSigner(ctx context.Context,
	octeliumC octeliumc.ClientInterface, svc *corev1.Service) (ssh.Signer, error) {
	seedSec, err := getSeedSecret(ctx, octeliumC)
	if err != nil {
		return nil, err
	}

	return deriveEd25519HostKey(seedSec, "user", svc.Metadata.Uid)
}

func getSeedSecret(ctx context.Context,
	octeliumC octeliumc.ClientInterface) ([]byte, error) {
	seedSec, err := octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
		Name: "sys:ssh-svc-seed",
	})
	if err != nil {
		return nil, err
	}

	return ucorev1.ToSecret(seedSec).GetValueBytes(), nil
}

func deriveEd25519HostKey(masterSeed []byte, keyType, serviceUID string) (ssh.Signer, error) {
	info := fmt.Sprintf("octelium/vigil/ssh-%s-key/ed25519/%s", keyType, serviceUID)
	r := hkdf.New(sha256.New, masterSeed, nil, []byte(info))

	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, fmt.Errorf("Could not get ed25519 seed: %w", err)
	}

	privKey := ed25519.NewKeyFromSeed(seed)
	return ssh.NewSignerFromKey(privKey)
}
