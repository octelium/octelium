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

package ssh

import (
	"context"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const maxUpstreamUserPrincipalLen = 256

type upstreamSigner struct {
	key  ssh.Signer
	cert ssh.Signer
}

func newUpstreamSigner(ctx context.Context,
	octeliumC octeliumc.ClientInterface, svc *corev1.Service) (*upstreamSigner, error) {
	key, err := sshutils.GenerateServiceEd25519UserSigner(ctx, octeliumC, svc)
	if err != nil {
		key, err = sshutils.GenerateSigner()
		if err != nil {
			return nil, err
		}
	}

	cert, err := sshutils.GenerateUserSigner(ctx, octeliumC, key)
	if err != nil {
		return nil, err
	}

	return &upstreamSigner{
		key:  key,
		cert: cert,
	}, nil
}

func (s *upstreamSigner) getSigners(ctx context.Context,
	octeliumC octeliumc.ClientInterface, id, user string) []ssh.Signer {
	if !isValidUpstreamUserPrincipal(user) {
		zap.L().Debug("The SSH user cannot be used as a certificate principal",
			zap.String("id", id))
		return []ssh.Signer{s.cert}
	}

	signer, err := sshutils.GenerateUserSignerWithPrincipals(ctx, octeliumC, s.key, user)
	if err != nil {
		zap.L().Warn("Could not generate the upstream user certificate",
			zap.String("id", id), zap.Error(err))
		return []ssh.Signer{s.cert}
	}

	return []ssh.Signer{
		signer,
		newFallbackCertSigner(s.cert, func() {
			zap.L().Warn("The upstream SSH server only accepted the user certificate without principals",
				zap.String("id", id), zap.String("user", user))
		}),
	}
}

func isValidUpstreamUserPrincipal(user string) bool {
	if user == "" || len(user) > maxUpstreamUserPrincipalLen || !utf8.ValidString(user) {
		return false
	}

	for _, r := range user {
		if unicode.IsControl(r) || strings.ContainsRune(",*?", r) {
			return false
		}
	}

	return true
}

type fallbackCertSigner struct {
	ssh.MultiAlgorithmSigner
	onSign func()
}

func newFallbackCertSigner(signer ssh.Signer, onSign func()) ssh.Signer {
	multiSigner, ok := signer.(ssh.MultiAlgorithmSigner)
	if !ok {
		return signer
	}

	return &fallbackCertSigner{
		MultiAlgorithmSigner: multiSigner,
		onSign:               onSign,
	}
}

func (s *fallbackCertSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	s.onSign()
	return s.MultiAlgorithmSigner.Sign(rand, data)
}

func (s *fallbackCertSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	s.onSign()
	return s.MultiAlgorithmSigner.SignWithAlgorithm(rand, data, algorithm)
}
