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

package authenticators

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
)

type Opts struct {
	User          *corev1.User
	Authenticator *corev1.Authenticator
	OcteliumC     octeliumc.ClientInterface
	ClusterConfig *corev1.ClusterConfig
}

type BeginReq struct {
	Req *authv1.AuthenticateAuthenticatorBeginRequest
}

type BeginResp struct {
	Response *authv1.AuthenticateAuthenticatorBeginResponse
}

type FinishReq struct {
	Resp             *authv1.AuthenticateWithAuthenticatorRequest
	ChallengeRequest *authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest
}

type BeginRegistrationReq struct {
	Req *authv1.RegisterAuthenticatorBeginRequest
}

type BeginRegistrationResp struct {
	Response *authv1.RegisterAuthenticatorBeginResponse
}

type FinishRegistrationReq struct {
	Resp             *authv1.RegisterAuthenticatorFinishRequest
	ChallengeRequest *authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest
}

type FinishResp struct {
	Cred *webauthn.Credential
}

type FinishRegistrationResp struct {
}

type Factor interface {
	Begin(ctx context.Context, req *BeginReq) (*BeginResp, error)
	Finish(ctx context.Context, req *FinishReq) (*FinishResp, error)

	BeginRegistration(ctx context.Context, req *BeginRegistrationReq) (*BeginRegistrationResp, error)
	FinishRegistration(ctx context.Context, req *FinishRegistrationReq) (*FinishRegistrationResp, error)
}

// var ErrInvalidAuth = errors.New("Invalid Authentication")

func ErrInvalidAuthMsg(msg string) error {
	return &errInvalidAuth{
		err: errors.New(msg),
	}
}

func ErrInvalidAuth(err error) error {
	return &errInvalidAuth{
		err: err,
	}
}

type errInvalidAuth struct {
	err error
}

func (e *errInvalidAuth) Error() string {
	return fmt.Sprintf("Authentication error: %+v", e.err)
}

func IsErrInvalidAuth(err error) bool {
	_, ok := err.(*errInvalidAuth)
	return ok
}

func EncryptData(ctx context.Context, octeliumC octeliumc.ClientInterface, plaintext []byte) (*corev1.Authenticator_Status_EncryptedData, error) {
	secretList, err := octeliumC.CoreC().ListSecret(ctx, &rmetav1.ListOptions{
		SystemLabels: map[string]string{
			"aes256-key": "true",
		},
	})

	if err != nil {
		return nil, err
	}
	if len(secretList.Items) == 0 {
		return nil, errors.Errorf("No AEAD Secrets found")
	}
	idx := utilrand.GetRandomRangeMath(0, len(secretList.Items)-1)

	secretKey := secretList.Items[idx]

	block, err := aes.NewCipher(ucorev1.ToSecret(secretKey).GetValueBytes())
	if err != nil {
		return nil, err
	}

	nonce, err := utilrand.GetRandomBytes(12)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	return &corev1.Authenticator_Status_EncryptedData{
		Ciphertext:   ciphertext,
		Nonce:        nonce,
		KeySecretRef: umetav1.GetObjectReference(secretKey),
	}, nil
}

func DecryptData(ctx context.Context, octeliumC octeliumc.ClientInterface, req *corev1.Authenticator_Status_EncryptedData) ([]byte, error) {
	keySecret, err := octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
		Uid: req.KeySecretRef.Uid,
	})
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(ucorev1.ToSecret(keySecret).GetValueBytes())
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, req.Nonce, req.Ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func GetDisplayName(authn *corev1.Authenticator, usr *corev1.User) string {
	if authn.Metadata.DisplayName != "" {
		if usr != nil && usr.Spec.Email != "" {
			return fmt.Sprintf("%s (%s)", usr.Spec.Email, authn.Metadata.DisplayName)
		}
		return authn.Metadata.DisplayName
	}

	if usr != nil && usr.Spec.Info != nil && usr.Spec.Email != "" {
		return usr.Spec.Email
	}

	return authn.Metadata.Name
}
