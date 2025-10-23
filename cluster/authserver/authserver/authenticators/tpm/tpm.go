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

package tpm

import (
	"context"
	"crypto/rsa"
	"crypto/x509"

	"github.com/google/go-attestation/attest"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type TPMFactor struct {
	cc        *corev1.ClusterConfig
	octeliumC octeliumc.ClientInterface
	opts      *authenticators.Opts
}

func NewFactor(ctx context.Context, o *authenticators.Opts) (*TPMFactor, error) {
	return &TPMFactor{
		cc:        o.ClusterConfig,
		octeliumC: o.OcteliumC,
		opts:      o,
	}, nil
}

func (c *TPMFactor) Begin(ctx context.Context, req *authenticators.BeginReq) (*authenticators.BeginResp, error) {
	ret := &authv1.AuthenticateAuthenticatorBeginResponse{
		ChallengeRequest: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest{
			Type: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_Tpm{
				Tpm: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_TPM{},
			},
		},
	}

	var err error
	authn := c.opts.Authenticator

	if authn.Status.AuthenticationAttempt.EncryptedDataMap == nil {
		authn.Status.AuthenticationAttempt.EncryptedDataMap = make(map[string]*corev1.Authenticator_Status_EncryptedData)
	}

	/*
		if authn.Status.SuccessfulAuthentications < 1 || authn.Status.GetInfo().GetTpm() == nil {
			if req.Req.PreChallenge == nil || req.Req.PreChallenge.GetTpm() == nil ||
				len(req.Req.PreChallenge.GetTpm().AkBytes) == 0 ||
				(len(req.Req.PreChallenge.GetTpm().GetEkCertificateDER()) == 0 && len(req.Req.PreChallenge.GetTpm().GetEkPublicKey()) == 0) ||
				req.Req.PreChallenge.GetTpm().AttestationParameters == nil {
				return nil, errors.Errorf("preChallenge must be set")
			}

			var ekBytes []byte
			if req.Req.PreChallenge.GetTpm().GetEkCertificateDER() != nil {
				ekCert, err := attest.ParseEKCertificate(req.Req.PreChallenge.GetTpm().GetEkCertificateDER())
				if err != nil {
					return nil, err
				}
				zap.L().Debug("ekCert successfully parsed", zap.Any("ekCert", ekCert))

				if _, ok := ekCert.PublicKey.(*rsa.PublicKey); !ok {
					return nil, errors.Errorf("publicKey must be RSA")
				}

				if err := c.verifyEKCert(ekCert); err != nil {
					return nil, errors.Errorf("Could not verify ekCert: %+v", err)
				}

				ekBytes, err = x509.MarshalPKIXPublicKey(ekCert.PublicKey)
				if err != nil {
					return nil, err
				}

			} else {
				if c.factor.Spec.GetTpm() != nil && c.factor.Spec.GetTpm().OnlyAllowEKCertificates {
					return nil, errors.Errorf("only ekCertificates not publicKeys are allowed")
				}

				pubKey, err := x509.ParsePKIXPublicKey(req.Req.PreChallenge.GetTpm().GetEkPublicKey())
				if err != nil {
					return nil, err
				}

				if _, ok := pubKey.(*rsa.PublicKey); !ok {
					return nil, errors.Errorf("publicKey must be RSA")
				}

				ekBytes, err = x509.MarshalPKIXPublicKey(pubKey)
				if err != nil {
					return nil, err
				}
			}

			authn.Status.Info = &corev1.Authenticator_Status_Info{
				Type: &corev1.Authenticator_Status_Info_Tpm{
					Tpm: &corev1.Authenticator_Status_Info_TPM{
						EkPublicKey: ekBytes,
						AkBytes:     req.Req.PreChallenge.GetTpm().AkBytes,
						AttestationParameters: &corev1.Authenticator_Status_Info_TPM_AttestationParameters{
							Public:            req.Req.PreChallenge.GetTpm().AttestationParameters.Public,
							CreateData:        req.Req.PreChallenge.GetTpm().AttestationParameters.CreateData,
							CreateAttestation: req.Req.PreChallenge.GetTpm().AttestationParameters.CreateAttestation,
							CreateSignature:   req.Req.PreChallenge.GetTpm().AttestationParameters.CreateSignature,
						},
					},
				},
			}

		}
	*/

	if authn.Status.GetInfo() == nil || authn.Status.GetInfo().GetTpm() == nil {
		return nil, errors.Errorf("TPM info not set")
	}

	info := authn.Status.GetInfo().GetTpm()

	ek, err := x509.ParsePKIXPublicKey(info.GetEkPublicKey())
	if err != nil {
		return nil, err
	}

	activationParams := &attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ek,
		AK: attest.AttestationParameters{
			Public:            info.AttestationParameters.Public,
			CreateData:        info.AttestationParameters.CreateData,
			CreateAttestation: info.AttestationParameters.CreateAttestation,
			CreateSignature:   info.AttestationParameters.CreateSignature,
		},
	}
	secret, encryptedSecret, err := activationParams.Generate()
	if err != nil {
		return nil, err
	}

	encryptedData, err := authenticators.EncryptData(ctx, c.octeliumC, secret)
	if err != nil {
		return nil, err
	}
	authn.Status.AuthenticationAttempt.EncryptedDataMap["secret"] = encryptedData

	ret.ChallengeRequest.GetTpm().AkBytes = info.AkBytes
	ret.ChallengeRequest.GetTpm().EncryptedCredential = &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_TPM_EncryptedCredential{
		Secret:     encryptedSecret.Secret,
		Credential: encryptedSecret.Credential,
	}

	zap.L().Debug("Returning challengeReq", zap.Any("challengeReq", ret.ChallengeRequest))

	return &authenticators.BeginResp{
		Response: ret,
	}, nil
}

func (c *TPMFactor) verifyEKCert(ekCrt *x509.Certificate) error {
	return nil
}

func (c *TPMFactor) Finish(ctx context.Context, reqCtx *authenticators.FinishReq) (*authenticators.FinishResp, error) {

	var err error

	resp := reqCtx.Resp
	authn := c.opts.Authenticator

	if resp == nil || resp.ChallengeResponse == nil || resp.ChallengeResponse.GetTpm() == nil {
		return nil, authenticators.ErrInvalidAuthMsg("Response is not TPM")
	}

	if authn == nil || authn.Status.Info == nil || authn.Status.Info.GetTpm() == nil {
		return nil, authenticators.ErrInvalidAuthMsg("Authenticator is not TPM")
	}

	secret, err := authenticators.DecryptData(ctx, c.octeliumC,
		authn.Status.AuthenticationAttempt.EncryptedDataMap["secret"])
	if err != nil {
		return nil, err
	}

	if !utils.SecureBytesEqual(secret, resp.ChallengeResponse.GetTpm().Response) {
		return nil, authenticators.ErrInvalidAuthMsg("Invalid response")
	}

	return &authenticators.FinishResp{}, nil
}

func (c *TPMFactor) BeginRegistration(ctx context.Context, req *authenticators.BeginRegistrationReq) (*authenticators.BeginRegistrationResp, error) {
	ret := &authv1.RegisterAuthenticatorBeginResponse{
		ChallengeRequest: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest{
			Type: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_Tpm{
				Tpm: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_TPM{},
			},
		},
	}

	var err error
	authn := c.opts.Authenticator

	if authn.Status.AuthenticationAttempt.EncryptedDataMap == nil {
		authn.Status.AuthenticationAttempt.EncryptedDataMap = make(map[string]*corev1.Authenticator_Status_EncryptedData)
	}

	{
		if req.Req.PreChallenge == nil || req.Req.PreChallenge.GetTpm() == nil ||
			len(req.Req.PreChallenge.GetTpm().AkBytes) == 0 ||
			(len(req.Req.PreChallenge.GetTpm().GetEkCertificateDER()) == 0 && len(req.Req.PreChallenge.GetTpm().GetEkPublicKey()) == 0) ||
			req.Req.PreChallenge.GetTpm().AttestationParameters == nil {
			return nil, errors.Errorf("preChallenge must be set")
		}

		var ekBytes []byte
		if req.Req.PreChallenge.GetTpm().GetEkCertificateDER() != nil {
			ekCert, err := attest.ParseEKCertificate(req.Req.PreChallenge.GetTpm().GetEkCertificateDER())
			if err != nil {
				return nil, err
			}
			zap.L().Debug("ekCert successfully parsed", zap.Any("ekCert", ekCert))

			if _, ok := ekCert.PublicKey.(*rsa.PublicKey); !ok {
				return nil, errors.Errorf("publicKey must be RSA")
			}

			if err := c.verifyEKCert(ekCert); err != nil {
				return nil, errors.Errorf("Could not verify ekCert: %+v", err)
			}

			ekBytes, err = x509.MarshalPKIXPublicKey(ekCert.PublicKey)
			if err != nil {
				return nil, err
			}

		} else {

			pubKey, err := x509.ParsePKIXPublicKey(req.Req.PreChallenge.GetTpm().GetEkPublicKey())
			if err != nil {
				return nil, err
			}

			if _, ok := pubKey.(*rsa.PublicKey); !ok {
				return nil, errors.Errorf("publicKey must be RSA")
			}

			ekBytes, err = x509.MarshalPKIXPublicKey(pubKey)
			if err != nil {
				return nil, err
			}
		}

		authn.Status.Info = &corev1.Authenticator_Status_Info{
			Type: &corev1.Authenticator_Status_Info_Tpm{
				Tpm: &corev1.Authenticator_Status_Info_TPM{
					EkPublicKey: ekBytes,
					AkBytes:     req.Req.PreChallenge.GetTpm().AkBytes,
					AttestationParameters: &corev1.Authenticator_Status_Info_TPM_AttestationParameters{
						Public:            req.Req.PreChallenge.GetTpm().AttestationParameters.Public,
						CreateData:        req.Req.PreChallenge.GetTpm().AttestationParameters.CreateData,
						CreateAttestation: req.Req.PreChallenge.GetTpm().AttestationParameters.CreateAttestation,
						CreateSignature:   req.Req.PreChallenge.GetTpm().AttestationParameters.CreateSignature,
					},
				},
			},
		}

	}

	info := authn.Status.GetInfo().GetTpm()

	ek, err := x509.ParsePKIXPublicKey(info.GetEkPublicKey())
	if err != nil {
		return nil, err
	}

	activationParams := &attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ek,
		AK: attest.AttestationParameters{
			Public:            info.AttestationParameters.Public,
			CreateData:        info.AttestationParameters.CreateData,
			CreateAttestation: info.AttestationParameters.CreateAttestation,
			CreateSignature:   info.AttestationParameters.CreateSignature,
		},
	}
	secret, encryptedSecret, err := activationParams.Generate()
	if err != nil {
		return nil, err
	}

	encryptedData, err := authenticators.EncryptData(ctx, c.octeliumC, secret)
	if err != nil {
		return nil, err
	}
	authn.Status.AuthenticationAttempt.EncryptedDataMap["secret"] = encryptedData

	ret.ChallengeRequest.GetTpm().AkBytes = info.AkBytes
	ret.ChallengeRequest.GetTpm().EncryptedCredential = &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_TPM_EncryptedCredential{
		Secret:     encryptedSecret.Secret,
		Credential: encryptedSecret.Credential,
	}

	zap.L().Debug("Returning challengeReq", zap.Any("challengeReq", ret.ChallengeRequest))

	return &authenticators.BeginRegistrationResp{
		Response: ret,
	}, nil
}

func (c *TPMFactor) FinishRegistration(ctx context.Context,
	reqCtx *authenticators.FinishRegistrationReq) (*authenticators.FinishRegistrationResp, error) {

	var err error

	resp := reqCtx.Resp
	authn := c.opts.Authenticator

	if resp == nil || resp.ChallengeResponse == nil || resp.ChallengeResponse.GetTpm() == nil {
		return nil, authenticators.ErrInvalidAuthMsg("Response is not TPM")
	}

	if authn == nil || authn.Status.Info == nil || authn.Status.Info.GetTpm() == nil {
		return nil, authenticators.ErrInvalidAuthMsg("Invalid req...")
	}

	secret, err := authenticators.DecryptData(ctx, c.octeliumC,
		authn.Status.AuthenticationAttempt.EncryptedDataMap["secret"])
	if err != nil {
		return nil, err
	}

	if !utils.SecureBytesEqual(secret, resp.ChallengeResponse.GetTpm().Response) {
		return nil, authenticators.ErrInvalidAuthMsg("Invalid response")
	}

	return &authenticators.FinishRegistrationResp{}, nil
}
