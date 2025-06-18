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

//go:build linux || windows

package authcommon

import (
	"context"
	"crypto/x509"

	"github.com/google/go-attestation/attest"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/pkg/errors"
)

func tpmAuthenticate(ctx context.Context, req *authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest) (*authv1.ChallengeResponse, error) {

	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	})
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	ak, err := tpm.LoadAK(req.GetTpm().AkBytes)
	if err != nil {
		return nil, err
	}
	defer ak.Close(tpm)

	secret, err := ak.ActivateCredential(tpm, attest.EncryptedCredential{
		Credential: req.GetTpm().EncryptedCredential.Credential,
		Secret:     req.GetTpm().EncryptedCredential.Secret,
	})
	if err != nil {
		return nil, err
	}

	return &authv1.ChallengeResponse{
		Type: &authv1.ChallengeResponse_Tpm{
			Tpm: &authv1.ChallengeResponse_TPM{
				Response: secret,
			},
		},
	}, nil
}

func tpmRegister(ctx context.Context, req *authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest) (*authv1.ChallengeResponse, error) {

	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	})
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	ak, err := tpm.LoadAK(req.GetTpm().AkBytes)
	if err != nil {
		return nil, err
	}
	defer ak.Close(tpm)

	secret, err := ak.ActivateCredential(tpm, attest.EncryptedCredential{
		Credential: req.GetTpm().EncryptedCredential.Credential,
		Secret:     req.GetTpm().EncryptedCredential.Secret,
	})
	if err != nil {
		return nil, err
	}

	return &authv1.ChallengeResponse{
		Type: &authv1.ChallengeResponse_Tpm{
			Tpm: &authv1.ChallengeResponse_TPM{
				Response: secret,
			},
		},
	}, nil
}

func tpmGetPreChallenge(ctx context.Context) (*authv1.RegisterAuthenticatorBeginRequest_PreChallenge, error) {
	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	})
	if err != nil {
		return nil, err
	}
	defer tpm.Close()

	eks, err := tpm.EKs()
	if err != nil {
		return nil, err
	}
	if len(eks) < 1 {
		return nil, errors.Errorf("No EK certs")
	}
	ek := eks[0]

	ak, err := tpm.NewAK(&attest.AKConfig{})
	if err != nil {
		return nil, err
	}
	defer ak.Close(tpm)
	attestParams := ak.AttestationParameters()
	akBytes, err := ak.Marshal()
	if err != nil {
		return nil, err
	}
	ret := &authv1.RegisterAuthenticatorBeginRequest_PreChallenge{
		Type: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_Tpm{
			Tpm: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM{
				AkBytes: akBytes,
				AttestationParameters: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM_AttestationParameters{
					Public:            attestParams.Public,
					CreateData:        attestParams.CreateData,
					CreateAttestation: attestParams.CreateAttestation,
					CreateSignature:   attestParams.CreateSignature,
				},
			},
		},
	}

	if ek.Certificate != nil && ek.Certificate.Raw != nil {
		ret.GetTpm().EkType = &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM_EkCertificateDER{
			EkCertificateDER: ek.Certificate.Raw,
		}
	} else {
		ekPublicKeyBytes, err := x509.MarshalPKIXPublicKey(ek.Public)
		if err != nil {
			return nil, err
		}
		ret.GetTpm().EkType = &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM_EkPublicKey{
			EkPublicKey: ekPublicKeyBytes,
		}
	}

	return ret, nil
}
