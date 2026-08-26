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
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestTPM(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(tst.C.OcteliumC)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	authn, err := tst.C.OcteliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Authenticator_Spec{
			State: corev1.Authenticator_Spec_ACTIVE,
		},
		Status: &corev1.Authenticator_Status{
			UserRef: umetav1.GetObjectReference(usr.Usr),
			Type:    corev1.Authenticator_Status_TPM,
		},
	})
	assert.Nil(t, err)

	fctr, err := NewFactor(ctx, &authenticators.Opts{
		ClusterConfig: cc,
		OcteliumC:     tst.C.OcteliumC,
		User:          usr.Usr,
		Authenticator: authn,
	})
	assert.Nil(t, err)

	sim, err := simulator.Get()
	assert.Nil(t, err)
	vTPM := attest.InjectSimulatedTPMForTest(sim)
	defer vTPM.Close()

	info, err := vTPM.Info()
	assert.Nil(t, err)

	zap.L().Debug("Info", zap.Any("info", info))

	eks, err := vTPM.EKs()
	assert.Nil(t, err)

	ek := eks[0]

	ak, err := vTPM.NewAK(&attest.AKConfig{})
	assert.Nil(t, err)

	akBytes, err := ak.Marshal()
	assert.Nil(t, err)

	attestParams := ak.AttestationParameters()

	ekBytes, err := x509.MarshalPKIXPublicKey(ek.Public)
	assert.Nil(t, err)
	{
		authn.Status.AuthenticationAttempt = &corev1.Authenticator_Status_AuthenticationAttempt{
			CreatedAt: pbutils.Now(),
		}
		beginResp, err := fctr.BeginRegistration(ctx, &authenticators.BeginRegistrationReq{

			Req: &authv1.RegisterAuthenticatorBeginRequest{
				PreChallenge: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge{
					Type: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_Tpm{
						Tpm: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM{
							EkType: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM_EkPublicKey{
								EkPublicKey: ekBytes,
							},
							AkBytes: akBytes,
							AttestationParameters: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM_AttestationParameters{
								Public:            attestParams.Public,
								CreateData:        attestParams.CreateData,
								CreateAttestation: attestParams.CreateAttestation,
								CreateSignature:   attestParams.CreateSignature,
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)

		secret, err := ak.ActivateCredential(vTPM, attest.EncryptedCredential{
			Credential: beginResp.Response.ChallengeRequest.GetTpm().EncryptedCredential.Credential,
			Secret:     beginResp.Response.ChallengeRequest.GetTpm().EncryptedCredential.Secret,
		})
		assert.Nil(t, err)

		_, err = fctr.FinishRegistration(ctx, &authenticators.FinishRegistrationReq{

			ChallengeRequest: beginResp.Response.ChallengeRequest,
			Resp: &authv1.RegisterAuthenticatorFinishRequest{
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Tpm{
						Tpm: &authv1.ChallengeResponse_TPM{
							Response: secret,
						},
					},
				},
			},
		})

		assert.Nil(t, err)

		_, err = fctr.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
		assert.Nil(t, err)
	}

	{
		authn, err := tst.C.OcteliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Authenticator_Spec{
				State: corev1.Authenticator_Spec_ACTIVE,
			},
			Status: &corev1.Authenticator_Status{
				UserRef: umetav1.GetObjectReference(usr.Usr),
				Type:    corev1.Authenticator_Status_TPM,
			},
		})
		assert.Nil(t, err)

		authn.Status.AuthenticationAttempt = &corev1.Authenticator_Status_AuthenticationAttempt{
			CreatedAt: pbutils.Now(),
		}

		_, err = fctr.BeginRegistration(ctx, &authenticators.BeginRegistrationReq{

			Req: &authv1.RegisterAuthenticatorBeginRequest{
				PreChallenge: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge{
					Type: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_Tpm{
						Tpm: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM{
							EkType: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM_EkPublicKey{
								EkPublicKey: ekBytes,
							},
							AkBytes: akBytes,
							AttestationParameters: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM_AttestationParameters{
								Public:            attestParams.Public,
								CreateData:        attestParams.CreateData,
								CreateAttestation: attestParams.CreateAttestation,
								CreateSignature:   attestParams.CreateSignature,
							},
						},
					},
				},
			},
		})
		assert.NotNil(t, err)
	}

}

func TestTPMEndorsement(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(tst.C.OcteliumC)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	sim, err := simulator.Get()
	assert.Nil(t, err)
	vTPM := attest.InjectSimulatedTPMForTest(sim)
	defer vTPM.Close()

	eks, err := vTPM.EKs()
	assert.Nil(t, err)

	ek := eks[0]

	ekBytes, err := x509.MarshalPKIXPublicKey(ek.Public)
	assert.Nil(t, err)

	rootCA, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	rootCAPEM, err := rootCA.GetCertPEM()
	assert.Nil(t, err)

	ekCert := generateEKCert(t, &ekCertOpts{
		parent:       rootCA,
		pub:          ek.Public,
		manufacturer: "id:49465800",
		model:        "SLB9670",
		version:      "id:00070055",
	})

	newAuthenticator := func() *corev1.Authenticator {
		ret, err := tst.C.OcteliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Authenticator_Spec{
				State: corev1.Authenticator_Spec_ACTIVE,
			},
			Status: &corev1.Authenticator_Status{
				UserRef: umetav1.GetObjectReference(usr.Usr),
				Type:    corev1.Authenticator_Status_TPM,
			},
		})
		assert.Nil(t, err)

		ret.Status.AuthenticationAttempt = &corev1.Authenticator_Status_AuthenticationAttempt{
			CreatedAt: pbutils.Now(),
		}

		return ret
	}

	ak, err := vTPM.NewAK(&attest.AKConfig{})
	assert.Nil(t, err)
	defer ak.Close(vTPM)

	akBytes, err := ak.Marshal()
	assert.Nil(t, err)

	attestParams := ak.AttestationParameters()

	newPreChallenge := func(withCert bool) *authv1.RegisterAuthenticatorBeginRequest_PreChallenge {
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

		if withCert {
			ret.GetTpm().EkType = &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM_EkCertificateDER{
				EkCertificateDER: ekCert.Raw,
			}
		} else {
			ret.GetTpm().EkType = &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM_EkPublicKey{
				EkPublicKey: ekBytes,
			}
		}

		return ret
	}

	{
		cc.Spec.Authenticator = nil

		authn := newAuthenticator()

		fctr, err := NewFactor(ctx, &authenticators.Opts{
			ClusterConfig: cc,
			OcteliumC:     tst.C.OcteliumC,
			User:          usr.Usr,
			Authenticator: authn,
		})
		assert.Nil(t, err)

		_, err = fctr.BeginRegistration(ctx, &authenticators.BeginRegistrationReq{
			Req: &authv1.RegisterAuthenticatorBeginRequest{
				PreChallenge: newPreChallenge(false),
			},
		})
		assert.Nil(t, err)

		endorsement := authn.Status.Info.GetTpm().Endorsement
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_NO_CERTIFICATE,
			endorsement.Verification)
		assert.Equal(t, ekBytes, authn.Status.Info.GetTpm().EkPublicKey)
	}

	{
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			Tpm: &corev1.ClusterConfig_Spec_Authenticator_TPM{
				EndorsementTrust: &corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust{
					Mode:       corev1.ClusterConfig_Spec_Authenticator_TPM_EndorsementTrust_REQUIRE_VERIFIED,
					TrustedCAs: []string{rootCAPEM},
				},
			},
		}

		authn := newAuthenticator()

		fctr, err := NewFactor(ctx, &authenticators.Opts{
			ClusterConfig: cc,
			OcteliumC:     tst.C.OcteliumC,
			User:          usr.Usr,
			Authenticator: authn,
		})
		assert.Nil(t, err)

		_, err = fctr.BeginRegistration(ctx, &authenticators.BeginRegistrationReq{
			Req: &authv1.RegisterAuthenticatorBeginRequest{
				PreChallenge: newPreChallenge(false),
			},
		})
		assert.NotNil(t, err)
	}

	{
		authn := newAuthenticator()

		fctr, err := NewFactor(ctx, &authenticators.Opts{
			ClusterConfig: cc,
			OcteliumC:     tst.C.OcteliumC,
			User:          usr.Usr,
			Authenticator: authn,
		})
		assert.Nil(t, err)

		preChallenge := newPreChallenge(true)

		beginResp, err := fctr.BeginRegistration(ctx, &authenticators.BeginRegistrationReq{
			Req: &authv1.RegisterAuthenticatorBeginRequest{
				PreChallenge: preChallenge,
			},
		})
		assert.Nil(t, err)

		endorsement := authn.Status.Info.GetTpm().Endorsement
		assert.Equal(t, corev1.Authenticator_Status_Info_TPM_Endorsement_VERIFIED,
			endorsement.Verification)

		ekCertSum := sha256.Sum256(ekCert.Raw)
		rootSum := sha256.Sum256(rootCA.Certificate.Raw)

		assert.Equal(t, ekCertSum[:], endorsement.CertificateSHA256)
		assert.Equal(t, rootSum[:], endorsement.TrustedCASHA256)
		assert.Equal(t, uint32(1229346816), endorsement.ManufacturerID)
		assert.Equal(t, "Infineon", endorsement.Manufacturer)
		assert.Equal(t, "SLB9670", endorsement.Model)
		assert.NotNil(t, endorsement.VerifiedAt)

		assert.Equal(t, ekBytes, authn.Status.Info.GetTpm().EkPublicKey)
		assert.Equal(t, akBytes, authn.Status.Info.GetTpm().AkBytes)

		secret, err := ak.ActivateCredential(vTPM, attest.EncryptedCredential{
			Credential: beginResp.Response.ChallengeRequest.GetTpm().EncryptedCredential.Credential,
			Secret:     beginResp.Response.ChallengeRequest.GetTpm().EncryptedCredential.Secret,
		})
		assert.Nil(t, err)

		_, err = fctr.FinishRegistration(ctx, &authenticators.FinishRegistrationReq{
			ChallengeRequest: beginResp.Response.ChallengeRequest,
			Resp: &authv1.RegisterAuthenticatorFinishRequest{
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Tpm{
						Tpm: &authv1.ChallengeResponse_TPM{
							Response: secret,
						},
					},
				},
			},
		})
		assert.Nil(t, err)
	}
}
