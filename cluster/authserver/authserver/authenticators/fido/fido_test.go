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

package fido

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestBegin(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	fakeC := tst.C

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
			UserRef:               umetav1.GetObjectReference(usr.Usr),
			AuthenticationAttempt: &corev1.Authenticator_Status_AuthenticationAttempt{},
		},
	})
	assert.Nil(t, err)

	t.Run("valid", func(t *testing.T) {

		cc := &corev1.ClusterConfig{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.ClusterConfig_Spec{},
			Status: &corev1.ClusterConfig_Status{
				Domain: "octeliumdomain.xyz",
			},
		}

		webauthnctl, err := NewFactor(ctx, &authenticators.Opts{
			OcteliumC:     tst.C.OcteliumC,
			ClusterConfig: cc,
			Authenticator: authn,
			User:          usr.Usr,
		}, nil)
		assert.Nil(t, err)

		resp, err := webauthnctl.BeginRegistration(context.Background(), &authenticators.BeginRegistrationReq{
			Req: &authv1.RegisterAuthenticatorBeginRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, resp.Response.ChallengeRequest.GetFido())
	})
}

func newTestClusterConfig() *corev1.ClusterConfig {
	return &corev1.ClusterConfig{
		Metadata: &metav1.Metadata{},
		Spec:     &corev1.ClusterConfig_Spec{},
		Status: &corev1.ClusterConfig_Status{
			Domain: "octeliumdomain.xyz",
		},
	}
}

func newTestAuthn(displayName string) *corev1.Authenticator {
	return &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
			Uid:  vutils.UUIDv4(),
		},
		Spec: &corev1.Authenticator_Spec{
			State:       corev1.Authenticator_Spec_ACTIVE,
			DisplayName: displayName,
		},
		Status: &corev1.Authenticator_Status{
			Type:                  corev1.Authenticator_Status_FIDO,
			AuthenticationAttempt: &corev1.Authenticator_Status_AuthenticationAttempt{},
		},
	}
}

func newTestUsr(email, displayName string) *corev1.User {
	return &corev1.User{
		Metadata: &metav1.Metadata{
			Name:        utilrand.GetRandomStringCanonical(8),
			Uid:         vutils.UUIDv4(),
			DisplayName: displayName,
		},
		Spec: &corev1.User_Spec{
			Type:  corev1.User_Spec_HUMAN,
			Email: email,
		},
	}
}

func TestWebauthnUserID(t *testing.T) {

	{
		usr := newTestUsr("", "")
		wu := NewWebAuthnUsr(newTestAuthn(""), usr)

		id := wu.WebAuthnID()
		assert.Equal(t, 16, len(id))

		parsed, err := uuid.Parse(usr.Metadata.Uid)
		assert.Nil(t, err)
		assert.Equal(t, parsed[:], id)
	}

	{
		usr := newTestUsr("", "")
		usr.Metadata.Uid = "not-a-uuid"

		wu := NewWebAuthnUsr(newTestAuthn(""), usr)

		id := wu.WebAuthnID()
		assert.Equal(t, 16, len(id))
		assert.Equal(t, make([]byte, 16), id)
	}
}

func TestWebauthnUserName(t *testing.T) {

	{
		usr := newTestUsr("User@Example.COM", "")
		wu := NewWebAuthnUsr(newTestAuthn(""), usr)
		assert.Equal(t, "user@example.com", wu.WebAuthnName())
	}

	{
		usr := newTestUsr("", "")
		wu := NewWebAuthnUsr(newTestAuthn(""), usr)
		assert.Equal(t, usr.Metadata.Name, wu.WebAuthnName())
	}
}

func TestWebauthnUserDisplayName(t *testing.T) {

	{
		usr := newTestUsr("User@Example.COM", "Meta Display")
		wu := NewWebAuthnUsr(newTestAuthn("Authn Display"), usr)
		assert.Equal(t, "Authn Display", wu.WebAuthnDisplayName())
	}

	{
		usr := newTestUsr("User@Example.COM", "Meta Display")
		wu := NewWebAuthnUsr(newTestAuthn(""), usr)
		assert.Equal(t, "user@example.com", wu.WebAuthnDisplayName())
	}

	{
		usr := newTestUsr("", "Meta Display")
		wu := NewWebAuthnUsr(newTestAuthn(""), usr)
		assert.Equal(t, "Meta Display", wu.WebAuthnDisplayName())
	}

	{
		usr := newTestUsr("", "")
		wu := NewWebAuthnUsr(newTestAuthn(""), usr)
		assert.Equal(t, usr.Metadata.Name, wu.WebAuthnDisplayName())
	}
}

func TestWebauthnUserCredentials(t *testing.T) {

	{
		wu := NewWebAuthnUsr(newTestAuthn(""), newTestUsr("", ""))
		assert.Nil(t, wu.WebAuthnCredentials())
	}

	{
		authn := newTestAuthn("")
		authn.Status.Info = &corev1.Authenticator_Status_Info{}

		wu := NewWebAuthnUsr(authn, newTestUsr("", ""))
		assert.Nil(t, wu.WebAuthnCredentials())
	}

	{
		aaguid := vutils.UUIDv4()
		credID := utilrand.GetRandomBytesMust(32)
		pubKey := utilrand.GetRandomBytesMust(64)

		authn := newTestAuthn("")
		authn.Status.Info = &corev1.Authenticator_Status_Info{
			Type: &corev1.Authenticator_Status_Info_Fido{
				Fido: &corev1.Authenticator_Status_Info_FIDO{
					Id:             credID,
					PublicKey:      pubKey,
					Aaguid:         aaguid,
					SignCount:      42,
					BackupEligible: true,
				},
			},
		}

		wu := NewWebAuthnUsr(authn, newTestUsr("", ""))

		creds := wu.WebAuthnCredentials()
		assert.Equal(t, 1, len(creds))

		cred := creds[0]
		assert.Equal(t, credID, cred.ID)
		assert.Equal(t, pubKey, cred.PublicKey)
		assert.True(t, cred.Flags.BackupEligible)
		assert.Equal(t, uint32(42), cred.Authenticator.SignCount)
		assert.Equal(t, "none", cred.AttestationType)

		parsed, err := uuid.Parse(aaguid)
		assert.Nil(t, err)
		assert.Equal(t, parsed[:], cred.Authenticator.AAGUID)
	}

	{
		authn := newTestAuthn("")
		authn.Status.Info = &corev1.Authenticator_Status_Info{
			Type: &corev1.Authenticator_Status_Info_Fido{
				Fido: &corev1.Authenticator_Status_Info_FIDO{
					Id:     utilrand.GetRandomBytesMust(32),
					Aaguid: "not-a-uuid",
				},
			},
		}

		wu := NewWebAuthnUsr(authn, newTestUsr("", ""))

		creds := wu.WebAuthnCredentials()
		assert.Equal(t, 1, len(creds))
		assert.Equal(t, 16, len(creds[0].Authenticator.AAGUID))
	}
}

func TestDefaultTimeout(t *testing.T) {
	ret := DefaultTimeout()
	assert.True(t, ret.Enforce)
	assert.True(t, ret.Timeout > 0)
	assert.True(t, ret.TimeoutUVD > 0)
	assert.Equal(t, ret.Timeout, ret.TimeoutUVD)
}

func TestGetWebauthnCtl(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	newCtl := func(authn *corev1.Authenticator, cc *corev1.ClusterConfig) *WebAuthNFactor {
		ctl, err := NewFactor(ctx, &authenticators.Opts{
			OcteliumC:     fakeC.OcteliumC,
			ClusterConfig: newTestClusterConfig(),
			Authenticator: authn,
			User:          newTestUsr("", ""),
		}, nil)
		assert.Nil(t, err)
		return ctl
	}

	attestations := []corev1.ClusterConfig_Spec_Authenticator_FIDO_AttestationConveyancePreference{
		corev1.ClusterConfig_Spec_Authenticator_FIDO_ATTESTATION_CONVEYANCE_PREFERENCE_UNSET,
		corev1.ClusterConfig_Spec_Authenticator_FIDO_DIRECT,
		corev1.ClusterConfig_Spec_Authenticator_FIDO_INDIRECT,
		corev1.ClusterConfig_Spec_Authenticator_FIDO_ENTERPRISE,
		corev1.ClusterConfig_Spec_Authenticator_FIDO_NONE,
	}

	for _, attestation := range attestations {
		authn := newTestAuthn("")
		ctl := newCtl(authn, nil)

		cc := newTestClusterConfig()
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			Fido: &corev1.ClusterConfig_Spec_Authenticator_FIDO{
				AttestationConveyancePreference: attestation,
			},
		}

		ret, err := ctl.getWebauthnCtl(authn, cc)
		assert.Nil(t, err, "%v", attestation)
		assert.NotNil(t, ret, "%v", attestation)
	}

	{
		authn := newTestAuthn("")
		ctl := newCtl(authn, nil)

		ret, err := ctl.getWebauthnCtl(authn, nil)
		assert.Nil(t, err)
		assert.NotNil(t, ret)
	}

	{
		authn := newTestAuthn("")
		authn.Status.IsRegistered = true
		authn.Status.Info = &corev1.Authenticator_Status_Info{
			Type: &corev1.Authenticator_Status_Info_Fido{
				Fido: &corev1.Authenticator_Status_Info_FIDO{
					Type: corev1.Authenticator_Status_Info_FIDO_PLATFORM,
				},
			},
		}

		ctl := newCtl(authn, nil)

		ret, err := ctl.getWebauthnCtl(authn, newTestClusterConfig())
		assert.Nil(t, err)
		assert.NotNil(t, ret)
	}

	{
		authn := newTestAuthn("")
		authn.Status.IsRegistered = true
		authn.Status.Info = &corev1.Authenticator_Status_Info{
			Type: &corev1.Authenticator_Status_Info_Fido{
				Fido: &corev1.Authenticator_Status_Info_FIDO{
					Type: corev1.Authenticator_Status_Info_FIDO_ROAMING,
				},
			},
		}

		ctl := newCtl(authn, nil)

		ret, err := ctl.getWebauthnCtl(authn, newTestClusterConfig())
		assert.Nil(t, err)
		assert.NotNil(t, ret)
	}
}

func TestFinishInvalidResponse(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc := newTestClusterConfig()
	authn := newTestAuthn("")

	ctl, err := NewFactor(ctx, &authenticators.Opts{
		OcteliumC:     fakeC.OcteliumC,
		ClusterConfig: cc,
		Authenticator: authn,
		User:          newTestUsr("", ""),
	}, nil)
	assert.Nil(t, err)

	{
		_, err := ctl.Finish(ctx, &authenticators.FinishReq{
			ClusterConfig: cc,
		})
		assert.NotNil(t, err)
		assert.True(t, authenticators.IsErrInvalidAuth(err))
	}

	{
		_, err := ctl.Finish(ctx, &authenticators.FinishReq{
			Resp:          &authv1.AuthenticateWithAuthenticatorRequest{},
			ClusterConfig: cc,
		})
		assert.NotNil(t, err)
		assert.True(t, authenticators.IsErrInvalidAuth(err))
	}

	{
		_, err := ctl.Finish(ctx, &authenticators.FinishReq{
			Resp: &authv1.AuthenticateWithAuthenticatorRequest{
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Fido{
						Fido: &authv1.ChallengeResponse_FIDO{
							Response: "",
						},
					},
				},
			},
			ClusterConfig: cc,
		})
		assert.NotNil(t, err)
		assert.True(t, authenticators.IsErrInvalidAuth(err))
	}

	{
		authn.Status.AuthenticationAttempt = &corev1.Authenticator_Status_AuthenticationAttempt{}

		_, err := ctl.Finish(ctx, &authenticators.FinishReq{
			Resp: &authv1.AuthenticateWithAuthenticatorRequest{
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Fido{
						Fido: &authv1.ChallengeResponse_FIDO{
							Response: utilrand.GetRandomStringCanonical(200),
						},
					},
				},
			},
			ClusterConfig: cc,
		})
		assert.NotNil(t, err)
		assert.True(t, authenticators.IsErrInvalidAuth(err))
	}

	{
		authn.Status.AuthenticationAttempt = &corev1.Authenticator_Status_AuthenticationAttempt{
			DataMap: map[string][]byte{
				"session": []byte("not valid json"),
			},
		}

		_, err := ctl.Finish(ctx, &authenticators.FinishReq{
			Resp: &authv1.AuthenticateWithAuthenticatorRequest{
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Fido{
						Fido: &authv1.ChallengeResponse_FIDO{
							Response: utilrand.GetRandomStringCanonical(200),
						},
					},
				},
			},
			ClusterConfig: cc,
		})
		assert.NotNil(t, err)
	}

	{
		authn.Status.AuthenticationAttempt = &corev1.Authenticator_Status_AuthenticationAttempt{
			DataMap: map[string][]byte{
				"session": []byte(`{"challenge":"abc","user_id":"eHh4"}`),
			},
		}

		_, err := ctl.Finish(ctx, &authenticators.FinishReq{
			Resp: &authv1.AuthenticateWithAuthenticatorRequest{
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Fido{
						Fido: &authv1.ChallengeResponse_FIDO{
							Response: strings.Repeat("a", 200),
						},
					},
				},
			},
			ClusterConfig: cc,
		})
		assert.NotNil(t, err)
		assert.True(t, authenticators.IsErrInvalidAuth(err))
	}
}

func TestFinishRegistrationInvalidResponse(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc := newTestClusterConfig()
	authn := newTestAuthn("")

	ctl, err := NewFactor(ctx, &authenticators.Opts{
		OcteliumC:     fakeC.OcteliumC,
		ClusterConfig: cc,
		Authenticator: authn,
		User:          newTestUsr("", ""),
	}, nil)
	assert.Nil(t, err)

	{
		_, err := ctl.FinishRegistration(ctx, &authenticators.FinishRegistrationReq{
			ClusterConfig: cc,
		})
		assert.NotNil(t, err)
		assert.True(t, authenticators.IsErrInvalidAuth(err))
	}

	{
		_, err := ctl.FinishRegistration(ctx, &authenticators.FinishRegistrationReq{
			Resp:          &authv1.RegisterAuthenticatorFinishRequest{},
			ClusterConfig: cc,
		})
		assert.NotNil(t, err)
		assert.True(t, authenticators.IsErrInvalidAuth(err))
	}

	{
		_, err := ctl.FinishRegistration(ctx, &authenticators.FinishRegistrationReq{
			Resp: &authv1.RegisterAuthenticatorFinishRequest{
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Fido{
						Fido: &authv1.ChallengeResponse_FIDO{
							Response: "",
						},
					},
				},
			},
			ClusterConfig: cc,
		})
		assert.NotNil(t, err)
		assert.True(t, authenticators.IsErrInvalidAuth(err))
	}

	{
		authn.Status.AuthenticationAttempt = &corev1.Authenticator_Status_AuthenticationAttempt{
			DataMap: map[string][]byte{
				"session": []byte(`{"challenge":"abc","user_id":"eHh4"}`),
			},
		}

		_, err := ctl.FinishRegistration(ctx, &authenticators.FinishRegistrationReq{
			Resp: &authv1.RegisterAuthenticatorFinishRequest{
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Fido{
						Fido: &authv1.ChallengeResponse_FIDO{
							Response: strings.Repeat("a", 200),
						},
					},
				},
			},
			ClusterConfig: cc,
		})
		assert.NotNil(t, err)
		assert.True(t, authenticators.IsErrInvalidAuth(err))
	}
}

func TestBeginRegistrationDataMap(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	cc := newTestClusterConfig()
	authn := newTestAuthn("")
	authn.Status.AuthenticationAttempt = &corev1.Authenticator_Status_AuthenticationAttempt{}

	ctl, err := NewFactor(ctx, &authenticators.Opts{
		OcteliumC:     fakeC.OcteliumC,
		ClusterConfig: cc,
		Authenticator: authn,
		User:          newTestUsr("usr@example.com", ""),
	}, nil)
	assert.Nil(t, err)

	resp, err := ctl.BeginRegistration(ctx, &authenticators.BeginRegistrationReq{
		Req:           &authv1.RegisterAuthenticatorBeginRequest{},
		ClusterConfig: cc,
	})
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, resp.Response.ChallengeRequest.GetFido())
	assert.True(t, len(resp.Response.ChallengeRequest.GetFido().Request) > 0)

	assert.NotNil(t, authn.Status.AuthenticationAttempt.DataMap)
	assert.True(t, len(authn.Status.AuthenticationAttempt.DataMap["session"]) > 0)

	{
		resp2, err := ctl.BeginRegistration(ctx, &authenticators.BeginRegistrationReq{
			Req:           &authv1.RegisterAuthenticatorBeginRequest{},
			ClusterConfig: cc,
		})
		assert.Nil(t, err)
		assert.NotEqual(t,
			resp.Response.ChallengeRequest.GetFido().Request,
			resp2.Response.ChallengeRequest.GetFido().Request)
	}
}
