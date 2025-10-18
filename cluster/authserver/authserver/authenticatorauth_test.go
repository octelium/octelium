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

package authserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestHandleBeginAuthenticator(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err, "%+v", err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		_, err = srv.doRegisterAuthenticatorBegin(context.Background(), &authv1.RegisterAuthenticatorBeginRequest{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}
	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		_, err = srv.doRegisterAuthenticatorBegin(getCtxRT(usrT), &authv1.RegisterAuthenticatorBeginRequest{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		_, err = srv.doRegisterAuthenticatorBegin(getCtxRT(usrT), &authv1.RegisterAuthenticatorBeginRequest{
			AuthenticatorRef: &metav1.ObjectReference{
				Uid: vutils.UUIDv4(),
			},
		})
		assert.NotNil(t, err)
		// assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		authn, err := srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Authenticator_Spec{},
			Status: &corev1.Authenticator_Status{
				UserRef: umetav1.GetObjectReference(usrT.Usr),
				Type:    corev1.Authenticator_Status_TOTP,
			},
		})
		assert.Nil(t, err)

		{
			resp, err := srv.doRegisterAuthenticatorBegin(getCtxRT(usrT), &authv1.RegisterAuthenticatorBeginRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
			})
			assert.Nil(t, err, "%+v", err)
			assert.NotNil(t, resp.ChallengeRequest.GetTotp())

			authn, err := srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
				Uid: authn.Metadata.Uid,
			})
			assert.Nil(t, err)

			assert.NotNil(t, authn.Status.AuthenticationAttempt.EncryptedChallengeRequest)
			reqBytes, err := authenticators.DecryptData(ctx, srv.octeliumC, authn.Status.AuthenticationAttempt.EncryptedChallengeRequest)
			assert.Nil(t, err)
			req := &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest{}
			err = pbutils.Unmarshal(reqBytes, req)
			assert.Nil(t, err)
			assert.True(t, pbutils.IsEqual(req, resp.ChallengeRequest))

			k, err := otp.NewKeyFromURL(req.GetTotp().Url)
			assert.Nil(t, err)

			passcode, err := totp.GenerateCode(k.Secret(), time.Now())
			assert.Nil(t, err)

			_, err = srv.doRegisterAuthenticatorFinish(getCtxRT(usrT), &authv1.RegisterAuthenticatorFinishRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Totp{
						Totp: &authv1.ChallengeResponse_TOTP{
							Response: passcode,
						},
					},
				},
			})
			assert.Nil(t, err)

			authn, err = srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
				Uid: authn.Metadata.Uid,
			})
			assert.Nil(t, err)

			assert.True(t, authn.Status.IsRegistered)
		}
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		usrT2, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		authn, err := srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Authenticator_Spec{},
			Status: &corev1.Authenticator_Status{
				UserRef: umetav1.GetObjectReference(usrT2.Usr),
				Type:    corev1.Authenticator_Status_TOTP,
			},
		})
		assert.Nil(t, err)
		{
			_, err := srv.doRegisterAuthenticatorBegin(getCtxRT(usrT), &authv1.RegisterAuthenticatorBeginRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
			})
			assert.NotNil(t, err)
			// assert.True(t, grpcerr.IsInvalidArg(err))
		}
	}

}

func TestCheckAuthenticatorRateLimit(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		authn, err := srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Authenticator_Spec{},
			Status: &corev1.Authenticator_Status{
				UserRef: umetav1.GetObjectReference(usrT.Usr),
				Type:    corev1.Authenticator_Status_TOTP,
			},
		})
		assert.Nil(t, err)

		for i := range 32 {
			err := srv.checkAuthenticatorRateLimit(ctx, authn)
			time.Sleep(100 * time.Millisecond)
			if i < 20 {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		}

	}

}

func TestAuthenticatorRegistration(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err, "%+v", err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		authnT, err := srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{
			Type: authv1.Authenticator_Status_TOTP,
		})
		assert.Nil(t, err)

		authn, err := srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
			Uid: authnT.Metadata.Uid,
		})
		assert.Nil(t, err)

		assert.Equal(t, usrT.Usr.Metadata.Uid, authn.Status.UserRef.Uid)
		assert.Equal(t, corev1.Authenticator_Status_TOTP, authn.Status.Type)
		assert.False(t, authn.Status.IsRegistered)

		{
			_, err := srv.doRegisterAuthenticatorBegin(getCtxRT(usrT), &authv1.RegisterAuthenticatorBeginRequest{})
			assert.NotNil(t, err, "%+v", err)
		}

		{
			_, err := srv.doRegisterAuthenticatorFinish(getCtxRT(usrT), &authv1.RegisterAuthenticatorFinishRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
			})
			assert.NotNil(t, err, "%+v", err)
		}

		{
			_, err := srv.doRegisterAuthenticatorFinish(getCtxRT(usrT), &authv1.RegisterAuthenticatorFinishRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Totp{
						Totp: &authv1.ChallengeResponse_TOTP{
							Response: "123456",
						},
					},
				},
			})
			assert.NotNil(t, err, "%+v", err)
		}

		resp, err := srv.doRegisterAuthenticatorBegin(getCtxRT(usrT), &authv1.RegisterAuthenticatorBeginRequest{
			AuthenticatorRef: umetav1.GetObjectReference(authn),
		})
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, resp.ChallengeRequest.GetTotp())

		authn, err = srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
			Uid: authn.Metadata.Uid,
		})
		assert.Nil(t, err)

		assert.NotNil(t, authn.Status.AuthenticationAttempt.EncryptedChallengeRequest)
		reqBytes, err := authenticators.DecryptData(ctx, srv.octeliumC, authn.Status.AuthenticationAttempt.EncryptedChallengeRequest)
		assert.Nil(t, err)
		req := &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest{}
		err = pbutils.Unmarshal(reqBytes, req)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(req, resp.ChallengeRequest))

		k, err := otp.NewKeyFromURL(req.GetTotp().Url)
		assert.Nil(t, err)

		passcode, err := totp.GenerateCode(k.Secret(), time.Now())
		assert.Nil(t, err)

		_, err = srv.doRegisterAuthenticatorFinish(getCtxRT(usrT), &authv1.RegisterAuthenticatorFinishRequest{
			AuthenticatorRef: umetav1.GetObjectReference(authn),
			ChallengeResponse: &authv1.ChallengeResponse{
				Type: &authv1.ChallengeResponse_Totp{
					Totp: &authv1.ChallengeResponse_TOTP{
						Response: passcode,
					},
				},
			},
		})
		assert.Nil(t, err)

		authn, err = srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
			Uid: authn.Metadata.Uid,
		})
		assert.Nil(t, err)

		assert.True(t, authn.Status.IsRegistered)
		{
			passcode, err := totp.GenerateCode(k.Secret(), time.Now())
			assert.Nil(t, err)

			_, err = srv.doRegisterAuthenticatorFinish(getCtxRT(usrT), &authv1.RegisterAuthenticatorFinishRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Totp{
						Totp: &authv1.ChallengeResponse_TOTP{
							Response: passcode,
						},
					},
				},
			})
			assert.NotNil(t, err)
		}

		{
			_, err := srv.doRegisterAuthenticatorBegin(getCtxRT(usrT), &authv1.RegisterAuthenticatorBeginRequest{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
			})
			assert.NotNil(t, err, "%+v", err)
		}
	}
}

func TestIsAuthenticationAttemptTimeoutExceeded(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	clusterCfg, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, clusterCfg)
	assert.Nil(t, err, "%+v", err)

	assert.False(t, srv.isAuthenticationAttemptTimeoutExceeded(&corev1.Authenticator{
		Status: &corev1.Authenticator_Status{
			AuthenticationAttempt: &corev1.Authenticator_Status_AuthenticationAttempt{
				CreatedAt: pbutils.Now(),
			},
		},
	}))

	assert.False(t, srv.isAuthenticationAttemptTimeoutExceeded(&corev1.Authenticator{
		Status: &corev1.Authenticator_Status{
			AuthenticationAttempt: &corev1.Authenticator_Status_AuthenticationAttempt{
				CreatedAt: pbutils.Timestamp(time.Now().Add(-1 * time.Minute)),
			},
		},
	}))

	assert.True(t, srv.isAuthenticationAttemptTimeoutExceeded(&corev1.Authenticator{
		Status: &corev1.Authenticator_Status{
			AuthenticationAttempt: &corev1.Authenticator_Status_AuthenticationAttempt{
				CreatedAt: pbutils.Timestamp(time.Now().Add(-25 * time.Minute)),
			},
		},
	}))
}

func TestDoPostAuthenticatorAuthenticationRules(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
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

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err, "%+v", err)

	{
		assert.Nil(t, srv.doPostAuthenticatorAuthenticationRules(ctx, cc, nil, nil, nil, nil))
	}

	{
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			PostAuthenticationRules: []*corev1.ClusterConfig_Spec_Authenticator_Rule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_Rule_DENY,
				},
			},
		}
		assert.NotNil(t, srv.doPostAuthenticatorAuthenticationRules(ctx, cc, nil, nil, nil, nil))
	}

	{
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			PostAuthenticationRules: []*corev1.ClusterConfig_Spec_Authenticator_Rule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_Rule_DENY,
				},

				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_Rule_ALLOW,
				},
			},
		}
		assert.NotNil(t, srv.doPostAuthenticatorAuthenticationRules(ctx, cc, nil, nil, nil, nil))
	}

	{
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			PostAuthenticationRules: []*corev1.ClusterConfig_Spec_Authenticator_Rule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_Rule_ALLOW,
				},

				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_Rule_DENY,
				},
			},
		}
		assert.Nil(t, srv.doPostAuthenticatorAuthenticationRules(ctx, cc, nil, nil, nil, nil))
	}

	{
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			PostAuthenticationRules: []*corev1.ClusterConfig_Spec_Authenticator_Rule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_Rule_ALLOW,
				},
			},
		}
		assert.Nil(t, srv.doPostAuthenticatorAuthenticationRules(ctx, cc, nil, nil, nil, nil))
	}

	{
		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			PostAuthenticationRules: []*corev1.ClusterConfig_Spec_Authenticator_Rule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `ctx.info.aal == "AAL1"`,
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_Rule_DENY,
				},
			},
		}
		assert.NotNil(t, srv.doPostAuthenticatorAuthenticationRules(ctx, cc, nil, nil, nil,
			&corev1.Session_Status_Authentication_Info{
				Aal: corev1.Session_Status_Authentication_Info_AAL1,
			}))
	}

	{

		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			PostAuthenticationRules: []*corev1.ClusterConfig_Spec_Authenticator_Rule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: fmt.Sprintf(`ctx.user.metadata.uid == "%s"`, usrT.Usr.Metadata.Uid),
						},
					},
					Effect: corev1.ClusterConfig_Spec_Authenticator_Rule_DENY,
				},
			},
		}
		assert.NotNil(t, srv.doPostAuthenticatorAuthenticationRules(ctx, cc, nil, usrT.Session, usrT.Usr,
			&corev1.Session_Status_Authentication_Info{
				Aal: corev1.Session_Status_Authentication_Info_AAL1,
			}))
	}
}
