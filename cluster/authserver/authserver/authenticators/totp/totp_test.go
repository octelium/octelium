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

package totp

import (
	"context"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestTOTP(t *testing.T) {

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
		Spec: &corev1.Authenticator_Spec{},
		Status: &corev1.Authenticator_Status{
			// IdentityProviderRef: umetav1.GetObjectReference(factor),
			UserRef: umetav1.GetObjectReference(usr.Usr),
		},
	})
	assert.Nil(t, err)

	fctr, err := NewFactor(ctx, &authenticators.Opts{
		ClusterConfig: cc,
		OcteliumC:     tst.C.OcteliumC,
		User:          usr.Usr,
		Authenticator: &corev1.Authenticator{
			Metadata: &metav1.Metadata{
				Name: "auth1",
			},
			Spec:   &corev1.Authenticator_Spec{},
			Status: &corev1.Authenticator_Status{},
		},
	})
	assert.Nil(t, err)

	req, err := fctr.BeginRegistration(ctx, &authenticators.BeginRegistrationReq{})
	assert.Nil(t, err)

	k, err := otp.NewKeyFromURL(req.Response.ChallengeRequest.GetTotp().Url)
	assert.Nil(t, err)

	authn, err = tst.C.OcteliumC.CoreC().UpdateAuthenticator(ctx, authn)
	assert.Nil(t, err)

	{
		passcode, err := totp.GenerateCode(k.Secret(), time.Now())
		assert.Nil(t, err)

		_, err = fctr.FinishRegistration(ctx, &authenticators.FinishRegistrationReq{
			ChallengeRequest: req.Response.ChallengeRequest,
			Resp: &authv1.RegisterAuthenticatorFinishRequest{
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Totp{
						Totp: &authv1.ChallengeResponse_TOTP{
							Response: passcode,
						},
					},
				},
			},
		})

		assert.Nil(t, err)

		authn.Status.SuccessfulAuthentications = authn.Status.SuccessfulAuthentications + 1
	}

	{
		// Again to get the secret from the User auth factor state
		req, err := fctr.Begin(ctx, &authenticators.BeginReq{})
		assert.Nil(t, err)

		passcode, err := totp.GenerateCode(k.Secret(), time.Now())
		assert.Nil(t, err)

		_, err = fctr.Finish(ctx, &authenticators.FinishReq{

			ChallengeRequest: req.Response.ChallengeRequest,
			Resp: &authv1.AuthenticateWithAuthenticatorRequest{
				ChallengeResponse: &authv1.ChallengeResponse{
					Type: &authv1.ChallengeResponse_Totp{
						Totp: &authv1.ChallengeResponse_TOTP{
							Response: passcode,
						},
					},
				},
			},
		})

		assert.Nil(t, err)
	}

}
