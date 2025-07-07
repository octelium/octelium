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
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticator(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, fakeC.OcteliumC, cc)
	assert.Nil(t, err)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	{
		_, err = srv.doCreateAuthenticator(ctx, &authv1.CreateAuthenticatorRequest{})
		assert.NotNil(t, err)

		assert.True(t, grpcerr.IsUnauthenticated(err))
	}
	{
		_, err = srv.doListAuthenticator(ctx, &authv1.ListAuthenticatorOptions{})
		assert.NotNil(t, err)

		assert.True(t, grpcerr.IsUnauthenticated(err))
	}
	{
		_, err = srv.doDeleteAuthenticator(ctx, &metav1.DeleteOptions{
			Uid: vutils.UUIDv4(),
		})
		assert.NotNil(t, err)

		assert.True(t, grpcerr.IsUnauthenticated(err))
	}
	{
		_, err = srv.doCreateAuthenticator(ctx, &authv1.CreateAuthenticatorRequest{})
		assert.NotNil(t, err)

		assert.True(t, grpcerr.IsUnauthenticated(err))
	}

	{
		usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		usrT.Session.Status.Type = corev1.Session_Status_CLIENTLESS
		usrT.Session.Status.IsBrowser = true
		usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
		assert.Nil(t, err)

		usr2T, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		usr2T.Session.Status.Type = corev1.Session_Status_CLIENTLESS
		usr2T.Session.Status.IsBrowser = true
		usr2T.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usr2T.Session)
		assert.Nil(t, err)

		itmList, err := srv.doListAuthenticator(getCtxRT(usrT), &authv1.ListAuthenticatorOptions{})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, len(itmList.Items))

		{
			_, err = srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{})
			assert.NotNil(t, err)

			assert.True(t, grpcerr.IsInvalidArg(err))
		}
		{
			_, err = srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{})
			assert.NotNil(t, err)

			assert.True(t, grpcerr.IsInvalidArg(err))
		}

		/*
			factor, err := srv.octeliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},

				Spec: &corev1.IdentityProvider_Spec{
					Type: &corev1.IdentityProvider_Spec_Totp{
						Totp: &corev1.IdentityProvider_Spec_TOTP{},
					},
				},
				Status: &corev1.IdentityProvider_Status{
					Type: corev1.IdentityProvider_Status_TOTP,
				},
			})
			assert.Nil(t, err)
		*/

		authn, err := srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{
			Type: authv1.Authenticator_Status_FIDO,
		})
		assert.Nil(t, err, "%+v", err)

		itmList, err = srv.doListAuthenticator(getCtxRT(usrT), &authv1.ListAuthenticatorOptions{})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(itmList.Items))
		assert.Equal(t, authn.Metadata.Uid, itmList.Items[0].Metadata.Uid)

		{
			itmList, err = srv.doListAuthenticator(getCtxRT(usr2T), &authv1.ListAuthenticatorOptions{})
			assert.Nil(t, err)
			assert.Equal(t, 0, len(itmList.Items))

			_, err = srv.doDeleteAuthenticator(getCtxRT(usr2T), &metav1.DeleteOptions{
				Name: authn.Metadata.Name,
			})
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsNotFound(err))
		}

		_, err = srv.doDeleteAuthenticator(getCtxRT(usrT), &metav1.DeleteOptions{
			Name: authn.Metadata.Name,
		})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.doDeleteAuthenticator(getCtxRT(usrT), &metav1.DeleteOptions{
			Name: authn.Metadata.Name,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}
}
