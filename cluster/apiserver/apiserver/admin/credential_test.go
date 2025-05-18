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

package admin

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestCredential(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	{
		_, err = srv.CreateCredential(ctx, &corev1.Credential{})
		assert.NotNil(t, err)
	}

	{
		_, err = srv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User: "does-not-exist",
			},
		})
		assert.NotNil(t, err)
	}

	{
		usr := tests.GenUser(nil)
		usr, err = srv.CreateUser(ctx, usr)
		assert.Nil(t, err)
		cred, err := srv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usr.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENT,
			},
		})
		assert.Nil(t, err)

		tknResp, err := srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err, "%+v", err)

		jwkCtl, err := jwkctl.NewJWKController(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		claims, err := jwkCtl.VerifyCredential(tknResp.GetAuthenticationToken().AuthenticationToken)
		assert.Nil(t, err)

		tkn, err := srv.GetCredential(ctx, &metav1.GetOptions{Uid: claims.UID})
		assert.Nil(t, err)
		assert.Equal(t, tkn.Status.UserRef.Uid, usr.Metadata.Uid)
		assert.Equal(t, tkn.Status.TokenID, claims.TokenID)
		assert.Equal(t, corev1.Credential_Spec_AUTH_TOKEN, tkn.Spec.Type)

		_, err = srv.DeleteCredential(ctx, &metav1.DeleteOptions{Uid: claims.UID})
		assert.Nil(t, err)

	}

	{
		usr := tests.GenUser(nil)
		_, err = srv.CreateUser(ctx, usr)
		assert.Nil(t, err)
		_, err := srv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usr.Metadata.Name,
				SessionType: corev1.Session_Status_CLIENT,
			},
		})
		assert.NotNil(t, err)
	}

	{
		usr := tests.GenUser(nil)
		_, err = srv.CreateUser(ctx, usr)
		assert.Nil(t, err)
		cred, err := srv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usr.Metadata.Name,
				Type:        corev1.Credential_Spec_OAUTH2,
				SessionType: corev1.Session_Status_CLIENT,
			},
		})
		assert.Nil(t, err)

		tknResp, err := srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		jwkCtl, err := jwkctl.NewJWKController(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		claims, err := jwkCtl.VerifyCredential(tknResp.GetOauth2Credentials().ClientSecret)
		assert.Nil(t, err)

		tkn, err := srv.GetCredential(ctx, &metav1.GetOptions{Uid: claims.UID})
		assert.Nil(t, err)

		assert.Equal(t, tkn.Status.Id, tknResp.GetOauth2Credentials().ClientID)
		assert.Equal(t, tkn.Status.TokenID, claims.TokenID)
		assert.Equal(t, corev1.Credential_Spec_OAUTH2, tkn.Spec.Type)

		_, err = srv.DeleteCredential(ctx, &metav1.DeleteOptions{Uid: claims.UID})
		assert.Nil(t, err)

	}

	{
		usr := tests.GenUser(nil)
		_, err = srv.CreateUser(ctx, usr)
		assert.Nil(t, err)
		cred, err := srv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:        usr.Metadata.Name,
				Type:        corev1.Credential_Spec_ACCESS_TOKEN,
				SessionType: corev1.Session_Status_CLIENTLESS,
			},
		})
		assert.Nil(t, err)

		{
			tknResp, err := srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
				CredentialRef: umetav1.GetObjectReference(cred),
			})
			assert.Nil(t, err)

			jwkCtl, err := jwkctl.NewJWKController(ctx, tst.C.OcteliumC)
			assert.Nil(t, err)

			claims, err := jwkCtl.VerifyAccessToken(tknResp.GetAccessToken().AccessToken)
			assert.Nil(t, err)

			sess, err := srv.GetSession(ctx, &metav1.GetOptions{Uid: claims.SessionUID})
			assert.Nil(t, err)

			assert.Equal(t, cred.Metadata.Uid, sess.Status.CredentialRef.Uid)
			assert.Equal(t, claims.TokenID, sess.Status.Authentication.TokenID)
			assert.Equal(t, uint32(1), sess.Status.TotalAuthentications)
		}

		{
			tknResp, err := srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
				CredentialRef: umetav1.GetObjectReference(cred),
			})
			assert.Nil(t, err)

			jwkCtl, err := jwkctl.NewJWKController(ctx, tst.C.OcteliumC)
			assert.Nil(t, err)

			claims, err := jwkCtl.VerifyAccessToken(tknResp.GetAccessToken().AccessToken)
			assert.Nil(t, err)

			sess, err := srv.GetSession(ctx, &metav1.GetOptions{Uid: claims.SessionUID})
			assert.Nil(t, err)

			assert.Equal(t, cred.Metadata.Uid, sess.Status.CredentialRef.Uid)
			assert.Equal(t, claims.TokenID, sess.Status.Authentication.TokenID)
			assert.Equal(t, uint32(2), sess.Status.TotalAuthentications)
		}

		_, err = srv.DeleteCredential(ctx, &metav1.DeleteOptions{Uid: cred.Metadata.Uid})
		assert.Nil(t, err)

		_, err = srv.DeleteCredential(ctx, &metav1.DeleteOptions{Uid: cred.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

}
