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
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func tstGenCredentialUser(ctx context.Context, t *testing.T, srv *Server, typ corev1.User_Spec_Type) *corev1.User {
	usr := tests.GenUser(nil)
	usr.Spec.Type = typ
	usr, err := srv.CreateUser(ctx, usr)
	assert.Nil(t, err, "%+v", err)
	return usr
}

func tstGenCredential(user string, typ corev1.Credential_Spec_Type) *corev1.Credential {
	return &corev1.Credential{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Credential_Spec{
			User: user,
			Type: typ,
		},
	}
}

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
				Type: corev1.Credential_Spec_AUTH_TOKEN,
				User: "does-not-exist",
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		usr := tstGenCredentialUser(ctx, t, srv, corev1.User_Spec_HUMAN)
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
		assert.Nil(t, err, "%+v", err)

		tknResp, err := srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err, "%+v", err)

		jwkCtl, err := jwkctl.NewJWKController(ctx, tst.C.OcteliumC, nil)
		assert.Nil(t, err)

		claims, err := jwkCtl.VerifyCredential(tknResp.GetAuthenticationToken().AuthenticationToken)
		assert.Nil(t, err)

		tkn, err := srv.GetCredential(ctx, &metav1.GetOptions{Uid: claims.UID})
		assert.Nil(t, err)
		assert.Equal(t, tkn.Status.UserRef.Uid, usr.Metadata.Uid)
		assert.Equal(t, tkn.Status.TokenID, claims.TokenID)
		assert.Equal(t, corev1.Credential_Spec_AUTH_TOKEN, tkn.Spec.Type)
		assert.Equal(t, uint32(1), tkn.Status.TotalRotations)

		_, err = srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err, "%+v", err)

		tkn, err = srv.GetCredential(ctx, &metav1.GetOptions{Uid: cred.Metadata.Uid})
		assert.Nil(t, err)
		assert.Equal(t, uint32(2), tkn.Status.TotalRotations)
		assert.NotEqual(t, claims.TokenID, tkn.Status.TokenID)

		_, err = srv.DeleteCredential(ctx, &metav1.DeleteOptions{Uid: claims.UID})
		assert.Nil(t, err)
	}

	{
		usr := tstGenCredentialUser(ctx, t, srv, corev1.User_Spec_HUMAN)
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
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		usr := tstGenCredentialUser(ctx, t, srv, corev1.User_Spec_WORKLOAD)
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
		assert.Nil(t, err, "%+v", err)

		tknResp, err := srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.Nil(t, err)

		jwkCtl, err := jwkctl.NewJWKController(ctx, tst.C.OcteliumC, nil)
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
		usr := tstGenCredentialUser(ctx, t, srv, corev1.User_Spec_WORKLOAD)
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
		assert.Nil(t, err, "%+v", err)

		{
			tknResp, err := srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
				CredentialRef: umetav1.GetObjectReference(cred),
			})
			assert.Nil(t, err)

			jwkCtl, err := jwkctl.NewJWKController(ctx, tst.C.OcteliumC, nil)
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

			jwkCtl, err := jwkctl.NewJWKController(ctx, tst.C.OcteliumC, nil)
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

func TestValidateCredential(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	human := tstGenCredentialUser(ctx, t, srv, corev1.User_Spec_HUMAN)
	workload := tstGenCredentialUser(ctx, t, srv, corev1.User_Spec_WORKLOAD)

	policy, err := srv.CreatePolicy(ctx, &corev1.Policy{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{
							MatchAny: true,
						},
					},
					Effect: corev1.Policy_Spec_Rule_ALLOW,
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	invalids := []*corev1.Credential{
		{},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		},
		{
			Spec: &corev1.Credential_Spec{
				User: human.Metadata.Name,
				Type: corev1.Credential_Spec_AUTH_TOKEN,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User: human.Metadata.Name,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User: human.Metadata.Name,
				Type: corev1.Credential_Spec_Type(1000),
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User:        human.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_Type(1000),
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				Type: corev1.Credential_Spec_AUTH_TOKEN,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User: utilrand.GetRandomStringCanonical(8),
				Type: corev1.Credential_Spec_AUTH_TOKEN,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User: human.Metadata.Name,
				Type: corev1.Credential_Spec_OAUTH2,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User: human.Metadata.Name,
				Type: corev1.Credential_Spec_ACCESS_TOKEN,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User:      human.Metadata.Name,
				Type:      corev1.Credential_Spec_AUTH_TOKEN,
				ExpiresAt: pbutils.Timestamp(time.Now().Add(-time.Hour)),
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User:      human.Metadata.Name,
				Type:      corev1.Credential_Spec_AUTH_TOKEN,
				ExpiresAt: pbutils.Timestamp(time.Now().Add(credMaxExpiryDuration + time.Hour*24)),
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User:               human.Metadata.Name,
				Type:               corev1.Credential_Spec_AUTH_TOKEN,
				MaxAuthentications: credMaxAuthentications + 1,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User:       human.Metadata.Name,
				Type:       corev1.Credential_Spec_AUTH_TOKEN,
				AutoDelete: true,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User: human.Metadata.Name,
				Type: corev1.Credential_Spec_AUTH_TOKEN,
				Authorization: &corev1.Credential_Spec_Authorization{
					Policies: []string{utilrand.GetRandomStringCanonical(8)},
				},
			},
		},
	}

	for _, invalid := range invalids {
		_, err = srv.CreateCredential(ctx, invalid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	valids := []*corev1.Credential{
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User: human.Metadata.Name,
				Type: corev1.Credential_Spec_AUTH_TOKEN,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User:        human.Metadata.Name,
				Type:        corev1.Credential_Spec_AUTH_TOKEN,
				SessionType: corev1.Session_Status_CLIENTLESS,
				ExpiresAt:   pbutils.Timestamp(time.Now().Add(time.Hour)),
				IsDisabled:  true,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User:               human.Metadata.Name,
				Type:               corev1.Credential_Spec_AUTH_TOKEN,
				MaxAuthentications: 10,
				AutoDelete:         true,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User: workload.Metadata.Name,
				Type: corev1.Credential_Spec_OAUTH2,
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Credential_Spec{
				User: workload.Metadata.Name,
				Type: corev1.Credential_Spec_ACCESS_TOKEN,
				Authorization: &corev1.Credential_Spec_Authorization{
					Policies: []string{policy.Metadata.Name},
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Name: utilrand.GetRandomStringCanonical(8),
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
										Effect: corev1.Policy_Spec_Rule_ALLOW,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, valid := range valids {
		item, err := srv.CreateCredential(ctx, valid)
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, item.Status.UserRef)
		assert.NotEmpty(t, item.Status.Id)

		_, err = srv.CreateCredential(ctx, valid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err), "%+v", err)
	}
}

func TestUpdateCredential(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	usr := tstGenCredentialUser(ctx, t, srv, corev1.User_Spec_WORKLOAD)
	usr2 := tstGenCredentialUser(ctx, t, srv, corev1.User_Spec_WORKLOAD)

	cred, err := srv.CreateCredential(ctx, tstGenCredential(usr.Metadata.Name, corev1.Credential_Spec_AUTH_TOKEN))
	assert.Nil(t, err, "%+v", err)

	{
		cred.Spec.MaxAuthentications = 42
		cred.Spec.IsDisabled = true
		updated, err := srv.UpdateCredential(ctx, cred)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, uint32(42), updated.Spec.MaxAuthentications)
		assert.True(t, updated.Spec.IsDisabled)
		assert.Equal(t, usr.Metadata.Uid, updated.Status.UserRef.Uid)
		cred = updated
	}

	{
		item := tstCloneCredential(cred)
		item.Spec.Type = corev1.Credential_Spec_OAUTH2
		_, err = srv.UpdateCredential(ctx, item)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		item := tstCloneCredential(cred)
		item.Spec.User = usr2.Metadata.Name
		_, err = srv.UpdateCredential(ctx, item)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		item := tstCloneCredential(cred)
		item.Spec.Type = corev1.Credential_Spec_TYPE_UNKNOWN
		_, err = srv.UpdateCredential(ctx, item)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		item := tstGenCredential(usr.Metadata.Name, corev1.Credential_Spec_AUTH_TOKEN)
		_, err = srv.UpdateCredential(ctx, item)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
	}
}

func TestListCredential(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	usr := tstGenCredentialUser(ctx, t, srv, corev1.User_Spec_WORKLOAD)
	usr2 := tstGenCredentialUser(ctx, t, srv, corev1.User_Spec_WORKLOAD)

	for i := 0; i < 3; i++ {
		_, err = srv.CreateCredential(ctx, tstGenCredential(usr.Metadata.Name, corev1.Credential_Spec_AUTH_TOKEN))
		assert.Nil(t, err, "%+v", err)
	}

	_, err = srv.CreateCredential(ctx, tstGenCredential(usr2.Metadata.Name, corev1.Credential_Spec_AUTH_TOKEN))
	assert.Nil(t, err, "%+v", err)

	{
		itemList, err := srv.ListCredential(ctx, &corev1.ListCredentialOptions{})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, len(itemList.Items) >= 4)
	}

	{
		itemList, err := srv.ListCredential(ctx, &corev1.ListCredentialOptions{
			UserRef: umetav1.GetObjectReference(usr),
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 3, len(itemList.Items))
		for _, item := range itemList.Items {
			assert.Equal(t, usr.Metadata.Uid, item.Status.UserRef.Uid)
		}
	}

	{
		_, err := srv.ListCredential(ctx, &corev1.ListCredentialOptions{
			UserRef: &metav1.ObjectReference{
				Uid: utilrand.GetRandomStringCanonical(8),
			},
		})
		assert.NotNil(t, err)
	}
}

func TestGenerateCredentialToken(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	usr := tstGenCredentialUser(ctx, t, srv, corev1.User_Spec_WORKLOAD)

	{
		_, err = srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{})
		assert.NotNil(t, err)
	}

	{
		_, err = srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: &metav1.ObjectReference{
				Uid: utilrand.GetRandomStringCanonical(8),
			},
		})
		assert.NotNil(t, err)
	}

	{
		cred, err := srv.CreateCredential(ctx, &corev1.Credential{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Credential_Spec{
				User:       usr.Metadata.Name,
				Type:       corev1.Credential_Spec_AUTH_TOKEN,
				IsDisabled: true,
			},
		})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.GenerateCredentialToken(ctx, &corev1.GenerateCredentialTokenRequest{
			CredentialRef: umetav1.GetObjectReference(cred),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}
}

func tstCloneCredential(arg *corev1.Credential) *corev1.Credential {
	return &corev1.Credential{
		Metadata: &metav1.Metadata{
			Name: arg.Metadata.Name,
			Uid:  arg.Metadata.Uid,
		},
		Spec: &corev1.Credential_Spec{
			User:               arg.Spec.User,
			Type:               arg.Spec.Type,
			MaxAuthentications: arg.Spec.MaxAuthentications,
			SessionType:        arg.Spec.SessionType,
			IsDisabled:         arg.Spec.IsDisabled,
			AutoDelete:         arg.Spec.AutoDelete,
		},
	}
}
