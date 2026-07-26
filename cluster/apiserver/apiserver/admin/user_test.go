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
	"fmt"
	"strings"
	"testing"

	"github.com/gosimple/slug"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestCreateUser(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	validUsers := []*corev1.User{
		{
			Metadata: &metav1.Metadata{Name: "usr-1"},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_WORKLOAD,
			},
		},
	}

	for _, usr := range validUsers {
		outUsr, err := srv.CreateUser(ctx, usr)
		assert.Nil(t, err, "%+v", err)
		assert.True(t, pbutils.IsEqual(usr.Spec, outUsr.Spec))
	}
}

func TestListUser(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	nHuman := utilrand.GetRandomRangeMath(100, 1000)
	nWorkload := utilrand.GetRandomRangeMath(100, 1000)

	{
		usrList, err := srv.ListUser(ctx, &corev1.ListUserOptions{})
		assert.Nil(t, err)
		for _, usr := range usrList.Items {
			_, err = srv.octeliumC.CoreC().DeleteUser(ctx, &rmetav1.DeleteOptions{
				Uid: usr.Metadata.Uid,
			})
			assert.Nil(t, err)
		}
	}

	for i := 0; i < nHuman; i++ {
		_, err := srv.CreateUser(ctx, &corev1.User{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_HUMAN,
			},
		})
		assert.Nil(t, err)
	}

	for i := 0; i < nWorkload; i++ {
		_, err := srv.CreateUser(ctx, &corev1.User{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_WORKLOAD,
			},
		})
		assert.Nil(t, err)
	}

	{
		usrList, err := srv.ListUser(ctx, &corev1.ListUserOptions{})
		assert.Nil(t, err)

		assert.Equal(t, nWorkload+nHuman, int(usrList.ListResponseMeta.TotalCount))
	}
}

func TestDeleteUser(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	usr := &corev1.User{
		Metadata: &metav1.Metadata{Name: "usr-1"},
		Spec: &corev1.User_Spec{
			Type: corev1.User_Spec_WORKLOAD,
		},
	}

	_, err = srv.CreateUser(ctx, usr)
	assert.Nil(t, err, "%+v", err)

	_, err = srv.DeleteUser(ctx, &metav1.DeleteOptions{Name: "usr-1"})
	assert.Nil(t, err, "%+v", err)
}

func TestIdentity(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	usr1 := &corev1.User{
		Metadata: &metav1.Metadata{Name: "usr-1"},
		Spec: &corev1.User_Spec{
			Type: corev1.User_Spec_HUMAN,
			Authentication: &corev1.User_Spec_Authentication{
				Identities: []*corev1.User_Spec_Authentication_Identity{
					{
						IdentityProvider: "github",
						Identifier:       "usr1",
					},
				},
			},
		},
	}

	_, err = srv.CreateUser(ctx, usr1)
	assert.NotNil(t, err, "%+v", err)

	cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	sec, err := srv.octeliumC.CoreC().CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(32),
			},
		},
	})
	assert.Nil(t, err)

	_, err = srv.octeliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name: "github",
		},
		Spec: &corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: "123456",
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	_, err = srv.octeliumC.CoreC().CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{
			Name: "oidc1",
		},
		Spec: &corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Oidc{
				Oidc: &corev1.IdentityProvider_Spec_OIDC{
					ClientID: "123456",
					ClientSecret: &corev1.IdentityProvider_Spec_OIDC_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_OIDC_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	_, err = srv.octeliumC.CoreC().UpdateClusterConfig(ctx, cc)
	assert.Nil(t, err)

	usr1, err = srv.CreateUser(ctx, usr1)
	assert.Nil(t, err, "%+v", err)

	usr2 := &corev1.User{
		Metadata: &metav1.Metadata{Name: "usr-2"},
		Spec: &corev1.User_Spec{
			Type: corev1.User_Spec_HUMAN,
			Authentication: &corev1.User_Spec_Authentication{
				Identities: []*corev1.User_Spec_Authentication_Identity{
					{
						IdentityProvider: "github",
						Identifier:       "usr1",
					},
				},
			},
		},
	}

	_, err = srv.CreateUser(ctx, usr2)
	assert.NotNil(t, err)

	usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, srv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	{
		usr1V, err := tst.C.OcteliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Uid: usr1.Metadata.Uid})
		assert.Nil(t, err)
		assert.Equal(t, "usr1", usr1V.Metadata.SpecLabels["auth-github"])

		usr1.Spec.Authentication = &corev1.User_Spec_Authentication{
			Identities: []*corev1.User_Spec_Authentication_Identity{
				{
					IdentityProvider: "oidc1",
					Identifier:       "user@example.com",
				},
			},
		}

		usr1, err = srv.UpdateUser(usrT.Ctx(), usr1)
		assert.Nil(t, err, "%+v", err)

		usr1V, err = tst.C.OcteliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{Uid: usr1.Metadata.Uid})
		assert.Nil(t, err)
		assert.Equal(t, slug.Make("user@example.com"), usr1V.Metadata.SpecLabels["auth-oidc1"])
		assert.Equal(t, "", usr1V.Metadata.SpecLabels["auth-github"])
	}

	{
		usr, err := srv.CreateUser(ctx, &corev1.User{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.User_Spec{
				Type:  corev1.User_Spec_HUMAN,
				Email: "linus@exmaple.com",
			},
		})
		assert.Nil(t, err, "%+v", err)

		itmList, err := srv.octeliumC.CoreC().ListUser(ctx, &rmetav1.ListOptions{
			Filters: []*rmetav1.ListOptions_Filter{
				urscsrv.FilterFieldEQValStr("spec.email", "linus@exmaple.com"),
			},
		})
		assert.Nil(t, err)
		assert.True(t, len(itmList.Items) == 1)
		assert.Equal(t, usr.Metadata.Uid, itmList.Items[0].Metadata.Uid)
		assert.Equal(t, usr.Metadata.SpecLabels["email"], slug.Make(usr.Spec.Email))

		{
			usr2T, err := tstuser.NewUserWithType(tst.C.OcteliumC, srv, nil, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)

			usr3T, err := tstuser.NewUserWithType(tst.C.OcteliumC, srv, nil, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)

			req := &corev1.User{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
				Spec: &corev1.User_Spec{
					Type:  corev1.User_Spec_HUMAN,
					Email: "linus@exmaple.com",
				},
			}

			{
				_, err = srv.CreateUser(usr2T.Ctx(), req)
				assert.NotNil(t, err, "%+v", err)
				assert.True(t, grpcerr.IsInvalidArg(err))
			}

			{
				usr3T.Usr.Spec.Email = "linus@exmaple.com"
				_, err = srv.UpdateUser(usr3T.Ctx(), usr3T.Usr)
				assert.NotNil(t, err, "%+v", err)
				assert.True(t, grpcerr.IsInvalidArg(err))
			}

			_, err = srv.DeleteUser(usr2T.Ctx(), &metav1.DeleteOptions{
				Uid: usr.Metadata.Uid,
			})
			assert.Nil(t, err)

			_, err = srv.CreateUser(usr2T.Ctx(), req)
			assert.Nil(t, err, "%+v", err)

			req2 := pbutils.Clone(req).(*corev1.User)
			req2.Metadata.Name = utilrand.GetRandomStringCanonical(8)
			_, err = srv.CreateUser(usr2T.Ctx(), req2)
			assert.NotNil(t, err, "%+v", err)
			assert.True(t, grpcerr.IsInvalidArg(err))
		}
	}
}

func newUserItem(spec *corev1.User_Spec) *corev1.User {
	return &corev1.User{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: spec,
	}
}

func newUserHours(hours int64) *metav1.Duration {
	return &metav1.Duration{
		Type: &metav1.Duration_Hours{Hours: uint32(hours)},
	}
}

func TestUserSpecType(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	invalids := []*corev1.User{
		newUserItem(&corev1.User_Spec{}),
		newUserItem(&corev1.User_Spec{
			Type: corev1.User_Spec_TYPE_UNKNOWN,
		}),
		newUserItem(&corev1.User_Spec{
			Type: corev1.User_Spec_Type(1000),
		}),
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		},
		{
			Spec: &corev1.User_Spec{Type: corev1.User_Spec_HUMAN},
		},
		{},
	}

	for _, invalid := range invalids {
		_, err = srv.CreateUser(ctx, invalid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	valids := []*corev1.User{
		newUserItem(&corev1.User_Spec{
			Type: corev1.User_Spec_HUMAN,
		}),
		newUserItem(&corev1.User_Spec{
			Type: corev1.User_Spec_WORKLOAD,
		}),
		newUserItem(&corev1.User_Spec{
			Type:       corev1.User_Spec_WORKLOAD,
			IsDisabled: true,
		}),
	}

	for _, valid := range valids {
		item, err := srv.CreateUser(ctx, valid)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, valid.Spec.Type, item.Spec.Type)

		_, err = srv.CreateUser(ctx, valid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err), "%+v", err)
	}
}

func TestUserSpecEmail(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	invalids := []*corev1.User{
		newUserItem(&corev1.User_Spec{
			Type:  corev1.User_Spec_WORKLOAD,
			Email: "valid@example.com",
		}),
		newUserItem(&corev1.User_Spec{
			Type:  corev1.User_Spec_HUMAN,
			Email: "not-an-email",
		}),
		newUserItem(&corev1.User_Spec{
			Type:  corev1.User_Spec_HUMAN,
			Email: "Upper@example.com",
		}),
		newUserItem(&corev1.User_Spec{
			Type:  corev1.User_Spec_HUMAN,
			Email: fmt.Sprintf("%s@example.com", strings.Repeat("a", userMaxEmailLen)),
		}),
		newUserItem(&corev1.User_Spec{
			Type:  corev1.User_Spec_HUMAN,
			Email: "tëst@example.com",
		}),
	}

	for _, invalid := range invalids {
		_, err = srv.CreateUser(ctx, invalid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		email := fmt.Sprintf("%s@example.com", utilrand.GetRandomStringLowercase(8))
		usr, err := srv.CreateUser(ctx, newUserItem(&corev1.User_Spec{
			Type:  corev1.User_Spec_HUMAN,
			Email: email,
		}))
		assert.Nil(t, err, "%+v", err)
		assert.NotEmpty(t, usr.Metadata.SpecLabels["email"])

		usr.Spec.Email = fmt.Sprintf("%s@example.com", utilrand.GetRandomStringLowercase(8))
		updated, err := srv.UpdateUser(ctx, usr)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, usr.Spec.Email, updated.Spec.Email)

		updated.Spec.Email = ""
		updated, err = srv.UpdateUser(ctx, updated)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "", updated.Metadata.SpecLabels["email"])
	}
}

func TestUserSpecInfo(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	tooLong := strings.Repeat("a", userMaxInfoLen+1)

	invalids := []*corev1.User_Spec_Info{
		{Locale: tooLong},
		{Phone: tooLong},
		{FirstName: tooLong},
		{MiddleName: tooLong},
		{LastName: tooLong},
		{Website: tooLong},
		{Country: tooLong},
	}

	for _, info := range invalids {
		_, err = srv.CreateUser(ctx, newUserItem(&corev1.User_Spec{
			Type: corev1.User_Spec_HUMAN,
			Info: info,
		}))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		usr, err := srv.CreateUser(ctx, newUserItem(&corev1.User_Spec{
			Type: corev1.User_Spec_HUMAN,
			Info: &corev1.User_Spec_Info{
				Locale:     "en-US",
				Phone:      "+201000000000",
				FirstName:  "Linus",
				MiddleName: "B",
				LastName:   "Torvalds",
				Website:    "https://example.com",
				Country:    "EG",
			},
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "Linus", usr.Spec.Info.FirstName)
		assert.Equal(t, "EG", usr.Spec.Info.Country)
	}
}

func TestUserSpecSession(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	invalids := []*corev1.User_Spec_Session{
		{ClientDuration: newUserHours(-1)},
		{ClientlessDuration: newUserHours(-1)},
		{AccessTokenDuration: newUserHours(-1)},
		{RefreshTokenDuration: newUserHours(-1)},
		{MaxPerUser: userMaxSessionsPerUser + 1},
		{DefaultState: corev1.Session_Spec_REJECTED},
		{DefaultState: corev1.Session_Spec_State(1000)},
	}

	for _, sess := range invalids {
		_, err = srv.CreateUser(ctx, newUserItem(&corev1.User_Spec{
			Type:    corev1.User_Spec_HUMAN,
			Session: sess,
		}))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	valids := []*corev1.User_Spec_Session{
		{},
		{
			ClientDuration:       newUserHours(8),
			ClientlessDuration:   newUserHours(4),
			AccessTokenDuration:  newUserHours(1),
			RefreshTokenDuration: newUserHours(24),
			MaxPerUser:           userMaxSessionsPerUser,
			DefaultState:         corev1.Session_Spec_ACTIVE,
		},
		{
			MaxPerUser:   1,
			DefaultState: corev1.Session_Spec_PENDING,
		},
	}

	for _, sess := range valids {
		usr, err := srv.CreateUser(ctx, newUserItem(&corev1.User_Spec{
			Type:    corev1.User_Spec_HUMAN,
			Session: sess,
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, sess.MaxPerUser, usr.Spec.Session.MaxPerUser)
	}
}

func TestUserSpecAuthentication(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	sec, err := srv.CreateSecret(ctx, &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Secret_Spec{},
		Data: &corev1.Secret_Data{
			Type: &corev1.Secret_Data_Value{
				Value: utilrand.GetRandomString(32),
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	idpName := utilrand.GetRandomStringCanonical(8)
	_, err = srv.CreateIdentityProvider(ctx, &corev1.IdentityProvider{
		Metadata: &metav1.Metadata{Name: idpName},
		Spec: &corev1.IdentityProvider_Spec{
			Type: &corev1.IdentityProvider_Spec_Github_{
				Github: &corev1.IdentityProvider_Spec_Github{
					ClientID: utilrand.GetRandomString(32),
					ClientSecret: &corev1.IdentityProvider_Spec_Github_ClientSecret{
						Type: &corev1.IdentityProvider_Spec_Github_ClientSecret_FromSecret{
							FromSecret: sec.Metadata.Name,
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	invalids := []*corev1.User_Spec_Authentication{
		{
			Identities: []*corev1.User_Spec_Authentication_Identity{
				{IdentityProvider: idpName},
			},
		},
		{
			Identities: []*corev1.User_Spec_Authentication_Identity{
				{Identifier: utilrand.GetRandomStringCanonical(8)},
			},
		},
		{
			Identities: []*corev1.User_Spec_Authentication_Identity{
				{
					IdentityProvider: idpName,
					Identifier:       strings.Repeat("a", userMaxIdentifierLen+1),
				},
			},
		},
		{
			Identities: []*corev1.User_Spec_Authentication_Identity{
				{
					IdentityProvider: strings.Repeat("a", userMaxIdentifierLen+1),
					Identifier:       utilrand.GetRandomStringCanonical(8),
				},
			},
		},
		{
			Identities: []*corev1.User_Spec_Authentication_Identity{
				{
					IdentityProvider: utilrand.GetRandomStringCanonical(8),
					Identifier:       utilrand.GetRandomStringCanonical(8),
				},
			},
		},
		{
			AuthenticatorDefaultState: corev1.Authenticator_Spec_REJECTED,
		},
		{
			AuthenticatorDefaultState: corev1.Authenticator_Spec_State(1000),
		},
	}

	for _, auth := range invalids {
		_, err = srv.CreateUser(ctx, newUserItem(&corev1.User_Spec{
			Type:           corev1.User_Spec_HUMAN,
			Authentication: auth,
		}))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		var identities []*corev1.User_Spec_Authentication_Identity
		for i := 0; i < userMaxIdentities+1; i++ {
			identities = append(identities, &corev1.User_Spec_Authentication_Identity{
				IdentityProvider: idpName,
				Identifier:       utilrand.GetRandomStringCanonical(8),
			})
		}

		_, err = srv.CreateUser(ctx, newUserItem(&corev1.User_Spec{
			Type: corev1.User_Spec_HUMAN,
			Authentication: &corev1.User_Spec_Authentication{
				Identities: identities,
			},
		}))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		identifier := utilrand.GetRandomStringCanonical(8)
		usr, err := srv.CreateUser(ctx, newUserItem(&corev1.User_Spec{
			Type: corev1.User_Spec_HUMAN,
			Authentication: &corev1.User_Spec_Authentication{
				AuthenticatorDefaultState: corev1.Authenticator_Spec_PENDING,
				Identities: []*corev1.User_Spec_Authentication_Identity{
					{
						IdentityProvider: idpName,
						Identifier:       identifier,
					},
				},
			},
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, identifier, usr.Metadata.SpecLabels[fmt.Sprintf("auth-%s", idpName)])
	}
}

func TestUserSpecGroupsAndAuthorization(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	grp, err := srv.CreateGroup(ctx, &corev1.Group{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec:     &corev1.Group_Spec{},
	})
	assert.Nil(t, err, "%+v", err)

	policy, err := srv.CreatePolicy(ctx, &corev1.Policy{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec: &corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{MatchAny: true},
					},
					Effect: corev1.Policy_Spec_Rule_ALLOW,
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	invalids := []*corev1.User_Spec{
		{
			Type:   corev1.User_Spec_HUMAN,
			Groups: []string{"INVALID NAME"},
		},
		{
			Type:   corev1.User_Spec_HUMAN,
			Groups: []string{utilrand.GetRandomStringCanonical(8)},
		},
		{
			Type: corev1.User_Spec_HUMAN,
			Authorization: &corev1.User_Spec_Authorization{
				Policies: []string{utilrand.GetRandomStringCanonical(8)},
			},
		},
		{
			Type: corev1.User_Spec_HUMAN,
			Authorization: &corev1.User_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Name: utilrand.GetRandomStringCanonical(8),
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_Match{Match: "!!!!"},
									},
									Effect: corev1.Policy_Spec_Rule_ALLOW,
								},
							},
						},
					},
				},
			},
		},
	}

	for _, spec := range invalids {
		_, err = srv.CreateUser(ctx, newUserItem(spec))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		attrs, err := structpb.NewStruct(map[string]any{
			"team": "platform",
		})
		assert.Nil(t, err, "%+v", err)

		usr, err := srv.CreateUser(ctx, newUserItem(&corev1.User_Spec{
			Type:   corev1.User_Spec_HUMAN,
			Groups: []string{grp.Metadata.Name},
			Attrs:  attrs,
			Authorization: &corev1.User_Spec_Authorization{
				Policies: []string{policy.Metadata.Name},
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Name: utilrand.GetRandomStringCanonical(8),
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{MatchAny: true},
									},
									Effect: corev1.Policy_Spec_Rule_DENY,
								},
							},
						},
					},
				},
			},
		}))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(usr.Spec.Groups))
		assert.NotNil(t, usr.Spec.Attrs)
	}
}

func TestUserCRUD(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	usr, err := srv.CreateUser(ctx, newUserItem(&corev1.User_Spec{
		Type: corev1.User_Spec_WORKLOAD,
	}))
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, usr.Status)

	{
		ret, err := srv.GetUser(ctx, &metav1.GetOptions{Uid: usr.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, usr.Metadata.Uid, ret.Metadata.Uid)

		ret, err = srv.GetUser(ctx, &metav1.GetOptions{Name: usr.Metadata.Name})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, usr.Metadata.Uid, ret.Metadata.Uid)
	}

	{
		_, err = srv.GetUser(ctx, &metav1.GetOptions{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err = srv.GetUser(ctx, &metav1.GetOptions{Name: utilrand.GetRandomStringCanonical(8)})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		usr.Metadata.DisplayName = "new display name"
		usr.Spec.IsDisabled = true

		updated, err := srv.UpdateUser(ctx, usr)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "new display name", updated.Metadata.DisplayName)
		assert.True(t, updated.Spec.IsDisabled)
		usr = updated
	}

	{
		_, err = srv.UpdateUser(ctx, newUserItem(&corev1.User_Spec{
			Type: corev1.User_Spec_WORKLOAD,
		}))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
	}

	{
		_, err = srv.ListUser(ctx, nil)
		assert.NotNil(t, err)
	}

	{
		_, err = srv.DeleteUser(ctx, &metav1.DeleteOptions{Uid: usr.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.DeleteUser(ctx, &metav1.DeleteOptions{Uid: usr.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)

		_, err = srv.DeleteUser(ctx, &metav1.DeleteOptions{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
}
