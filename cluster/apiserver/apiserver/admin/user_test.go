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

	"github.com/gosimple/slug"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestCreateUser(t *testing.T) {
	t.Log("Testing CreateUser")

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
		if err != nil {
			t.Fatalf("Could not create valid user: %+v", err)
		}

		assert.True(t, pbutils.IsEqual(usr.Spec, outUsr.Spec))
	}

}

func TestListUser(t *testing.T) {
	t.Log("Testing CreateUser")

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

	{
		usr := &corev1.User{
			Metadata: &metav1.Metadata{Name: "usr-1"},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_WORKLOAD,
			},
		}

		_, err = srv.CreateUser(ctx, usr)
		if err != nil {
			t.Fatalf("Could not create user: %+v", err)
		}

		_, err = srv.DeleteUser(ctx, &metav1.DeleteOptions{Name: "usr-1"})
		if err != nil {
			t.Fatalf("Could not delete user: %+v", err)
		}
	}
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

	/*
		cc.Spec.Authentication = &corev1.ClusterConfig_Spec_Authentication{
			WebIdentityProviders: []string{
				"github", "oidc1",
			},
		}
	*/

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
	}
}
