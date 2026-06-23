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
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticator(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	usr, err := srv.CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err)

	usr2, err := srv.CreateUser(ctx, tests.GenUser(nil))
	assert.Nil(t, err)

	createAuthn := func(userRef *metav1.ObjectReference) *corev1.Authenticator {
		authn, err := srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Authenticator_Spec{
				State:       corev1.Authenticator_Spec_ACTIVE,
				DisplayName: utilrand.GetRandomStringLowercase(10),
			},
			Status: &corev1.Authenticator_Status{
				UserRef: userRef,
				Type:    corev1.Authenticator_Status_FIDO,
			},
		})
		assert.Nil(t, err, "%+v", err)
		return authn
	}

	{
		authn := createAuthn(umetav1.GetObjectReference(usr))

		res, err := srv.GetAuthenticator(ctx, &metav1.GetOptions{Uid: authn.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, authn.Metadata.Uid, res.Metadata.Uid)
		assert.True(t, pbutils.IsEqual(authn.Spec, res.Spec))
		assert.Equal(t, usr.Metadata.Uid, res.Status.UserRef.Uid)
	}

	{
		res, err := srv.GetAuthenticator(ctx, &metav1.GetOptions{})
		assert.NotNil(t, err)
		assert.Nil(t, res)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		authn := createAuthn(umetav1.GetObjectReference(usr))

		upd := pbutils.Clone(authn).(*corev1.Authenticator)
		upd.Spec.State = corev1.Authenticator_Spec_PENDING
		upd.Spec.DisplayName = "updated display name"

		out, err := srv.UpdateAuthenticator(ctx, upd)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, corev1.Authenticator_Spec_PENDING, out.Spec.State)
		assert.Equal(t, "updated display name", out.Spec.DisplayName)

		res, err := srv.GetAuthenticator(ctx, &metav1.GetOptions{Uid: authn.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, corev1.Authenticator_Spec_PENDING, res.Spec.State)
		assert.Equal(t, "updated display name", res.Spec.DisplayName)
		assert.Equal(t, usr.Metadata.Uid, res.Status.UserRef.Uid)
	}

	{
		_, err := srv.UpdateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpdateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Authenticator_Spec{
				State: corev1.Authenticator_Spec_STATE_UNKNOWN,
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpdateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Authenticator_Spec{
				State:       corev1.Authenticator_Spec_ACTIVE,
				DisplayName: strings.Repeat("a", 121),
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		randomNonASCIIRune := func() rune {
			for {
				r := rune(rand.Int32N(0x10FFFF-0x0080) + 0x0080)

				if r >= 0xD800 && r <= 0xDFFF {
					continue
				}
				return r
			}
		}

		_, err := srv.UpdateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Authenticator_Spec{
				State: corev1.Authenticator_Spec_ACTIVE,
				DisplayName: func() string {
					runes := make([]rune, 10)
					for i := range runes {
						runes[i] = randomNonASCIIRune()
					}
					return string(runes)
				}(),
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := srv.UpdateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Authenticator_Spec{
				State:       corev1.Authenticator_Spec_ACTIVE,
				DisplayName: utilrand.GetRandomStringLowercase(8),
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		authn := createAuthn(umetav1.GetObjectReference(usr))

		list, err := srv.ListAuthenticator(ctx, &corev1.ListAuthenticatorOptions{})
		assert.Nil(t, err, "%+v", err)

		found := false
		for _, itm := range list.Items {
			if itm.Metadata.Uid == authn.Metadata.Uid {
				found = true
			}
		}
		assert.True(t, found)
	}

	{
		authnUsr := createAuthn(umetav1.GetObjectReference(usr))
		authnUsr2 := createAuthn(umetav1.GetObjectReference(usr2))

		list, err := srv.ListAuthenticator(ctx, &corev1.ListAuthenticatorOptions{
			UserRef: umetav1.GetObjectReference(usr),
		})
		assert.Nil(t, err, "%+v", err)

		foundUsr := false
		for _, itm := range list.Items {
			assert.Equal(t, usr.Metadata.Uid, itm.Status.UserRef.Uid)
			assert.NotEqual(t, authnUsr2.Metadata.Uid, itm.Metadata.Uid)
			if itm.Metadata.Uid == authnUsr.Metadata.Uid {
				foundUsr = true
			}
		}
		assert.True(t, foundUsr)

		listUsr2, err := srv.ListAuthenticator(ctx, &corev1.ListAuthenticatorOptions{
			UserRef: umetav1.GetObjectReference(usr2),
		})
		assert.Nil(t, err, "%+v", err)

		foundUsr2 := false
		for _, itm := range listUsr2.Items {
			assert.Equal(t, usr2.Metadata.Uid, itm.Status.UserRef.Uid)
			if itm.Metadata.Uid == authnUsr2.Metadata.Uid {
				foundUsr2 = true
			}
		}
		assert.True(t, foundUsr2)
	}

	{
		_, err := srv.ListAuthenticator(ctx, &corev1.ListAuthenticatorOptions{
			UserRef: &metav1.ObjectReference{},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		authn := createAuthn(umetav1.GetObjectReference(usr))

		_, err := srv.DeleteAuthenticator(ctx, &metav1.DeleteOptions{Uid: authn.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.GetAuthenticator(ctx, &metav1.GetOptions{Uid: authn.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		_, err := srv.DeleteAuthenticator(ctx, &metav1.DeleteOptions{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
}
