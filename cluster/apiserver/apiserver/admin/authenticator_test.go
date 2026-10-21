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
	"math"
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
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
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

func TestAuthenticatorUpdatePreservesStatus(t *testing.T) {
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	s := newFakeServer(tst.C)
	item, err := s.octeliumC.CoreC().CreateAuthenticator(t.Context(), &corev1.Authenticator{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec:     &corev1.Authenticator_Spec{State: corev1.Authenticator_Spec_ACTIVE},
		Status:   &corev1.Authenticator_Status{UserRef: &metav1.ObjectReference{Name: "owner", Uid: "7f0da666-37af-4cf9-8d0f-995d82877e70"}, IsRegistered: true},
	})
	require.Nil(t, err)
	before := proto.Clone(item.Status)
	req := proto.Clone(item).(*corev1.Authenticator)
	req.Spec.DisplayName = "Updated Authenticator"
	req.Spec.State = corev1.Authenticator_Spec_PENDING
	req.Status = &corev1.Authenticator_Status{UserRef: &metav1.ObjectReference{Name: "forged-owner"}}
	got, err := s.UpdateAuthenticator(t.Context(), req)
	require.Nil(t, err)
	assert.Equal(t, "Updated Authenticator", got.Spec.DisplayName)
	assert.Equal(t, corev1.Authenticator_Spec_PENDING, got.Spec.State)
	assert.True(t, proto.Equal(before, got.Status))
}

func TestAuthenticatorStateValidation(t *testing.T) {
	for _, state := range []corev1.Authenticator_Spec_State{
		corev1.Authenticator_Spec_ACTIVE,
		corev1.Authenticator_Spec_PENDING,
		corev1.Authenticator_Spec_REJECTED,
		corev1.Authenticator_Spec_STATE_UNKNOWN,
		-1, 4, 1000, math.MinInt32, math.MaxInt32,
	} {
		t.Run(state.String(), func(t *testing.T) {
			calls := 0
			s := newTstServer(func(method string, req, resp any) error {
				calls++
				return status.Error(codes.Unavailable, "backend")
			})
			item := &corev1.Authenticator{
				Metadata: &metav1.Metadata{Name: "authenticator"},
				Spec:     &corev1.Authenticator_Spec{State: state},
			}
			err := s.validateAuthenticator(t.Context(), item)
			switch state {
			case corev1.Authenticator_Spec_ACTIVE, corev1.Authenticator_Spec_PENDING, corev1.Authenticator_Spec_REJECTED:
				assert.Nil(t, err)
			default:
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				_, err = s.UpdateAuthenticator(t.Context(), item)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			}
			assert.Zero(t, calls)
		})
	}
}
