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
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
			res, err := srv.doGetAvailableAuthenticator(getCtxRT(usrT), &authv1.GetAvailableAuthenticatorRequest{})
			assert.Nil(t, err)

			assert.Nil(t, res.MainAuthenticator)
			assert.Equal(t, 0, len(res.AvailableAuthenticators))
		}

		{
			_, err = srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{})
			assert.NotNil(t, err)

			assert.True(t, grpcerr.IsInvalidArg(err))
		}
		{
			res, err := srv.doGetAvailableAuthenticator(getCtxRT(usrT), &authv1.GetAvailableAuthenticatorRequest{})
			assert.Nil(t, err)

			assert.Nil(t, res.MainAuthenticator)
			assert.Equal(t, 0, len(res.AvailableAuthenticators))
		}
		{
			_, err = srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{})
			assert.NotNil(t, err)

			assert.True(t, grpcerr.IsInvalidArg(err))
		}

		authn, err := srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{
			Type: authv1.Authenticator_Status_FIDO,
		})
		assert.Nil(t, err, "%+v", err)

		authn.Spec.DisplayName = utilrand.GetRandomStringCanonical(32)

		authn, err = srv.doUpdateAuthenticator(getCtxRT(usrT), authn)
		assert.Nil(t, err)
		{
			_, err := srv.doUpdateAuthenticator(getCtxRT(usr2T), authn)
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
		}

		itmList, err = srv.doListAuthenticator(getCtxRT(usrT), &authv1.ListAuthenticatorOptions{})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(itmList.Items))

		assert.Equal(t, authn.Metadata.Uid, itmList.Items[0].Metadata.Uid)

		{
			res, err := srv.doGetAvailableAuthenticator(getCtxRT(usrT), &authv1.GetAvailableAuthenticatorRequest{})
			assert.Nil(t, err)

			assert.Nil(t, res.MainAuthenticator)
			assert.Equal(t, 0, len(res.AvailableAuthenticators))
		}

		{
			itmList, err = srv.doListAuthenticator(getCtxRT(usr2T), &authv1.ListAuthenticatorOptions{})
			assert.Nil(t, err)
			assert.Equal(t, 0, len(itmList.Items))

			_, err = srv.doDeleteAuthenticator(getCtxRT(usr2T), &metav1.DeleteOptions{
				Name: authn.Metadata.Name,
			})
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
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

func TestGetAvailableAuthenticators(t *testing.T) {

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
		_, err = srv.doGetAvailableAuthenticator(ctx, &authv1.GetAvailableAuthenticatorRequest{})
		assert.NotNil(t, err)

		assert.True(t, grpcerr.IsUnauthenticated(err))
	}

	usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	usr2T, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	usr2T.Session.Status.Type = corev1.Session_Status_CLIENTLESS
	usr2T.Session.Status.IsBrowser = true
	usr2T.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usr2T.Session)
	assert.Nil(t, err)

	res, err := srv.doGetAvailableAuthenticator(getCtxRT(usrT), &authv1.GetAvailableAuthenticatorRequest{})
	assert.Nil(t, err)

	assert.Nil(t, res.MainAuthenticator)
	assert.Equal(t, 0, len(res.AvailableAuthenticators))

	_, err = srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Authenticator_Spec{
			State: corev1.Authenticator_Spec_ACTIVE,
		},
		Status: &corev1.Authenticator_Status{
			UserRef: umetav1.GetObjectReference(usrT.Usr),
			Type:    corev1.Authenticator_Status_TPM,
		},
	})
	assert.Nil(t, err)

	{
		res, err := srv.doGetAvailableAuthenticator(getCtxRT(usrT), &authv1.GetAvailableAuthenticatorRequest{})
		assert.Nil(t, err)

		assert.Nil(t, res.MainAuthenticator)
		assert.Equal(t, 0, len(res.AvailableAuthenticators))
	}

	authn, err := srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Authenticator_Spec{
			State: corev1.Authenticator_Spec_ACTIVE,
		},
		Status: &corev1.Authenticator_Status{
			UserRef:      umetav1.GetObjectReference(usrT.Usr),
			Type:         corev1.Authenticator_Status_TPM,
			IsRegistered: true,
		},
	})
	assert.Nil(t, err)

	res, err = srv.doGetAvailableAuthenticator(getCtxRT(usrT), &authv1.GetAvailableAuthenticatorRequest{})
	assert.Nil(t, err)

	assert.Nil(t, res.MainAuthenticator)
	assert.Equal(t, 1, len(res.AvailableAuthenticators))

	assert.Equal(t, authn.Metadata.Uid, res.AvailableAuthenticators[0].Metadata.Uid)

	{
		res, err := srv.doGetAvailableAuthenticator(getCtxRT(usr2T), &authv1.GetAvailableAuthenticatorRequest{})
		assert.Nil(t, err)

		assert.Nil(t, res.MainAuthenticator)
		assert.Equal(t, 0, len(res.AvailableAuthenticators))
	}

	_, err = srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Authenticator_Spec{
			State: corev1.Authenticator_Spec_ACTIVE,
		},
		Status: &corev1.Authenticator_Status{
			UserRef:      umetav1.GetObjectReference(usrT.Usr),
			Type:         corev1.Authenticator_Status_FIDO,
			IsRegistered: true,
		},
	})
	assert.Nil(t, err)

	{
		res, err := srv.doGetAvailableAuthenticator(getCtxRT(usrT), &authv1.GetAvailableAuthenticatorRequest{})
		assert.Nil(t, err)

		assert.Nil(t, res.MainAuthenticator)
		assert.Equal(t, 1, len(res.AvailableAuthenticators))

		assert.Equal(t, authn.Metadata.Uid, res.AvailableAuthenticators[0].Metadata.Uid)
	}

	authn2, err := srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Authenticator_Spec{
			State: corev1.Authenticator_Spec_ACTIVE,
		},
		Status: &corev1.Authenticator_Status{
			UserRef:      umetav1.GetObjectReference(usr2T.Usr),
			Type:         corev1.Authenticator_Status_FIDO,
			IsRegistered: true,
		},
	})
	assert.Nil(t, err)

	{
		res, err := srv.doGetAvailableAuthenticator(getCtxRT(usrT), &authv1.GetAvailableAuthenticatorRequest{})
		assert.Nil(t, err)

		assert.Nil(t, res.MainAuthenticator)
		assert.Equal(t, 1, len(res.AvailableAuthenticators))

		assert.Equal(t, authn.Metadata.Uid, res.AvailableAuthenticators[0].Metadata.Uid)
	}

	{
		res, err := srv.doGetAvailableAuthenticator(getCtxRT(usr2T), &authv1.GetAvailableAuthenticatorRequest{})
		assert.Nil(t, err)

		assert.Nil(t, res.MainAuthenticator)
		assert.Equal(t, 1, len(res.AvailableAuthenticators))

		assert.Equal(t, authn2.Metadata.Uid, res.AvailableAuthenticators[0].Metadata.Uid)
	}

	authn1, err := srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Authenticator_Spec{
			State: corev1.Authenticator_Spec_ACTIVE,
		},
		Status: &corev1.Authenticator_Status{
			UserRef:      umetav1.GetObjectReference(usrT.Usr),
			Type:         corev1.Authenticator_Status_TPM,
			IsRegistered: true,
		},
	})
	assert.Nil(t, err)

	{
		res, err := srv.doGetAvailableAuthenticator(getCtxRT(usrT), &authv1.GetAvailableAuthenticatorRequest{})
		assert.Nil(t, err)

		assert.Nil(t, res.MainAuthenticator)
		assert.Equal(t, 2, len(res.AvailableAuthenticators))

		assert.Equal(t, authn1.Metadata.Uid, res.AvailableAuthenticators[1].Metadata.Uid)
	}
	{
		res, err := srv.doGetAvailableAuthenticator(getCtxRT(usr2T), &authv1.GetAvailableAuthenticatorRequest{})
		assert.Nil(t, err)

		assert.Nil(t, res.MainAuthenticator)
		assert.Equal(t, 1, len(res.AvailableAuthenticators))

		assert.Equal(t, authn2.Metadata.Uid, res.AvailableAuthenticators[0].Metadata.Uid)
	}
}

func TestCreateAuthenticatorUnknownType(t *testing.T) {

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

	usrT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	usrT.Session.Status.IsBrowser = true
	usrT.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
	assert.Nil(t, err)

	for _, typ := range []authv1.Authenticator_Status_Type{
		authv1.Authenticator_Status_TYPE_UNKNOWN,
		authv1.Authenticator_Status_Type(4),
		authv1.Authenticator_Status_Type(1000),
		authv1.Authenticator_Status_Type(-1),
	} {
		_, err := srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{
			Type: typ,
		})
		assert.NotNil(t, err, "%d", typ)
		assert.True(t, grpcerr.IsInvalidArg(err), "%d", typ)
	}

	itmList, err := srv.octeliumC.CoreC().ListAuthenticator(ctx, urscsrv.FilterByUser(usrT.Usr))
	assert.Nil(t, err)
	assert.Equal(t, 0, len(itmList.Items))
}

func TestAuthenticatorOwnership(t *testing.T) {
	ctx := context.Background()
	srv, _, adminSrv := newWebAuthnTestEnv(t)
	usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
	assert.Nil(t, err)
	otherT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
	assert.Nil(t, err)
	authn, err := srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{
		Type: authv1.Authenticator_Status_TOTP, DisplayName: "owned",
	})
	assert.Nil(t, err)
	before, err := srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{Uid: authn.Metadata.Uid})
	assert.Nil(t, err)

	tests := []struct {
		name string
		call func(context.Context, *metav1.ObjectReference) error
	}{
		{"Get", func(ctx context.Context, ref *metav1.ObjectReference) error {
			res, err := srv.doGetAuthenticator(ctx, &metav1.GetOptions{Name: ref.Name, Uid: ref.Uid})
			assert.Nil(t, res)
			return err
		}},
		{"Update", func(ctx context.Context, ref *metav1.ObjectReference) error {
			res, err := srv.doUpdateAuthenticator(ctx, &authv1.Authenticator{
				Metadata: &metav1.Metadata{Name: authn.Metadata.Name, Uid: ref.Uid},
				Spec:     &authv1.Authenticator_Spec{DisplayName: "changed"},
			})
			assert.Nil(t, res)
			return err
		}},
		{"Delete", func(ctx context.Context, ref *metav1.ObjectReference) error {
			res, err := srv.doDeleteAuthenticator(ctx, &metav1.DeleteOptions{Name: ref.Name, Uid: ref.Uid})
			assert.Nil(t, res)
			return err
		}},
		{"RegisterBegin", func(ctx context.Context, ref *metav1.ObjectReference) error {
			res, err := srv.doRegisterAuthenticatorBegin(ctx, &authv1.RegisterAuthenticatorBeginRequest{AuthenticatorRef: ref})
			assert.Nil(t, res)
			return err
		}},
		{"RegisterFinish", func(ctx context.Context, ref *metav1.ObjectReference) error {
			res, err := srv.doRegisterAuthenticatorFinish(ctx, &authv1.RegisterAuthenticatorFinishRequest{
				AuthenticatorRef: ref, ChallengeResponse: fidoChallengeResponse("response"),
			})
			assert.Nil(t, res)
			return err
		}},
		{"AuthenticateBegin", func(ctx context.Context, ref *metav1.ObjectReference) error {
			res, err := srv.doAuthenticateAuthenticatorBegin(ctx, &authv1.AuthenticateAuthenticatorBeginRequest{AuthenticatorRef: ref})
			assert.Nil(t, res)
			return err
		}},
		{"AuthenticateFinish", func(ctx context.Context, ref *metav1.ObjectReference) error {
			res, err := srv.doAuthenticateWithAuthenticator(ctx, &authv1.AuthenticateWithAuthenticatorRequest{
				AuthenticatorRef: ref, ChallengeResponse: fidoChallengeResponse("response"),
			})
			assert.Nil(t, res)
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, ref := range []*metav1.ObjectReference{
				{Name: authn.Metadata.Name},
				{Uid: authn.Metadata.Uid},
			} {
				assert.Equal(t, codes.PermissionDenied, status.Code(tt.call(getCtxRT(otherT), ref)))
			}
		})
	}

	after, err := srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{Uid: authn.Metadata.Uid})
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(before, after))
	got, err := srv.doGetAuthenticator(getCtxRT(usrT), &metav1.GetOptions{Uid: authn.Metadata.Uid})
	assert.Nil(t, err)
	assert.Equal(t, authn.Metadata.Uid, got.Metadata.Uid)
	assert.Equal(t, "owned", got.Spec.DisplayName)
}

func TestUpdateAuthenticatorValidation(t *testing.T) {
	ctx := context.Background()
	srv, _, adminSrv := newWebAuthnTestEnv(t)
	usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
	assert.Nil(t, err)
	authn, err := srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{
		Type: authv1.Authenticator_Status_TOTP,
	})
	assert.Nil(t, err)

	for _, req := range []*authv1.Authenticator{
		{},
		{Metadata: &metav1.Metadata{}},
		{Metadata: &metav1.Metadata{Name: authn.Metadata.Name}},
		{Metadata: &metav1.Metadata{Name: authn.Metadata.Name}, Spec: &authv1.Authenticator_Spec{DisplayName: strings.Repeat("a", 121)}},
		{Metadata: &metav1.Metadata{Name: authn.Metadata.Name}, Spec: &authv1.Authenticator_Spec{DisplayName: "日"}},
	} {
		res, err := srv.doUpdateAuthenticator(getCtxRT(usrT), req)
		assert.Nil(t, res)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	}

	for _, displayName := range []string{"", strings.Repeat("a", 120)} {
		got, err := srv.doUpdateAuthenticator(getCtxRT(usrT), &authv1.Authenticator{
			Metadata: &metav1.Metadata{Name: authn.Metadata.Name},
			Spec:     &authv1.Authenticator_Spec{DisplayName: displayName},
			Status:   &authv1.Authenticator_Status{IsRegistered: true, Type: authv1.Authenticator_Status_TPM},
		})
		assert.Nil(t, err)
		assert.Equal(t, displayName, got.Spec.DisplayName)
		assert.False(t, got.Status.IsRegistered)
		assert.Equal(t, authv1.Authenticator_Status_TOTP, got.Status.Type)
	}

	usrT.Session.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATION_REQUIRED
	_, err = srv.octeliumC.CoreC().UpdateSession(ctx, usrT.Session)
	assert.Nil(t, err)
	res, err := srv.doUpdateAuthenticator(getCtxRT(usrT), &authv1.Authenticator{
		Metadata: &metav1.Metadata{Name: authn.Metadata.Name},
		Spec:     &authv1.Authenticator_Spec{DisplayName: "changed"},
	})
	assert.Nil(t, res)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestCreateAuthenticatorLimit(t *testing.T) {
	ctx := context.Background()
	srv, _, adminSrv := newWebAuthnTestEnv(t)
	usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
	assert.Nil(t, err)

	for range maxAuthenticatorPerUser - 1 {
		_, err := srv.octeliumC.CoreC().CreateAuthenticator(ctx, &corev1.Authenticator{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringLowercase(12)},
			Spec:     &corev1.Authenticator_Spec{State: corev1.Authenticator_Spec_ACTIVE},
			Status: &corev1.Authenticator_Status{
				UserRef: umetav1.GetObjectReference(usrT.Usr), Type: corev1.Authenticator_Status_TOTP,
			},
		})
		assert.Nil(t, err)
	}
	res, err := srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{Type: authv1.Authenticator_Status_TOTP})
	assert.Nil(t, err)
	assert.NotNil(t, res)
	res, err = srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{Type: authv1.Authenticator_Status_TOTP})
	assert.Nil(t, res)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	items, err := srv.octeliumC.CoreC().ListAuthenticator(ctx, urscsrv.FilterByUser(usrT.Usr))
	assert.Nil(t, err)
	assert.Equal(t, maxAuthenticatorPerUser, len(items.Items))
}

func TestAuthenticatorUserState(t *testing.T) {
	ctx := context.Background()
	srv, _, adminSrv := newWebAuthnTestEnv(t)
	c := authv1.NewMainServiceClient(newAuthGRPCTestClient(t, srv))

	tests := []struct {
		name       string
		isDisabled bool
		isLocked   bool
		isDeleted  bool
		code       codes.Code
	}{
		{name: "Disabled", isDisabled: true, code: codes.PermissionDenied},
		{name: "Locked", isLocked: true, code: codes.PermissionDenied},
		{name: "DisabledAndLocked", isDisabled: true, isLocked: true, code: codes.PermissionDenied},
		{name: "Deleted", isDeleted: true, code: codes.Unauthenticated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usrT, err := tstuser.NewUserWeb(srv.octeliumC, adminSrv, nil, nil)
			assert.Nil(t, err)
			authn, err := srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{
				Type:        authv1.Authenticator_Status_TOTP,
				DisplayName: "original",
			})
			assert.Nil(t, err)
			before, err := srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{Uid: authn.Metadata.Uid})
			assert.Nil(t, err)

			if tt.isDeleted {
				_, err = srv.octeliumC.CoreC().DeleteUser(ctx, &rmetav1.DeleteOptions{Uid: usrT.Usr.Metadata.Uid})
			} else {
				usrT.Usr.Spec.IsDisabled = tt.isDisabled
				usrT.Usr.Status.IsLocked = tt.isLocked
				usrT.Usr, err = srv.octeliumC.CoreC().UpdateUser(ctx, usrT.Usr)
			}
			assert.Nil(t, err)

			rpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			rpcCtx = metadata.NewOutgoingContext(rpcCtx, metadata.Pairs(
				"x-octelium-refresh-token", usrT.GetAccessToken().RefreshToken,
			))

			got, err := c.GetAuthenticator(rpcCtx, &metav1.GetOptions{Uid: authn.Metadata.Uid})
			assert.Nil(t, got)
			assert.Equal(t, tt.code, status.Code(err))
			updated, err := c.UpdateAuthenticator(rpcCtx, &authv1.Authenticator{
				Metadata: authn.Metadata,
				Spec:     &authv1.Authenticator_Spec{DisplayName: "changed"},
			})
			assert.Nil(t, updated)
			assert.Equal(t, tt.code, status.Code(err))
			deleted, err := c.DeleteAuthenticator(rpcCtx, &metav1.DeleteOptions{Uid: authn.Metadata.Uid})
			assert.Nil(t, deleted)
			assert.Equal(t, tt.code, status.Code(err))

			after, err := srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{Uid: authn.Metadata.Uid})
			if !assert.Nil(t, err) {
				return
			}
			assert.True(t, pbutils.IsEqual(before, after))

			if tt.isDeleted {
				return
			}

			usrT.Usr.Spec.IsDisabled = false
			usrT.Usr.Status.IsLocked = false
			_, err = srv.octeliumC.CoreC().UpdateUser(ctx, usrT.Usr)
			assert.Nil(t, err)
			got, err = c.GetAuthenticator(rpcCtx, &metav1.GetOptions{Uid: authn.Metadata.Uid})
			assert.Nil(t, err)
			assert.Equal(t, "original", got.Spec.DisplayName)
			updated, err = c.UpdateAuthenticator(rpcCtx, &authv1.Authenticator{
				Metadata: authn.Metadata,
				Spec:     &authv1.Authenticator_Spec{DisplayName: "allowed"},
			})
			assert.Nil(t, err)
			assert.Equal(t, "allowed", updated.Spec.DisplayName)
			_, err = c.DeleteAuthenticator(rpcCtx, &metav1.DeleteOptions{Uid: authn.Metadata.Uid})
			assert.Nil(t, err)
		})
	}
}
