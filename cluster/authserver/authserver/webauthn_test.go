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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

type virtualFIDO struct {
	rp   virtualwebauthn.RelyingParty
	auth virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
}

func newVirtualFIDO(domain string, usr *corev1.User,
	opts virtualwebauthn.AuthenticatorOptions) *virtualFIDO {

	uid, _ := uuid.Parse(usr.Metadata.Uid)
	opts.UserHandle = uid[:]

	return &virtualFIDO{
		rp: virtualwebauthn.RelyingParty{
			ID:     domain,
			Name:   "Octelium",
			Origin: fmt.Sprintf("https://%s", domain),
		},
		auth: virtualwebauthn.NewAuthenticatorWithOptions(opts),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
}

func newPasskeyFIDO(domain string, usr *corev1.User) *virtualFIDO {
	return newVirtualFIDO(domain, usr, virtualwebauthn.AuthenticatorOptions{
		BackupEligible: true,
		ClientExtensionResults: map[string]any{
			"credProps": map[string]any{
				"rk": true,
			},
		},
	})
}

func (d *virtualFIDO) attestation(t *testing.T, req string) string {
	t.Helper()

	opts, err := virtualwebauthn.ParseAttestationOptions(req)
	assert.Nil(t, err, "%+v", err)

	return virtualwebauthn.CreateAttestationResponse(d.rp, d.auth, d.cred, *opts)
}

func (d *virtualFIDO) assertion(t *testing.T, req string) string {
	t.Helper()

	opts, err := virtualwebauthn.ParseAssertionOptions(req)
	assert.Nil(t, err, "%+v", err)

	return virtualwebauthn.CreateAssertionResponse(d.rp, d.auth, d.cred, *opts)
}

func fidoChallengeResponse(resp string) *authv1.ChallengeResponse {
	return &authv1.ChallengeResponse{
		Type: &authv1.ChallengeResponse_Fido{
			Fido: &authv1.ChallengeResponse_FIDO{
				Response: resp,
			},
		},
	}
}

func newWebAuthnServer(t *testing.T, tst *tests.T) *server {
	t.Helper()

	ctx := context.Background()

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	srv, err := initServer(ctx, tst.C.OcteliumC, cc)
	assert.Nil(t, err, "%+v", err)

	return srv
}

func newWebAuthnTestEnv(t *testing.T) (*server, *tests.T, *admin.Server) {
	t.Helper()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	return newWebAuthnServer(t, tst), tst, admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})
}

func setClusterAuthenticator(t *testing.T, tst *tests.T,
	arg *corev1.ClusterConfig_Spec_Authenticator) {
	t.Helper()

	ctx := context.Background()

	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
	assert.Nil(t, err)

	cc.Spec.Authenticator = arg

	_, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
	assert.Nil(t, err)
}

func (s *server) mustGetAuthenticator(t *testing.T, authn *corev1.Authenticator) *corev1.Authenticator {
	t.Helper()

	ret, err := s.octeliumC.CoreC().GetAuthenticator(context.Background(), &rmetav1.GetOptions{
		Uid: authn.Metadata.Uid,
	})
	assert.Nil(t, err, "%+v", err)

	return ret
}

func resyncWebSession(t *testing.T, srv *server, usrT *tstuser.User) {
	t.Helper()

	usrT.Resync()

	refreshToken, err := srv.generateRefreshToken(usrT.Session)
	assert.Nil(t, err, "%+v", err)

	usrT.SetSessionToken(&authv1.SessionToken{RefreshToken: refreshToken})
}

func createFIDOAuthenticator(t *testing.T, srv *server, usrT *tstuser.User) *corev1.Authenticator {
	t.Helper()

	authn, err := srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{
		Type:        authv1.Authenticator_Status_FIDO,
		DisplayName: "virtual key",
	})
	assert.Nil(t, err, "%+v", err)
	assert.False(t, authn.Status.IsRegistered)

	ret, err := srv.octeliumC.CoreC().GetAuthenticator(context.Background(), &rmetav1.GetOptions{
		Uid: authn.Metadata.Uid,
	})
	assert.Nil(t, err, "%+v", err)

	return ret
}

func beginFIDORegistration(t *testing.T, srv *server,
	usrT *tstuser.User, authn *corev1.Authenticator) (string, error) {
	t.Helper()

	resp, err := srv.doRegisterAuthenticatorBegin(getCtxRT(usrT),
		&authv1.RegisterAuthenticatorBeginRequest{
			AuthenticatorRef: umetav1.GetObjectReference(authn),
		})
	if err != nil {
		return "", err
	}

	assert.NotNil(t, resp.ChallengeRequest.GetFido())

	return resp.ChallengeRequest.GetFido().Request, nil
}

func finishFIDORegistration(t *testing.T, srv *server,
	usrT *tstuser.User, authn *corev1.Authenticator, resp string) error {
	t.Helper()

	_, err := srv.doRegisterAuthenticatorFinish(getCtxRT(usrT),
		&authv1.RegisterAuthenticatorFinishRequest{
			AuthenticatorRef:  umetav1.GetObjectReference(authn),
			ChallengeResponse: fidoChallengeResponse(resp),
		})

	return err
}

func registerFIDO(t *testing.T, srv *server,
	usrT *tstuser.User, authn *corev1.Authenticator, d *virtualFIDO) error {
	t.Helper()

	req, err := beginFIDORegistration(t, srv, usrT, authn)
	if err != nil {
		return err
	}

	return finishFIDORegistration(t, srv, usrT, authn, d.attestation(t, req))
}

func beginFIDOAuthentication(t *testing.T, srv *server,
	usrT *tstuser.User, authn *corev1.Authenticator) (string, error) {
	t.Helper()

	resp, err := srv.doAuthenticateAuthenticatorBegin(getCtxRT(usrT),
		&authv1.AuthenticateAuthenticatorBeginRequest{
			AuthenticatorRef: umetav1.GetObjectReference(authn),
		})
	if err != nil {
		return "", err
	}

	assert.NotNil(t, resp.ChallengeRequest.GetFido())

	return resp.ChallengeRequest.GetFido().Request, nil
}

func finishFIDOAuthentication(t *testing.T, srv *server,
	usrT *tstuser.User, authn *corev1.Authenticator, resp string) (*authv1.SessionToken, error) {
	t.Helper()

	return srv.doAuthenticateWithAuthenticator(getCtxRT(usrT),
		&authv1.AuthenticateWithAuthenticatorRequest{
			AuthenticatorRef:  umetav1.GetObjectReference(authn),
			ChallengeResponse: fidoChallengeResponse(resp),
		})
}

func authenticateFIDO(t *testing.T, srv *server,
	usrT *tstuser.User, authn *corev1.Authenticator, d *virtualFIDO) (*authv1.SessionToken, error) {
	t.Helper()

	req, err := beginFIDOAuthentication(t, srv, usrT, authn)
	if err != nil {
		return nil, err
	}

	return finishFIDOAuthentication(t, srv, usrT, authn, d.assertion(t, req))
}

func TestFIDORegistrationCeremony(t *testing.T) {

	ctx := context.Background()

	srv, tst, adminSrv := newWebAuthnTestEnv(t)

	usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
	assert.Nil(t, err, "%+v", err)

	authn := createFIDOAuthenticator(t, srv, usrT)
	d := newPasskeyFIDO(srv.domain, usrT.Usr)

	req, err := beginFIDORegistration(t, srv, usrT, authn)
	assert.Nil(t, err, "%+v", err)

	{
		opts := &protocol.PublicKeyCredentialCreationOptions{}
		assert.Nil(t, json.Unmarshal([]byte(req), opts))

		assert.Equal(t, srv.domain, opts.RelyingParty.ID)
		assert.Equal(t, 32, len(opts.Challenge))
		assert.Equal(t, protocol.ResidentKeyRequirementPreferred, opts.AuthenticatorSelection.ResidentKey)
		assert.Equal(t, protocol.VerificationPreferred, opts.AuthenticatorSelection.UserVerification)
		assert.True(t, opts.Timeout > 0)

		vopts, err := virtualwebauthn.ParseAttestationOptions(req)
		assert.Nil(t, err, "%+v", err)

		uid, err := uuid.Parse(usrT.Usr.Metadata.Uid)
		assert.Nil(t, err)
		assert.Equal(t, uid[:], []byte(vopts.UserID))
	}

	assert.Nil(t, finishFIDORegistration(t, srv, usrT, authn, d.attestation(t, req)))

	authn = srv.mustGetAuthenticator(t, authn)
	assert.True(t, authn.Status.IsRegistered)
	assert.Nil(t, authn.Status.AuthenticationAttempt)

	fido := authn.Status.GetInfo().GetFido()
	assert.NotNil(t, fido)
	assert.Equal(t, d.cred.ID, fido.Id)
	assert.True(t, len(fido.IdHash) == 32)
	assert.True(t, len(fido.PublicKey) > 0)
	assert.True(t, fido.IsPasskey)
	assert.True(t, fido.BackupEligible)
	assert.Equal(t, uuid.UUID(d.auth.Aaguid).String(), fido.Aaguid)
	assert.False(t, fido.IsAttestationVerified)

	{
		itmList, err := srv.octeliumC.CoreC().ListAuthenticator(ctx, &rmetav1.ListOptions{})
		assert.Nil(t, err)
		assert.True(t, len(itmList.Items) > 0)
	}

	t.Run("AlreadyRegistered", func(t *testing.T) {
		_, err := beginFIDORegistration(t, srv, usrT, authn)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	})

	t.Run("DuplicateCredentialIDRejected", func(t *testing.T) {
		otherT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err, "%+v", err)

		other := createFIDOAuthenticator(t, srv, otherT)

		dup := newPasskeyFIDO(srv.domain, otherT.Usr)
		dup.cred = d.cred

		err = registerFIDO(t, srv, otherT, other, dup)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

		other = srv.mustGetAuthenticator(t, other)
		assert.False(t, other.Status.IsRegistered)
	})
}

func TestFIDORegistrationRejections(t *testing.T) {

	srv, tst, adminSrv := newWebAuthnTestEnv(t)

	usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
	assert.Nil(t, err, "%+v", err)

	newAttempt := func(t *testing.T) (*corev1.Authenticator, string) {
		t.Helper()

		authn := createFIDOAuthenticator(t, srv, usrT)
		req, err := beginFIDORegistration(t, srv, usrT, authn)
		assert.Nil(t, err, "%+v", err)

		return authn, req
	}

	t.Run("ForeignOriginRejected", func(t *testing.T) {
		authn, req := newAttempt(t)

		d := newPasskeyFIDO(srv.domain, usrT.Usr)
		d.rp.Origin = "https://evil.example.com"

		err := finishFIDORegistration(t, srv, usrT, authn, d.attestation(t, req))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

		assert.False(t, srv.mustGetAuthenticator(t, authn).Status.IsRegistered)
	})

	t.Run("ForeignRelyingPartyRejected", func(t *testing.T) {
		authn, req := newAttempt(t)

		d := newPasskeyFIDO(srv.domain, usrT.Usr)
		d.rp.ID = "evil.example.com"

		err := finishFIDORegistration(t, srv, usrT, authn, d.attestation(t, req))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("ForeignChallengeRejected", func(t *testing.T) {
		authn, _ := newAttempt(t)

		other := createFIDOAuthenticator(t, srv, usrT)
		otherReq, err := beginFIDORegistration(t, srv, usrT, other)
		assert.Nil(t, err, "%+v", err)

		d := newPasskeyFIDO(srv.domain, usrT.Usr)

		err = finishFIDORegistration(t, srv, usrT, authn, d.attestation(t, otherReq))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("UserNotPresentRejected", func(t *testing.T) {
		authn, req := newAttempt(t)

		d := newVirtualFIDO(srv.domain, usrT.Usr, virtualwebauthn.AuthenticatorOptions{
			UserNotPresent: true,
		})

		err := finishFIDORegistration(t, srv, usrT, authn, d.attestation(t, req))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("FailedAttemptIsNullified", func(t *testing.T) {
		authn, req := newAttempt(t)

		d := newPasskeyFIDO(srv.domain, usrT.Usr)
		d.rp.Origin = "https://evil.example.com"

		assert.NotNil(t, finishFIDORegistration(t, srv, usrT, authn, d.attestation(t, req)))
		assert.Nil(t, srv.mustGetAuthenticator(t, authn).Status.AuthenticationAttempt)

		err := finishFIDORegistration(t, srv, usrT, authn,
			newPasskeyFIDO(srv.domain, usrT.Usr).attestation(t, req))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("ForeignSessionRejected", func(t *testing.T) {
		authn, req := newAttempt(t)

		otherT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err, "%+v", err)

		d := newPasskeyFIDO(srv.domain, usrT.Usr)

		err = finishFIDORegistration(t, srv, otherT, authn, d.attestation(t, req))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("NonBrowserSessionRejected", func(t *testing.T) {
		clientT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)

		_, err = srv.doCreateAuthenticator(getCtxRT(clientT), &authv1.CreateAuthenticatorRequest{
			Type: authv1.Authenticator_Status_FIDO,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("WorkloadUserRejected", func(t *testing.T) {
		wlT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_WORKLOAD, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err, "%+v", err)

		wlT.Session.Status.IsBrowser = true
		wlT.Session, err = srv.octeliumC.CoreC().UpdateSession(context.Background(), wlT.Session)
		assert.Nil(t, err)

		_, err = srv.doCreateAuthenticator(getCtxRT(wlT), &authv1.CreateAuthenticatorRequest{
			Type: authv1.Authenticator_Status_FIDO,
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})
}

func TestFIDOAuthenticationCeremony(t *testing.T) {

	srv, tst, adminSrv := newWebAuthnTestEnv(t)

	usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
	assert.Nil(t, err, "%+v", err)

	authn := createFIDOAuthenticator(t, srv, usrT)
	d := newPasskeyFIDO(srv.domain, usrT.Usr)

	assert.Nil(t, registerFIDO(t, srv, usrT, authn, d))

	{
		req, err := beginFIDOAuthentication(t, srv, usrT, authn)
		assert.Nil(t, err, "%+v", err)

		opts := &protocol.PublicKeyCredentialRequestOptions{}
		assert.Nil(t, json.Unmarshal([]byte(req), opts))
		assert.Equal(t, srv.domain, opts.RelyingPartyID)
		assert.Equal(t, 32, len(opts.Challenge))
		assert.Equal(t, 1, len(opts.AllowedCredentials))
		assert.Equal(t, d.cred.ID, []byte(opts.AllowedCredentials[0].CredentialID))

		d.cred.Counter = 4

		tkn, err := finishFIDOAuthentication(t, srv, usrT, authn, d.assertion(t, req))
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, tkn)
		assert.Empty(t, tkn.AccessToken)
		assert.Empty(t, tkn.RefreshToken)

		resyncWebSession(t, srv, usrT)
	}

	authn = srv.mustGetAuthenticator(t, authn)
	assert.Equal(t, uint32(1), authn.Status.SuccessfulAuthentications)
	assert.Equal(t, uint32(4), authn.Status.GetInfo().GetFido().SignCount)
	assert.Nil(t, authn.Status.AuthenticationAttempt)
	assert.True(t, len(authn.Status.LastAuthenticationAttempts) > 0)

	sess, err := srv.octeliumC.CoreC().GetSession(context.Background(), &rmetav1.GetOptions{
		Uid: usrT.Session.Metadata.Uid,
	})
	assert.Nil(t, err)

	info := sess.Status.Authentication.Info
	assert.Equal(t, corev1.Session_Status_Authentication_Info_AUTHENTICATOR, info.Type)
	assert.Equal(t, authn.Metadata.Uid, info.GetAuthenticator().AuthenticatorRef.Uid)
	assert.Equal(t, corev1.Authenticator_Status_FIDO, info.GetAuthenticator().Type)

	fidoInfo := info.GetAuthenticator().GetInfo().GetFido()
	assert.NotNil(t, fidoInfo)
	assert.True(t, fidoInfo.UserPresent)
	assert.True(t, fidoInfo.UserVerified)
	assert.True(t, fidoInfo.IsPasskey)
	assert.Equal(t, uuid.UUID(d.auth.Aaguid).String(), fidoInfo.Aaguid)

	assert.NotNil(t, sess.Status.RequiredAuthenticatorRef)
	assert.Equal(t, authn.Metadata.Uid, sess.Status.RequiredAuthenticatorRef.Uid)

	t.Run("ReplayRejected", func(t *testing.T) {
		req, err := beginFIDOAuthentication(t, srv, usrT, authn)
		assert.Nil(t, err, "%+v", err)

		d.cred.Counter = 8
		resp := d.assertion(t, req)

		_, err = finishFIDOAuthentication(t, srv, usrT, authn, resp)
		assert.Nil(t, err, "%+v", err)

		resyncWebSession(t, srv, usrT)

		_, err = finishFIDOAuthentication(t, srv, usrT, authn, resp)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("ClonedAuthenticatorRejected", func(t *testing.T) {
		req, err := beginFIDOAuthentication(t, srv, usrT, authn)
		assert.Nil(t, err, "%+v", err)

		d.cred.Counter = 2

		_, err = finishFIDOAuthentication(t, srv, usrT, authn, d.assertion(t, req))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

		d.cred.Counter = 9
	})

	t.Run("ForeignOriginRejected", func(t *testing.T) {
		req, err := beginFIDOAuthentication(t, srv, usrT, authn)
		assert.Nil(t, err, "%+v", err)

		evil := *d
		evil.rp.Origin = "https://evil.example.com"

		_, err = finishFIDOAuthentication(t, srv, usrT, authn, evil.assertion(t, req))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("UnknownCredentialRejected", func(t *testing.T) {
		req, err := beginFIDOAuthentication(t, srv, usrT, authn)
		assert.Nil(t, err, "%+v", err)

		_, err = finishFIDOAuthentication(t, srv, usrT, authn,
			newPasskeyFIDO(srv.domain, usrT.Usr).assertion(t, req))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("WithoutBeginRejected", func(t *testing.T) {
		req, err := beginFIDOAuthentication(t, srv, usrT, authn)
		assert.Nil(t, err, "%+v", err)

		resp := d.assertion(t, req)

		_, err = finishFIDOAuthentication(t, srv, usrT, authn, resp)
		assert.Nil(t, err, "%+v", err)

		resyncWebSession(t, srv, usrT)

		_, err = finishFIDOAuthentication(t, srv, usrT, authn, resp)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("InactiveAuthenticatorRejected", func(t *testing.T) {
		ctx := context.Background()

		cur := srv.mustGetAuthenticator(t, authn)
		cur.Spec.State = corev1.Authenticator_Spec_PENDING

		cur, err := srv.octeliumC.CoreC().UpdateAuthenticator(ctx, cur)
		assert.Nil(t, err)

		_, err = beginFIDOAuthentication(t, srv, usrT, cur)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

		cur.Spec.State = corev1.Authenticator_Spec_ACTIVE
		_, err = srv.octeliumC.CoreC().UpdateAuthenticator(ctx, cur)
		assert.Nil(t, err)
	})

	t.Run("ForeignAuthenticatorRejected", func(t *testing.T) {
		otherT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
		assert.Nil(t, err, "%+v", err)

		_, err = beginFIDOAuthentication(t, srv, otherT, authn)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("ClientSessionRejected", func(t *testing.T) {
		clientT, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)

		other := &corev1.Authenticator{}
		other.Metadata = authn.Metadata

		_, err = beginFIDOAuthentication(t, srv, clientT, other)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})
}

func TestFIDOUnregisteredAuthenticationRejected(t *testing.T) {

	srv, tst, adminSrv := newWebAuthnTestEnv(t)

	usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
	assert.Nil(t, err, "%+v", err)

	authn := createFIDOAuthenticator(t, srv, usrT)

	_, err = beginFIDOAuthentication(t, srv, usrT, authn)
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)

	unsolicited := fmt.Sprintf(`{"challenge":%q,"rpId":%q}`,
		base64.RawURLEncoding.EncodeToString(utilrand.GetRandomBytesMust(32)), srv.domain)

	_, err = finishFIDOAuthentication(t, srv, usrT, authn,
		newPasskeyFIDO(srv.domain, usrT.Usr).assertion(t, unsolicited))
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
}

func TestFIDOAttestationConveyancePreference(t *testing.T) {

	ctx := context.Background()

	srv, tst, adminSrv := newWebAuthnTestEnv(t)

	usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
	assert.Nil(t, err, "%+v", err)

	setPreference := func(t *testing.T,
		arg corev1.ClusterConfig_Spec_Authenticator_FIDO_AttestationConveyancePreference) {
		t.Helper()

		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			Fido: &corev1.ClusterConfig_Spec_Authenticator_FIDO{
				AttestationConveyancePreference: arg,
			},
		}

		_, err = srv.octeliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	for _, tc := range []struct {
		arg  corev1.ClusterConfig_Spec_Authenticator_FIDO_AttestationConveyancePreference
		want protocol.ConveyancePreference
	}{
		{
			corev1.ClusterConfig_Spec_Authenticator_FIDO_ATTESTATION_CONVEYANCE_PREFERENCE_UNSET,
			protocol.PreferDirectAttestation,
		},
		{
			corev1.ClusterConfig_Spec_Authenticator_FIDO_DIRECT,
			protocol.PreferDirectAttestation,
		},
		{
			corev1.ClusterConfig_Spec_Authenticator_FIDO_INDIRECT,
			protocol.PreferIndirectAttestation,
		},
		{
			corev1.ClusterConfig_Spec_Authenticator_FIDO_ENTERPRISE,
			protocol.PreferEnterpriseAttestation,
		},
		{
			corev1.ClusterConfig_Spec_Authenticator_FIDO_NONE,
			protocol.PreferNoAttestation,
		},
	} {
		setPreference(t, tc.arg)

		authn := createFIDOAuthenticator(t, srv, usrT)

		req, err := beginFIDORegistration(t, srv, usrT, authn)
		assert.Nil(t, err, "%+v", err)

		opts := &protocol.PublicKeyCredentialCreationOptions{}
		assert.Nil(t, json.Unmarshal([]byte(req), opts))
		assert.Equal(t, tc.want, opts.Attestation, "%v", tc.arg)

		assert.Nil(t, finishFIDORegistration(t, srv, usrT, authn,
			newPasskeyFIDO(srv.domain, usrT.Usr).attestation(t, req)))
	}
}

func TestFIDOPostAuthenticationRules(t *testing.T) {

	ctx := context.Background()

	srv, tst, adminSrv := newWebAuthnTestEnv(t)

	usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
	assert.Nil(t, err, "%+v", err)

	authn := createFIDOAuthenticator(t, srv, usrT)
	d := newPasskeyFIDO(srv.domain, usrT.Usr)

	assert.Nil(t, registerFIDO(t, srv, usrT, authn, d))

	setRules := func(t *testing.T, rules []*corev1.ClusterConfig_Spec_Authenticator_Rule) {
		t.Helper()

		cc, err := srv.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Spec.Authenticator = &corev1.ClusterConfig_Spec_Authenticator{
			PostAuthenticationRules: rules,
		}

		_, err = srv.octeliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	newRule := func(match string,
		effect corev1.ClusterConfig_Spec_Authenticator_Rule_Effect) *corev1.ClusterConfig_Spec_Authenticator_Rule {
		return &corev1.ClusterConfig_Spec_Authenticator_Rule{
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: match,
				},
			},
			Effect: effect,
		}
	}

	t.Run("DenyVerifiedUser", func(t *testing.T) {
		resyncWebSession(t, srv, usrT)

		setRules(t, []*corev1.ClusterConfig_Spec_Authenticator_Rule{
			newRule(`ctx.info.authenticator.info.fido.userVerified`,
				corev1.ClusterConfig_Spec_Authenticator_Rule_DENY),
		})

		d.cred.Counter = d.cred.Counter + 1

		_, err := authenticateFIDO(t, srv, usrT, authn, d)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("DenyByAAGUID", func(t *testing.T) {
		resyncWebSession(t, srv, usrT)

		setRules(t, []*corev1.ClusterConfig_Spec_Authenticator_Rule{
			newRule(fmt.Sprintf(`ctx.info.authenticator.info.fido.aaguid == "%s"`,
				uuid.UUID(d.auth.Aaguid).String()),
				corev1.ClusterConfig_Spec_Authenticator_Rule_DENY),
		})

		d.cred.Counter = d.cred.Counter + 1

		_, err := authenticateFIDO(t, srv, usrT, authn, d)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("AllowBeforeDeny", func(t *testing.T) {
		resyncWebSession(t, srv, usrT)

		setRules(t, []*corev1.ClusterConfig_Spec_Authenticator_Rule{
			newRule(`ctx.info.authenticator.info.fido.userVerified`,
				corev1.ClusterConfig_Spec_Authenticator_Rule_ALLOW),
			newRule(`true`, corev1.ClusterConfig_Spec_Authenticator_Rule_DENY),
		})

		d.cred.Counter = d.cred.Counter + 1

		_, err := authenticateFIDO(t, srv, usrT, authn, d)
		assert.Nil(t, err, "%+v", err)
	})

	t.Run("DenyByUser", func(t *testing.T) {
		resyncWebSession(t, srv, usrT)

		setRules(t, []*corev1.ClusterConfig_Spec_Authenticator_Rule{
			newRule(fmt.Sprintf(`ctx.user.metadata.uid == "%s"`, usrT.Usr.Metadata.Uid),
				corev1.ClusterConfig_Spec_Authenticator_Rule_DENY),
		})

		d.cred.Counter = d.cred.Counter + 1

		_, err := authenticateFIDO(t, srv, usrT, authn, d)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("RulesRemoved", func(t *testing.T) {
		resyncWebSession(t, srv, usrT)

		setRules(t, nil)

		d.cred.Counter = d.cred.Counter + 1

		_, err := authenticateFIDO(t, srv, usrT, authn, d)
		assert.Nil(t, err, "%+v", err)
	})
}

func newPasskeyEnv(t *testing.T,
	rules []*corev1.ClusterConfig_Spec_Authenticator_Rule) (*server, *tests.T, *tstuser.User, *virtualFIDO) {
	t.Helper()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	setClusterAuthenticator(t, tst, &corev1.ClusterConfig_Spec_Authenticator{
		EnablePasskeyLogin:      true,
		PostAuthenticationRules: rules,
	})

	srv := newWebAuthnServer(t, tst)

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
	assert.Nil(t, err, "%+v", err)

	authn := createFIDOAuthenticator(t, srv, usrT)
	d := newPasskeyFIDO(srv.domain, usrT.Usr)

	assert.Nil(t, registerFIDO(t, srv, usrT, authn, d))
	assert.Nil(t, srv.authnCache.SetAuthenticator(srv.mustGetAuthenticator(t, authn)))

	return srv, tst, usrT, d
}

func passkeyLogin(t *testing.T, srv *server, d *virtualFIDO) (*authv1.SessionToken, error) {
	t.Helper()

	begin, err := srv.doAuthenticateWithPasskeyBegin(newWebCtx(srv),
		&authv1.AuthenticateWithPasskeyBeginRequest{})
	if err != nil {
		return nil, err
	}

	opts := &protocol.PublicKeyCredentialRequestOptions{}
	assert.Nil(t, json.Unmarshal([]byte(begin.Request), opts))
	assert.Equal(t, srv.domain, opts.RelyingPartyID)
	assert.Equal(t, protocol.VerificationRequired, opts.UserVerification)
	assert.Equal(t, 0, len(opts.AllowedCredentials))
	assert.Equal(t, 32, len(opts.Challenge))

	return srv.doAuthenticateWithPasskey(newWebCtx(srv),
		&authv1.AuthenticateWithPasskeyRequest{
			Response: d.assertion(t, begin.Request),
		})
}

func TestPasskeyLoginCeremony(t *testing.T) {

	ctx := context.Background()

	srv, _, usrT, d := newPasskeyEnv(t, nil)

	authn, err := srv.octeliumC.CoreC().ListAuthenticator(ctx, &rmetav1.ListOptions{})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(authn.Items))

	d.cred.Counter = 3

	tkn, err := passkeyLogin(t, srv, d)
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, tkn)

	sessList, err := srv.octeliumC.CoreC().ListSession(ctx, &rmetav1.ListOptions{})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(sessList.Items))

	var sess *corev1.Session
	for _, itm := range sessList.Items {
		if itm.Metadata.Uid != usrT.Session.Metadata.Uid {
			sess = itm
		}
	}
	assert.NotNil(t, sess)

	assert.True(t, sess.Status.IsBrowser)
	assert.Equal(t, corev1.Session_Status_CLIENTLESS, sess.Status.Type)
	assert.Equal(t, usrT.Usr.Metadata.Uid, sess.Status.UserRef.Uid)
	assert.NotNil(t, sess.Status.RequiredAuthenticatorRef)
	assert.Equal(t, authn.Items[0].Metadata.Uid, sess.Status.RequiredAuthenticatorRef.Uid)

	info := sess.Status.Authentication.Info
	assert.Equal(t, corev1.Session_Status_Authentication_Info_AUTHENTICATOR, info.Type)
	assert.Equal(t, corev1.Session_Status_Authentication_Info_Authenticator_PASSKEY,
		info.GetAuthenticator().Mode)
	assert.Equal(t, corev1.Authenticator_Status_FIDO, info.GetAuthenticator().Type)
	assert.True(t, info.GetAuthenticator().GetInfo().GetFido().UserVerified)
	assert.True(t, info.GetAuthenticator().GetInfo().GetFido().UserPresent)
	assert.True(t, info.GetAuthenticator().GetInfo().GetFido().IsPasskey)

	assert.Equal(t, uint32(3),
		srv.mustGetAuthenticator(t, authn.Items[0]).Status.GetInfo().GetFido().SignCount)

	t.Run("SessionIsPinnedToThePasskey", func(t *testing.T) {
		refreshToken, err := srv.generateRefreshToken(sess)
		assert.Nil(t, err, "%+v", err)

		res, err := srv.doGetAvailableAuthenticator(
			getCtxRTSessTkn(&authv1.SessionToken{RefreshToken: refreshToken}),
			&authv1.GetAvailableAuthenticatorRequest{})
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, res.MainAuthenticator)
		assert.Equal(t, authn.Items[0].Metadata.Uid, res.MainAuthenticator.Metadata.Uid)
		assert.Equal(t, 1, len(res.AvailableAuthenticators))
	})

	t.Run("UnknownCredentialRejected", func(t *testing.T) {
		_, err := passkeyLogin(t, srv, newPasskeyFIDO(srv.domain, usrT.Usr))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("UnverifiedUserRejected", func(t *testing.T) {
		unverified := *d
		unverified.auth.Options.UserNotVerified = true
		unverified.cred.Counter = d.cred.Counter + 1

		_, err := passkeyLogin(t, srv, &unverified)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("ForeignOriginRejected", func(t *testing.T) {
		evil := *d
		evil.rp.Origin = "https://evil.example.com"
		evil.cred.Counter = d.cred.Counter + 1

		_, err := passkeyLogin(t, srv, &evil)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("ForeignUserHandleRejected", func(t *testing.T) {
		foreign := *d
		otherHandle := uuid.New()
		foreign.auth.Options.UserHandle = otherHandle[:]
		foreign.cred.Counter = d.cred.Counter + 1

		_, err := passkeyLogin(t, srv, &foreign)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("ReplayRejected", func(t *testing.T) {
		begin, err := srv.doAuthenticateWithPasskeyBegin(newWebCtx(srv),
			&authv1.AuthenticateWithPasskeyBeginRequest{})
		assert.Nil(t, err, "%+v", err)

		d.cred.Counter = d.cred.Counter + 4
		resp := d.assertion(t, begin.Request)

		_, err = srv.doAuthenticateWithPasskey(newWebCtx(srv),
			&authv1.AuthenticateWithPasskeyRequest{Response: resp})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.doAuthenticateWithPasskey(newWebCtx(srv),
			&authv1.AuthenticateWithPasskeyRequest{Response: resp})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("NonBrowserRequestRejected", func(t *testing.T) {
		_, err := srv.doAuthenticateWithPasskeyBegin(context.Background(),
			&authv1.AuthenticateWithPasskeyBeginRequest{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)

		d.cred.Counter = d.cred.Counter + 1

		_, err = srv.doAuthenticateWithPasskey(context.Background(),
			&authv1.AuthenticateWithPasskeyRequest{
				Response: d.assertion(t, fmt.Sprintf(`{"challenge":%q,"rpId":%q}`,
					base64.RawURLEncoding.EncodeToString(utilrand.GetRandomBytesMust(32)),
					srv.domain)),
			})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	})

	t.Run("InactiveAuthenticatorRejected", func(t *testing.T) {
		cur := srv.mustGetAuthenticator(t, authn.Items[0])
		cur.Spec.State = corev1.Authenticator_Spec_PENDING

		cur, err := srv.octeliumC.CoreC().UpdateAuthenticator(ctx, cur)
		assert.Nil(t, err)
		assert.Nil(t, srv.authnCache.SetAuthenticator(cur))

		d.cred.Counter = d.cred.Counter + 1

		_, err = passkeyLogin(t, srv, d)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

		cur.Spec.State = corev1.Authenticator_Spec_ACTIVE
		cur, err = srv.octeliumC.CoreC().UpdateAuthenticator(ctx, cur)
		assert.Nil(t, err)
		assert.Nil(t, srv.authnCache.SetAuthenticator(cur))
	})

	t.Run("DisabledUserRejected", func(t *testing.T) {
		usr := usrT.Usr
		usr.Spec.IsDisabled = true

		usr, err := srv.octeliumC.CoreC().UpdateUser(ctx, usr)
		assert.Nil(t, err)

		d.cred.Counter = d.cred.Counter + 1

		_, err = passkeyLogin(t, srv, d)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

		usr.Spec.IsDisabled = false
		_, err = srv.octeliumC.CoreC().UpdateUser(ctx, usr)
		assert.Nil(t, err)
	})

	t.Run("StillAllowedAfterRejections", func(t *testing.T) {
		d.cred.Counter = d.cred.Counter + 1

		_, err := passkeyLogin(t, srv, d)
		assert.Nil(t, err, "%+v", err)
	})
}

func TestPasskeyLoginPostAuthenticationRules(t *testing.T) {

	srv, tst, _, d := newPasskeyEnv(t, []*corev1.ClusterConfig_Spec_Authenticator_Rule{
		{
			Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{
					Match: `ctx.info.authenticator.mode == "PASSKEY"`,
				},
			},
			Effect: corev1.ClusterConfig_Spec_Authenticator_Rule_DENY,
		},
	})

	d.cred.Counter = 2

	_, err := passkeyLogin(t, srv, d)
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

	setClusterAuthenticator(t, tst, &corev1.ClusterConfig_Spec_Authenticator{
		EnablePasskeyLogin: true,
	})

	allowed := newWebAuthnServer(t, tst)

	authnList, err := allowed.octeliumC.CoreC().ListAuthenticator(context.Background(),
		&rmetav1.ListOptions{})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(authnList.Items))
	assert.Nil(t, allowed.authnCache.SetAuthenticator(authnList.Items[0]))

	d.cred.Counter = d.cred.Counter + 1

	_, err = passkeyLogin(t, allowed, d)
	assert.Nil(t, err, "%+v", err)
}

func TestPasskeyLoginRequiresClusterConfig(t *testing.T) {

	srv, tst, adminSrv := newWebAuthnTestEnv(t)

	usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
	assert.Nil(t, err, "%+v", err)

	authn := createFIDOAuthenticator(t, srv, usrT)
	d := newPasskeyFIDO(srv.domain, usrT.Usr)

	assert.Nil(t, registerFIDO(t, srv, usrT, authn, d))
	assert.Nil(t, srv.authnCache.SetAuthenticator(srv.mustGetAuthenticator(t, authn)))

	_, err = passkeyLogin(t, srv, d)
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

	setClusterAuthenticator(t, tst, &corev1.ClusterConfig_Spec_Authenticator{
		EnablePasskeyLogin: true,
	})

	enabled := newWebAuthnServer(t, tst)
	assert.Nil(t, enabled.authnCache.SetAuthenticator(enabled.mustGetAuthenticator(t, authn)))

	d.cred.Counter = 2

	_, err = passkeyLogin(t, enabled, d)
	assert.Nil(t, err, "%+v", err)
}

func TestFIDOAuthenticatorDefaultState(t *testing.T) {

	ctx := context.Background()

	srv, tst, adminSrv := newWebAuthnTestEnv(t)

	setClusterAuthenticator(t, tst, &corev1.ClusterConfig_Spec_Authenticator{
		DefaultState: corev1.Authenticator_Spec_PENDING,
	})

	usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
	assert.Nil(t, err, "%+v", err)

	authn := createFIDOAuthenticator(t, srv, usrT)
	assert.Equal(t, corev1.Authenticator_Spec_PENDING, authn.Spec.State)

	d := newPasskeyFIDO(srv.domain, usrT.Usr)
	assert.Nil(t, registerFIDO(t, srv, usrT, authn, d))
	assert.True(t, srv.mustGetAuthenticator(t, authn).Status.IsRegistered)

	_, err = beginFIDOAuthentication(t, srv, usrT, authn)
	assert.NotNil(t, err, "a PENDING Authenticator must not authenticate")
	assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

	t.Run("UserOverridesCluster", func(t *testing.T) {
		usr := usrT.Usr
		usr.Spec.Authentication = &corev1.User_Spec_Authentication{
			AuthenticatorDefaultState: corev1.Authenticator_Spec_ACTIVE,
		}

		usr, err := srv.octeliumC.CoreC().UpdateUser(ctx, usr)
		assert.Nil(t, err)
		usrT.Usr = usr

		other := createFIDOAuthenticator(t, srv, usrT)
		assert.Equal(t, corev1.Authenticator_Spec_ACTIVE, other.Spec.State)

		assert.Nil(t, registerFIDO(t, srv, usrT, other, newPasskeyFIDO(srv.domain, usrT.Usr)))

		_, err = beginFIDOAuthentication(t, srv, usrT, other)
		assert.Nil(t, err, "%+v", err)
	})
}

func TestFIDOAuthenticatorActionGuards(t *testing.T) {

	ctx := context.Background()

	srv, tst, adminSrv := newWebAuthnTestEnv(t)

	usrT, err := tstuser.NewUserWeb(tst.C.OcteliumC, adminSrv, nil, nil)
	assert.Nil(t, err, "%+v", err)

	authn := createFIDOAuthenticator(t, srv, usrT)

	sess := usrT.Session
	sess.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATION_REQUIRED

	sess, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
	assert.Nil(t, err)
	usrT.Session = sess

	_, err = srv.doCreateAuthenticator(getCtxRT(usrT), &authv1.CreateAuthenticatorRequest{
		Type: authv1.Authenticator_Status_FIDO,
	})
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

	_, err = beginFIDORegistration(t, srv, usrT, authn)
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

	_, err = srv.doDeleteAuthenticator(getCtxRT(usrT), &metav1.DeleteOptions{
		Uid: authn.Metadata.Uid,
	})
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

	sess.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET
	sess, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
	assert.Nil(t, err)
	usrT.Session = sess

	assert.Nil(t, registerFIDO(t, srv, usrT, authn, newPasskeyFIDO(srv.domain, usrT.Usr)))
}
