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
	"crypto/x509"
	"testing"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/sessionc"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

type tstDeviceSession struct {
	srv *server
	uid string
	tkn *authv1.SessionToken
}

func newTstDeviceSession(t *testing.T, srv *server, usrT *tstuser.User,
	opts *sessionc.CreateSessionOpts) *tstDeviceSession {
	t.Helper()

	ctx := context.Background()

	if opts == nil {
		opts = &sessionc.CreateSessionOpts{
			SessType: corev1.Session_Status_CLIENT,
		}
	}

	opts.OcteliumC = srv.octeliumC
	opts.Usr = usrT.Usr

	sess, err := sessionc.CreateSession(ctx, opts)
	assert.Nil(t, err, "%+v", err)

	refreshToken, err := srv.generateRefreshToken(sess)
	assert.Nil(t, err, "%+v", err)

	return &tstDeviceSession{
		srv: srv,
		uid: sess.Metadata.Uid,
		tkn: &authv1.SessionToken{RefreshToken: refreshToken},
	}
}

func (c *tstDeviceSession) ctx() context.Context {
	return getCtxRTSessTkn(c.tkn)
}

func (c *tstDeviceSession) session(t *testing.T) *corev1.Session {
	t.Helper()

	ret, err := c.srv.octeliumC.CoreC().GetSession(context.Background(), &rmetav1.GetOptions{
		Uid: c.uid,
	})
	assert.Nil(t, err, "%+v", err)

	return ret
}

func (c *tstDeviceSession) registerDevice(t *testing.T, info *authv1.RegisterDeviceRequest_Info) {
	t.Helper()

	_, err := c.srv.doRegisterDevice(c.ctx(), &authv1.RegisterDeviceRequest{Info: info})
	assert.Nil(t, err, "%+v", err)
}

func newTstDeviceInfo() *authv1.RegisterDeviceRequest_Info {
	return &authv1.RegisterDeviceRequest_Info{
		OsType:       authv1.RegisterDeviceRequest_Info_LINUX,
		Hostname:     utilrand.GetRandomStringCanonical(8),
		Id:           utilrand.GetRandomStringHex(64),
		SerialNumber: utilrand.GetRandomStringCanonical(12),
		MacAddresses: []string{"02:42:ac:11:00:02"},
	}
}

func newTstHumanClient(t *testing.T, srv *server, adminSrv corev1.MainServiceServer) *tstuser.User {
	t.Helper()

	ret, err := tstuser.NewUserWithType(srv.octeliumC, adminSrv, nil, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err, "%+v", err)

	return ret
}

func createTstDeviceAuthenticator(t *testing.T, srv *server, usrT *tstuser.User,
	typ corev1.Authenticator_Status_Type, deviceRef *metav1.ObjectReference,
	fn func(*corev1.Authenticator)) *corev1.Authenticator {
	t.Helper()

	authn := &corev1.Authenticator{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Authenticator_Spec{
			State: corev1.Authenticator_Spec_ACTIVE,
		},
		Status: &corev1.Authenticator_Status{
			UserRef:      umetav1.GetObjectReference(usrT.Usr),
			Type:         typ,
			IsRegistered: true,
			DeviceRef:    deviceRef,
		},
	}

	if fn != nil {
		fn(authn)
	}

	ret, err := srv.octeliumC.CoreC().CreateAuthenticator(context.Background(), authn)
	assert.Nil(t, err, "%+v", err)

	return ret
}

type tstVirtualTPM struct {
	tpm *attest.TPM
	ak  *attest.AK
	pre *authv1.RegisterAuthenticatorBeginRequest_PreChallenge
}

func newTstVirtualTPM(t *testing.T) *tstVirtualTPM {
	t.Helper()

	sim, err := simulator.Get()
	assert.Nil(t, err, "%+v", err)

	tpm := attest.InjectSimulatedTPMForTest(sim)
	t.Cleanup(func() {
		tpm.Close()
	})

	eks, err := tpm.EKs()
	assert.Nil(t, err, "%+v", err)

	ak, err := tpm.NewAK(&attest.AKConfig{})
	assert.Nil(t, err, "%+v", err)

	akBytes, err := ak.Marshal()
	assert.Nil(t, err, "%+v", err)

	ekBytes, err := x509.MarshalPKIXPublicKey(eks[0].Public)
	assert.Nil(t, err, "%+v", err)

	params := ak.AttestationParameters()

	return &tstVirtualTPM{
		tpm: tpm,
		ak:  ak,
		pre: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge{
			Type: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_Tpm{
				Tpm: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM{
					EkType: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM_EkPublicKey{
						EkPublicKey: ekBytes,
					},
					AkBytes: akBytes,
					AttestationParameters: &authv1.RegisterAuthenticatorBeginRequest_PreChallenge_TPM_AttestationParameters{
						Public:            params.Public,
						CreateData:        params.CreateData,
						CreateAttestation: params.CreateAttestation,
						CreateSignature:   params.CreateSignature,
					},
				},
			},
		},
	}
}

func tpmChallengeResponse(resp []byte) *authv1.ChallengeResponse {
	return &authv1.ChallengeResponse{
		Type: &authv1.ChallengeResponse_Tpm{
			Tpm: &authv1.ChallengeResponse_TPM{
				Response: resp,
			},
		},
	}
}

func (d *tstVirtualTPM) register(t *testing.T, c *tstDeviceSession, authn *corev1.Authenticator) {
	t.Helper()

	resp, err := c.srv.doRegisterAuthenticatorBegin(c.ctx(), &authv1.RegisterAuthenticatorBeginRequest{
		AuthenticatorRef: umetav1.GetObjectReference(authn),
		PreChallenge:     d.pre,
	})
	assert.Nil(t, err, "%+v", err)

	secret, err := d.ak.ActivateCredential(d.tpm, attest.EncryptedCredential{
		Credential: resp.ChallengeRequest.GetTpm().EncryptedCredential.Credential,
		Secret:     resp.ChallengeRequest.GetTpm().EncryptedCredential.Secret,
	})
	assert.Nil(t, err, "%+v", err)

	_, err = c.srv.doRegisterAuthenticatorFinish(c.ctx(), &authv1.RegisterAuthenticatorFinishRequest{
		AuthenticatorRef:  umetav1.GetObjectReference(authn),
		ChallengeResponse: tpmChallengeResponse(secret),
	})
	assert.Nil(t, err, "%+v", err)
}

func (d *tstVirtualTPM) beginAuthentication(t *testing.T, c *tstDeviceSession,
	authn *corev1.Authenticator) ([]byte, error) {
	t.Helper()

	resp, err := c.srv.doAuthenticateAuthenticatorBegin(c.ctx(), &authv1.AuthenticateAuthenticatorBeginRequest{
		AuthenticatorRef: umetav1.GetObjectReference(authn),
	})
	if err != nil {
		return nil, err
	}

	secret, err := d.ak.ActivateCredential(d.tpm, attest.EncryptedCredential{
		Credential: resp.ChallengeRequest.GetTpm().EncryptedCredential.Credential,
		Secret:     resp.ChallengeRequest.GetTpm().EncryptedCredential.Secret,
	})
	assert.Nil(t, err, "%+v", err)

	return secret, nil
}

func (d *tstVirtualTPM) authenticate(t *testing.T, c *tstDeviceSession, authn *corev1.Authenticator) error {
	t.Helper()

	secret, err := d.beginAuthentication(t, c, authn)
	if err != nil {
		return err
	}

	tkn, err := c.srv.doAuthenticateWithAuthenticator(c.ctx(), &authv1.AuthenticateWithAuthenticatorRequest{
		AuthenticatorRef:  umetav1.GetObjectReference(authn),
		ChallengeResponse: tpmChallengeResponse(secret),
	})
	if err != nil {
		return err
	}

	c.tkn = tkn

	return nil
}

func TestDeviceAuthenticatorProof(t *testing.T) {

	ctx := context.Background()

	srv, _, adminSrv := newWebAuthnTestEnv(t)
	vTPM := newTstVirtualTPM(t)

	usrT := newTstHumanClient(t, srv, adminSrv)
	info := newTstDeviceInfo()

	first := newTstDeviceSession(t, srv, usrT, nil)
	first.registerDevice(t, info)

	deviceRef := first.session(t).Status.DeviceRef
	assert.NotNil(t, deviceRef)

	authnT, err := srv.doCreateAuthenticator(first.ctx(), &authv1.CreateAuthenticatorRequest{
		Type: authv1.Authenticator_Status_TPM,
	})
	assert.Nil(t, err, "%+v", err)

	authn, err := srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
		Uid: authnT.Metadata.Uid,
	})
	assert.Nil(t, err, "%+v", err)

	vTPM.register(t, first, authn)

	authn = srv.mustGetAuthenticator(t, authn)
	assert.True(t, authn.Status.IsRegistered)
	assert.Equal(t, deviceRef.Uid, authn.Status.DeviceRef.GetUid(),
		"a TPM Authenticator must be bound to the Device of its registration")

	assertWithheld := func(t *testing.T, c *tstDeviceSession) {
		t.Helper()

		sess := c.session(t)
		assert.Nil(t, sess.Status.DeviceRef, "the Device must be withheld until it is proven")
		assert.Equal(t, authn.Metadata.Uid, sess.Status.RequiredAuthenticatorRef.GetUid())
	}

	t.Run("RegisterDeviceWithholdsDevice", func(t *testing.T) {
		c := newTstDeviceSession(t, srv, usrT, nil)
		c.registerDevice(t, info)
		assertWithheld(t, c)

		res, err := srv.doGetAvailableAuthenticator(c.ctx(), &authv1.GetAvailableAuthenticatorRequest{})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, authn.Metadata.Uid, res.MainAuthenticator.GetMetadata().GetUid())
		assert.Equal(t, 1, len(res.AvailableAuthenticators))

		probe, err := srv.doRunDeviceProbeBegin(c.ctx(), &authv1.RunDeviceProbeBeginRequest{})
		assert.Nil(t, err, "%+v", err)
		assert.Empty(t, probe.AttemptUID, "a Session must not feed the probes of an unproven Device")

		_, err = srv.doAuthenticateWithRefreshToken(c.ctx(), &authv1.AuthenticateWithRefreshTokenRequest{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("RepeatedRegisterDevice", func(t *testing.T) {
		c := newTstDeviceSession(t, srv, usrT, nil)
		c.registerDevice(t, info)
		c.registerDevice(t, info)
		assertWithheld(t, c)
	})

	t.Run("SerialNumberMatch", func(t *testing.T) {
		claim := newTstDeviceInfo()
		claim.SerialNumber = info.SerialNumber

		c := newTstDeviceSession(t, srv, usrT, nil)
		c.registerDevice(t, claim)
		assertWithheld(t, c)
	})

	t.Run("RegisterDeviceBegin", func(t *testing.T) {
		c := newTstDeviceSession(t, srv, usrT, nil)

		_, err := srv.doRegisterDeviceBegin(c.ctx(), &authv1.RegisterDeviceBeginRequest{Info: info})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err), "%+v", err)
		assertWithheld(t, c)
	})

	t.Run("WrongProof", func(t *testing.T) {
		c := newTstDeviceSession(t, srv, usrT, nil)
		c.registerDevice(t, info)

		_, err := vTPM.beginAuthentication(t, c, authn)
		assert.Nil(t, err, "%+v", err)

		_, err = srv.doAuthenticateWithAuthenticator(c.ctx(), &authv1.AuthenticateWithAuthenticatorRequest{
			AuthenticatorRef:  umetav1.GetObjectReference(authn),
			ChallengeResponse: tpmChallengeResponse(utilrand.GetRandomBytesMust(32)),
		})
		assert.NotNil(t, err)
		assertWithheld(t, c)
		assert.Nil(t, c.session(t).Status.DeviceProof)
	})

	t.Run("OtherAuthenticatorIsNoProof", func(t *testing.T) {
		totpAuthn := createTstDeviceAuthenticator(t, srv, usrT, corev1.Authenticator_Status_TOTP, nil, nil)

		c := newTstDeviceSession(t, srv, usrT, nil)
		c.registerDevice(t, info)

		_, err := srv.doAuthenticateAuthenticatorBegin(c.ctx(), &authv1.AuthenticateAuthenticatorBeginRequest{
			AuthenticatorRef: umetav1.GetObjectReference(totpAuthn),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
		assertWithheld(t, c)
	})

	t.Run("ProofAttachesDevice", func(t *testing.T) {
		c := newTstDeviceSession(t, srv, usrT, nil)
		c.registerDevice(t, info)
		assertWithheld(t, c)

		assert.Nil(t, vTPM.authenticate(t, c, authn))

		sess := c.session(t)
		assert.Equal(t, deviceRef.Uid, sess.Status.DeviceRef.GetUid())
		assert.Equal(t, authn.Metadata.Uid, sess.Status.RequiredAuthenticatorRef.GetUid())
		assert.Equal(t, corev1.Session_Status_DeviceProof_HARDWARE_KEY, sess.Status.DeviceProof.GetType())
		assert.True(t, sess.Status.DeviceProof.GetProvedAt().IsValid())
		assert.Empty(t, sess.Status.DeviceProof.GetBindingUID(), "a hardware key proves the Device and not a Binding")

		_, err := srv.doRegisterDevice(c.ctx(), &authv1.RegisterDeviceRequest{Info: info})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err), "%+v", err)
	})

	t.Run("SessionOnAnotherDevice", func(t *testing.T) {
		c := newTstDeviceSession(t, srv, usrT, nil)
		c.registerDevice(t, newTstDeviceInfo())

		otherRef := c.session(t).Status.DeviceRef
		assert.NotNil(t, otherRef)
		assert.NotEqual(t, deviceRef.Uid, otherRef.Uid)

		_, err := vTPM.beginAuthentication(t, c, authn)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)

		assert.Equal(t, otherRef.Uid, c.session(t).Status.DeviceRef.GetUid())
	})

	t.Run("DeviceChangedDuringProof", func(t *testing.T) {
		c := newTstDeviceSession(t, srv, usrT, nil)
		c.registerDevice(t, info)

		secret, err := vTPM.beginAuthentication(t, c, authn)
		assert.Nil(t, err, "%+v", err)

		sess := c.session(t)
		sess.Status.DeviceRef = &metav1.ObjectReference{Uid: utilrand.GetRandomStringCanonical(8)}
		_, err = srv.octeliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err, "%+v", err)

		_, err = srv.doAuthenticateWithAuthenticator(c.ctx(), &authv1.AuthenticateWithAuthenticatorRequest{
			AuthenticatorRef:  umetav1.GetObjectReference(authn),
			ChallengeResponse: tpmChallengeResponse(secret),
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
	})

	t.Run("AuthenticationNeverBindsTPM", func(t *testing.T) {
		cur := srv.mustGetAuthenticator(t, authn)
		cur.Status.DeviceRef = nil
		_, err := srv.octeliumC.CoreC().UpdateAuthenticator(ctx, cur)
		assert.Nil(t, err, "%+v", err)

		t.Cleanup(func() {
			cur := srv.mustGetAuthenticator(t, authn)
			cur.Status.DeviceRef = deviceRef
			_, err := srv.octeliumC.CoreC().UpdateAuthenticator(ctx, cur)
			assert.Nil(t, err, "%+v", err)
		})

		c := newTstDeviceSession(t, srv, usrT, nil)
		c.registerDevice(t, newTstDeviceInfo())
		assert.NotNil(t, c.session(t).Status.DeviceRef)

		assert.Nil(t, vTPM.authenticate(t, c, authn))
		assert.Nil(t, srv.mustGetAuthenticator(t, authn).Status.DeviceRef,
			"only the registration binds an Authenticator to a Device")
		assert.Nil(t, c.session(t).Status.DeviceProof,
			"an Authenticator that is not bound to the Device must not prove it")
	})

	t.Run("OwnerOfAnotherDeviceClaim", func(t *testing.T) {
		otherT := newTstHumanClient(t, srv, adminSrv)

		c := newTstDeviceSession(t, srv, otherT, nil)

		_, err := srv.doRegisterDevice(c.ctx(), &authv1.RegisterDeviceRequest{Info: info})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)

		sess := c.session(t)
		assert.Nil(t, sess.Status.DeviceRef)
		assert.Nil(t, sess.Status.RequiredAuthenticatorRef)
	})
}

func TestAttachSessionDevice(t *testing.T) {

	srv, _, adminSrv := newWebAuthnTestEnv(t)

	otherDeviceRef := &metav1.ObjectReference{Uid: utilrand.GetRandomStringCanonical(8)}

	tbl := []struct {
		name     string
		typ      corev1.Authenticator_Status_Type
		other    bool
		fn       func(*corev1.Authenticator)
		withheld bool
	}{
		{
			name:     "ActiveTPM",
			typ:      corev1.Authenticator_Status_TPM,
			withheld: true,
		},
		{
			name: "PendingTPM",
			typ:  corev1.Authenticator_Status_TPM,
			fn: func(authn *corev1.Authenticator) {
				authn.Spec.State = corev1.Authenticator_Spec_PENDING
			},
		},
		{
			name: "RejectedTPM",
			typ:  corev1.Authenticator_Status_TPM,
			fn: func(authn *corev1.Authenticator) {
				authn.Spec.State = corev1.Authenticator_Spec_REJECTED
			},
		},
		{
			name: "UnregisteredTPM",
			typ:  corev1.Authenticator_Status_TPM,
			fn: func(authn *corev1.Authenticator) {
				authn.Status.IsRegistered = false
			},
		},
		{
			name:  "TPMOfAnotherDevice",
			typ:   corev1.Authenticator_Status_TPM,
			other: true,
		},
		{
			name: "LegacyTOTP",
			typ:  corev1.Authenticator_Status_TOTP,
		},
		{
			name: "LegacyFIDO",
			typ:  corev1.Authenticator_Status_FIDO,
		},
	}

	for _, itm := range tbl {
		t.Run(itm.name, func(t *testing.T) {
			usrT := newTstHumanClient(t, srv, adminSrv)
			info := newTstDeviceInfo()

			first := newTstDeviceSession(t, srv, usrT, nil)
			first.registerDevice(t, info)

			deviceRef := first.session(t).Status.DeviceRef
			if itm.other {
				deviceRef = otherDeviceRef
			}

			authn := createTstDeviceAuthenticator(t, srv, usrT, itm.typ, deviceRef, itm.fn)

			c := newTstDeviceSession(t, srv, usrT, nil)
			c.registerDevice(t, info)

			sess := c.session(t)
			if itm.withheld {
				assert.Nil(t, sess.Status.DeviceRef)
				assert.Equal(t, authn.Metadata.Uid, sess.Status.RequiredAuthenticatorRef.GetUid())
			} else {
				assert.Equal(t, first.session(t).Status.DeviceRef.GetUid(), sess.Status.DeviceRef.GetUid())
				assert.Nil(t, sess.Status.RequiredAuthenticatorRef)
			}
		})
	}

	t.Run("RequiredAuthenticatorIsNotReplaced", func(t *testing.T) {
		usrT := newTstHumanClient(t, srv, adminSrv)
		info := newTstDeviceInfo()

		first := newTstDeviceSession(t, srv, usrT, nil)
		first.registerDevice(t, info)

		createTstDeviceAuthenticator(t, srv, usrT, corev1.Authenticator_Status_TPM,
			first.session(t).Status.DeviceRef, nil)

		required := createTstDeviceAuthenticator(t, srv, usrT, corev1.Authenticator_Status_TPM, nil, nil)

		c := newTstDeviceSession(t, srv, usrT, &sessionc.CreateSessionOpts{
			SessType:                 corev1.Session_Status_CLIENT,
			RequiredAuthenticatorRef: umetav1.GetObjectReference(required),
		})
		c.registerDevice(t, info)

		sess := c.session(t)
		assert.Nil(t, sess.Status.DeviceRef)
		assert.Equal(t, required.Metadata.Uid, sess.Status.RequiredAuthenticatorRef.GetUid())
	})

	t.Run("NewDevice", func(t *testing.T) {
		usrT := newTstHumanClient(t, srv, adminSrv)

		c := newTstDeviceSession(t, srv, usrT, nil)
		c.registerDevice(t, newTstDeviceInfo())

		sess := c.session(t)
		assert.NotNil(t, sess.Status.DeviceRef)
		assert.Nil(t, sess.Status.RequiredAuthenticatorRef)
	})
}

func TestDeleteDeviceAuthenticator(t *testing.T) {

	ctx := context.Background()

	srv, _, adminSrv := newWebAuthnTestEnv(t)

	del := func(c *tstDeviceSession, authn *corev1.Authenticator) error {
		_, err := srv.doDeleteAuthenticator(c.ctx(), &metav1.DeleteOptions{
			Uid: authn.Metadata.Uid,
		})
		return err
	}

	assertExists := func(t *testing.T, authn *corev1.Authenticator, exists bool) {
		t.Helper()

		_, err := srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
			Uid: authn.Metadata.Uid,
		})
		if exists {
			assert.Nil(t, err, "%+v", err)
		} else {
			assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
		}
	}

	type env struct {
		usrT      *tstuser.User
		info      *authv1.RegisterDeviceRequest_Info
		deviceRef *metav1.ObjectReference
		authn     *corev1.Authenticator
	}

	newEnv := func(t *testing.T) *env {
		t.Helper()

		usrT := newTstHumanClient(t, srv, adminSrv)
		info := newTstDeviceInfo()

		first := newTstDeviceSession(t, srv, usrT, nil)
		first.registerDevice(t, info)

		deviceRef := first.session(t).Status.DeviceRef

		return &env{
			usrT:      usrT,
			info:      info,
			deviceRef: deviceRef,
			authn: createTstDeviceAuthenticator(t, srv, usrT,
				corev1.Authenticator_Status_TPM, deviceRef, nil),
		}
	}

	t.Run("WithheldSession", func(t *testing.T) {
		e := newEnv(t)

		c := newTstDeviceSession(t, srv, e.usrT, nil)
		c.registerDevice(t, e.info)

		err := del(c, e.authn)
		assert.NotNil(t, err, "deleting the proof must not reopen the Device")
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
		assertExists(t, e.authn, true)

		c2 := newTstDeviceSession(t, srv, e.usrT, nil)
		c2.registerDevice(t, e.info)
		assert.Nil(t, c2.session(t).Status.DeviceRef)
	})

	t.Run("SessionWithoutDevice", func(t *testing.T) {
		e := newEnv(t)

		err := del(newTstDeviceSession(t, srv, e.usrT, nil), e.authn)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
		assertExists(t, e.authn, true)
	})

	t.Run("BrowserSession", func(t *testing.T) {
		e := newEnv(t)

		c := newTstDeviceSession(t, srv, e.usrT, &sessionc.CreateSessionOpts{
			SessType:  corev1.Session_Status_CLIENTLESS,
			IsBrowser: true,
		})

		err := del(c, e.authn)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
		assertExists(t, e.authn, true)
	})

	t.Run("SessionOnAnotherDevice", func(t *testing.T) {
		e := newEnv(t)

		c := newTstDeviceSession(t, srv, e.usrT, nil)
		c.registerDevice(t, newTstDeviceInfo())

		err := del(c, e.authn)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsPermissionDenied(err), "%+v", err)
		assertExists(t, e.authn, true)
	})

	t.Run("SessionOnTheDevice", func(t *testing.T) {
		e := newEnv(t)

		dev, err := srv.octeliumC.CoreC().GetDevice(ctx, &rmetav1.GetOptions{Uid: e.deviceRef.Uid})
		assert.Nil(t, err, "%+v", err)

		c := newTstDeviceSession(t, srv, e.usrT, &sessionc.CreateSessionOpts{
			SessType: corev1.Session_Status_CLIENT,
			Device:   dev,
		})

		assert.Nil(t, del(c, e.authn))
		assertExists(t, e.authn, false)

		c2 := newTstDeviceSession(t, srv, e.usrT, nil)
		c2.registerDevice(t, e.info)
		assert.Equal(t, e.deviceRef.Uid, c2.session(t).Status.DeviceRef.GetUid())
	})

	t.Run("AdminRecovery", func(t *testing.T) {
		e := newEnv(t)

		authn := srv.mustGetAuthenticator(t, e.authn)
		authn.Spec.State = corev1.Authenticator_Spec_REJECTED

		authn, err := srv.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
		assert.Nil(t, err, "%+v", err)

		c := newTstDeviceSession(t, srv, e.usrT, nil)
		c.registerDevice(t, e.info)
		assert.Equal(t, e.deviceRef.Uid, c.session(t).Status.DeviceRef.GetUid())

		assert.Nil(t, del(newTstDeviceSession(t, srv, e.usrT, nil), authn))
		assertExists(t, authn, false)
	})

	t.Run("NotDeviceBound", func(t *testing.T) {
		e := newEnv(t)

		for _, authn := range []*corev1.Authenticator{
			createTstDeviceAuthenticator(t, srv, e.usrT, corev1.Authenticator_Status_TPM, nil, nil),
			createTstDeviceAuthenticator(t, srv, e.usrT, corev1.Authenticator_Status_TOTP, e.deviceRef, nil),
			createTstDeviceAuthenticator(t, srv, e.usrT, corev1.Authenticator_Status_FIDO, e.deviceRef, nil),
		} {
			assert.Nil(t, del(newTstDeviceSession(t, srv, e.usrT, nil), authn))
			assertExists(t, authn, false)
		}
	})
}

func registerTstTOTP(t *testing.T, c *tstDeviceSession, authn *corev1.Authenticator) string {
	t.Helper()

	resp, err := c.srv.doRegisterAuthenticatorBegin(c.ctx(), &authv1.RegisterAuthenticatorBeginRequest{
		AuthenticatorRef: umetav1.GetObjectReference(authn),
	})
	assert.Nil(t, err, "%+v", err)

	k, err := otp.NewKeyFromURL(resp.ChallengeRequest.GetTotp().Url)
	assert.Nil(t, err, "%+v", err)

	code, err := totp.GenerateCode(k.Secret(), time.Now())
	assert.Nil(t, err, "%+v", err)

	_, err = c.srv.doRegisterAuthenticatorFinish(c.ctx(), &authv1.RegisterAuthenticatorFinishRequest{
		AuthenticatorRef: umetav1.GetObjectReference(authn),
		ChallengeResponse: &authv1.ChallengeResponse{
			Type: &authv1.ChallengeResponse_Totp{
				Totp: &authv1.ChallengeResponse_TOTP{
					Response: code,
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	return k.Secret()
}

func authenticateTstTOTP(t *testing.T, c *tstDeviceSession, authn *corev1.Authenticator, secret string) error {
	t.Helper()

	if _, err := c.srv.doAuthenticateAuthenticatorBegin(c.ctx(), &authv1.AuthenticateAuthenticatorBeginRequest{
		AuthenticatorRef: umetav1.GetObjectReference(authn),
	}); err != nil {
		return err
	}

	code, err := totp.GenerateCode(secret, time.Now().Add(30*time.Second))
	assert.Nil(t, err, "%+v", err)

	tkn, err := c.srv.doAuthenticateWithAuthenticator(c.ctx(), &authv1.AuthenticateWithAuthenticatorRequest{
		AuthenticatorRef: umetav1.GetObjectReference(authn),
		ChallengeResponse: &authv1.ChallengeResponse{
			Type: &authv1.ChallengeResponse_Totp{
				Totp: &authv1.ChallengeResponse_TOTP{
					Response: code,
				},
			},
		},
	})
	if err != nil {
		return err
	}

	c.tkn = tkn

	return nil
}

func TestTOTPNotDeviceBound(t *testing.T) {

	ctx := context.Background()

	srv, _, adminSrv := newWebAuthnTestEnv(t)

	createTOTP := func(t *testing.T, c *tstDeviceSession) *corev1.Authenticator {
		t.Helper()

		authn, err := srv.doCreateAuthenticator(c.ctx(), &authv1.CreateAuthenticatorRequest{
			Type: authv1.Authenticator_Status_TOTP,
		})
		assert.Nil(t, err, "%+v", err)

		ret, err := srv.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
			Uid: authn.Metadata.Uid,
		})
		assert.Nil(t, err, "%+v", err)

		return ret
	}

	t.Run("RegistrationOnADevice", func(t *testing.T) {
		usrT := newTstHumanClient(t, srv, adminSrv)

		c := newTstDeviceSession(t, srv, usrT, nil)
		c.registerDevice(t, newTstDeviceInfo())
		assert.NotNil(t, c.session(t).Status.DeviceRef)

		authn := createTOTP(t, c)
		registerTstTOTP(t, c, authn)

		authn = srv.mustGetAuthenticator(t, authn)
		assert.True(t, authn.Status.IsRegistered)
		assert.Nil(t, authn.Status.DeviceRef)
	})

	t.Run("AuthenticationNeverWritesDevice", func(t *testing.T) {
		usrT := newTstHumanClient(t, srv, adminSrv)

		c := newTstDeviceSession(t, srv, usrT, nil)
		authn := createTOTP(t, c)
		secret := registerTstTOTP(t, c, authn)

		c.registerDevice(t, newTstDeviceInfo())
		deviceRef := c.session(t).Status.DeviceRef
		assert.NotNil(t, deviceRef)

		assert.Nil(t, authenticateTstTOTP(t, c, authn, secret))

		assert.Nil(t, srv.mustGetAuthenticator(t, authn).Status.DeviceRef)
		assert.Equal(t, deviceRef.Uid, c.session(t).Status.DeviceRef.GetUid())
	})

	t.Run("OneTOTPOnTwoDevices", func(t *testing.T) {
		usrT := newTstHumanClient(t, srv, adminSrv)

		first := newTstDeviceSession(t, srv, usrT, nil)
		first.registerDevice(t, newTstDeviceInfo())
		firstRef := first.session(t).Status.DeviceRef

		authn := createTOTP(t, first)
		secret := registerTstTOTP(t, first, authn)

		legacy := srv.mustGetAuthenticator(t, authn)
		legacy.Status.DeviceRef = firstRef
		_, err := srv.octeliumC.CoreC().UpdateAuthenticator(ctx, legacy)
		assert.Nil(t, err, "%+v", err)

		second := newTstDeviceSession(t, srv, usrT, nil)
		second.registerDevice(t, newTstDeviceInfo())
		secondRef := second.session(t).Status.DeviceRef
		assert.NotEqual(t, firstRef.Uid, secondRef.Uid)

		assert.Nil(t, authenticateTstTOTP(t, second, authn, secret),
			"a TOTP Authenticator is not tied to the Device where it was first used")

		assert.Equal(t, secondRef.Uid, second.session(t).Status.DeviceRef.GetUid())
		assert.Equal(t, firstRef.Uid, srv.mustGetAuthenticator(t, authn).Status.DeviceRef.GetUid())
	})

	t.Run("BrowserSessionGetsNoDevice", func(t *testing.T) {
		usrT := newTstHumanClient(t, srv, adminSrv)

		first := newTstDeviceSession(t, srv, usrT, nil)
		first.registerDevice(t, newTstDeviceInfo())

		authn := createTOTP(t, first)
		secret := registerTstTOTP(t, first, authn)

		legacy := srv.mustGetAuthenticator(t, authn)
		legacy.Status.DeviceRef = first.session(t).Status.DeviceRef
		_, err := srv.octeliumC.CoreC().UpdateAuthenticator(ctx, legacy)
		assert.Nil(t, err, "%+v", err)

		c := newTstDeviceSession(t, srv, usrT, &sessionc.CreateSessionOpts{
			SessType:  corev1.Session_Status_CLIENTLESS,
			IsBrowser: true,
		})

		assert.Nil(t, authenticateTstTOTP(t, c, authn, secret))
		assert.Nil(t, c.session(t).Status.DeviceRef,
			"a TOTP code entered on any machine says nothing about the Device")
	})
}
