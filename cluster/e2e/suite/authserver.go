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

package suite

import (
	"context"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func authenticatorRef(authn *authv1.Authenticator) *metav1.ObjectReference {
	return &metav1.ObjectReference{Uid: authn.Metadata.Uid}
}

func totpResponse(code string) *authv1.ChallengeResponse {
	return &authv1.ChallengeResponse{
		Type: &authv1.ChallengeResponse_Totp{
			Totp: &authv1.ChallengeResponse_TOTP{Response: code},
		},
	}
}

func wrongTOTPCode(code string) string {
	digits := []byte(code)
	for i, d := range digits {
		if d == '0' {
			digits[i] = '1'
		} else {
			digits[i] = '0'
		}
	}
	return string(digits)
}

func createTOTPAuthenticator(t *testing.T,
	sess *harness.AuthSession, displayName string) *authv1.Authenticator {
	t.Helper()

	authn, err := sess.C().CreateAuthenticator(sess.Ctx(t.Context()),
		&authv1.CreateAuthenticatorRequest{
			Type:        authv1.Authenticator_Status_TOTP,
			DisplayName: displayName,
		})
	require.Nil(t, err, "could not create a TOTP Authenticator")
	require.NotNil(t, authn.Metadata)
	require.NotEmpty(t, authn.Metadata.Uid)
	require.False(t, authn.Status.IsRegistered,
		"a newly created Authenticator must not be registered")

	return authn
}

func beginTOTPRegistration(t *testing.T,
	sess *harness.AuthSession, authn *authv1.Authenticator) string {
	t.Helper()

	begin, err := sess.C().RegisterAuthenticatorBegin(sess.Ctx(t.Context()),
		&authv1.RegisterAuthenticatorBeginRequest{
			AuthenticatorRef: authenticatorRef(authn),
		})
	require.Nil(t, err, "could not begin the TOTP registration")
	require.NotNil(t, begin.ChallengeRequest)
	require.NotNil(t, begin.ChallengeRequest.GetTotp(),
		"a TOTP Authenticator must be challenged with TOTP")

	return harness.TOTPSecret(t, begin.ChallengeRequest.GetTotp().Url)
}

func registerTOTPAuthenticator(t *testing.T,
	sess *harness.AuthSession, displayName string) (*authv1.Authenticator, string) {
	t.Helper()

	authn := createTOTPAuthenticator(t, sess, displayName)
	secret := beginTOTPRegistration(t, sess, authn)

	_, err := sess.C().RegisterAuthenticatorFinish(sess.Ctx(t.Context()),
		&authv1.RegisterAuthenticatorFinishRequest{
			AuthenticatorRef: authenticatorRef(authn),
			ChallengeResponse: totpResponse(
				harness.TOTPCode(t, secret, harness.TOTPStep(time.Now()))),
		})
	require.Nil(t, err, "could not finish the TOTP registration")

	return authn, secret
}

func newHumanSession(t *testing.T, h *harness.H) *harness.AuthSession {
	t.Helper()

	return h.NewAuthSession(t, harness.AuthSessionOpts{
		UserType:    corev1.User_Spec_HUMAN,
		SessionType: corev1.Session_Status_CLIENT,
	})
}

func testAuthenticatorRegistration(t *testing.T, h *harness.H) {
	t.Run("TOTP", func(t *testing.T) {
		sess := newHumanSession(t, h)

		authn, _ := registerTOTPAuthenticator(t, sess, "e2e totp")

		got, err := sess.C().GetAuthenticator(sess.Ctx(t.Context()),
			&metav1.GetOptions{Uid: authn.Metadata.Uid})
		require.Nil(t, err)
		assert.True(t, got.Status.IsRegistered,
			"the Authenticator must be registered after a successful challenge")
		assert.Equal(t, authv1.Authenticator_Status_TOTP, got.Status.Type)
		assert.Equal(t, "e2e totp", got.Spec.DisplayName)

		itmList, err := sess.C().ListAuthenticator(sess.Ctx(t.Context()),
			&authv1.ListAuthenticatorOptions{})
		require.Nil(t, err)
		assert.True(t, slices.ContainsFunc(itmList.Items,
			func(itm *authv1.Authenticator) bool {
				return itm.Metadata.Uid == authn.Metadata.Uid
			}), "the registered Authenticator is missing from the User's Authenticators")

		available, err := sess.C().GetAvailableAuthenticator(sess.Ctx(t.Context()),
			&authv1.GetAvailableAuthenticatorRequest{})
		require.Nil(t, err)
		assert.True(t, slices.ContainsFunc(available.AvailableAuthenticators,
			func(itm *authv1.Authenticator) bool {
				return itm.Metadata.Uid == authn.Metadata.Uid
			}), "the registered Authenticator is not available to its own Session")
	})

	t.Run("InvalidCodeRejected", func(t *testing.T) {
		sess := newHumanSession(t, h)

		authn := createTOTPAuthenticator(t, sess, "e2e invalid")
		secret := beginTOTPRegistration(t, sess, authn)

		_, err := sess.C().RegisterAuthenticatorFinish(sess.Ctx(t.Context()),
			&authv1.RegisterAuthenticatorFinishRequest{
				AuthenticatorRef: authenticatorRef(authn),
				ChallengeResponse: totpResponse(wrongTOTPCode(
					harness.TOTPCode(t, secret, harness.TOTPStep(time.Now())))),
			})
		require.NotNil(t, err, "an invalid TOTP code must not register the Authenticator")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"an invalid TOTP code returned an unexpected error: %+v", err)

		got, err := sess.C().GetAuthenticator(sess.Ctx(t.Context()),
			&metav1.GetOptions{Uid: authn.Metadata.Uid})
		require.Nil(t, err)
		assert.False(t, got.Status.IsRegistered,
			"a failed challenge must leave the Authenticator unregistered")
	})

	t.Run("DoubleRegistrationRejected", func(t *testing.T) {
		sess := newHumanSession(t, h)

		authn, _ := registerTOTPAuthenticator(t, sess, "e2e double")

		_, err := sess.C().RegisterAuthenticatorBegin(sess.Ctx(t.Context()),
			&authv1.RegisterAuthenticatorBeginRequest{
				AuthenticatorRef: authenticatorRef(authn),
			})
		require.NotNil(t, err, "an already registered Authenticator must not be re-registered")
		assert.True(t, grpcerr.IsInvalidArg(err),
			"re-registering an Authenticator returned an unexpected error: %+v", err)
	})

	t.Run("WorkloadUserRejected", func(t *testing.T) {
		sess := h.NewAuthSession(t, harness.AuthSessionOpts{
			UserType:    corev1.User_Spec_WORKLOAD,
			SessionType: corev1.Session_Status_CLIENT,
		})

		_, err := sess.C().CreateAuthenticator(sess.Ctx(t.Context()),
			&authv1.CreateAuthenticatorRequest{
				Type: authv1.Authenticator_Status_TOTP,
			})
		require.NotNil(t, err, "TOTP Authenticators require a HUMAN User")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"creating a TOTP Authenticator for a WORKLOAD User returned an unexpected error: %+v",
			err)
	})

	t.Run("FIDORequiresBrowser", func(t *testing.T) {
		sess := newHumanSession(t, h)

		_, err := sess.C().CreateAuthenticator(sess.Ctx(t.Context()),
			&authv1.CreateAuthenticatorRequest{
				Type: authv1.Authenticator_Status_FIDO,
			})
		require.NotNil(t, err, "FIDO Authenticators require a browser Session")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"creating a FIDO Authenticator outside a browser returned an unexpected error: %+v",
			err)
	})
}

func testAuthenticatorAuthentication(t *testing.T, h *harness.H) {
	sess := newHumanSession(t, h)

	authn, secret := registerTOTPAuthenticator(t, sess, "e2e login")

	before := sess.Session(t)
	require.NotNil(t, before.Status)

	authenticate := func(t *testing.T, code string) (*authv1.SessionToken, error) {
		t.Helper()

		begin, err := sess.C().AuthenticateAuthenticatorBegin(sess.Ctx(t.Context()),
			&authv1.AuthenticateAuthenticatorBeginRequest{
				AuthenticatorRef: authenticatorRef(authn),
			})
		require.Nil(t, err, "could not begin the TOTP authentication")
		require.NotNil(t, begin.ChallengeRequest)
		require.NotNil(t, begin.ChallengeRequest.GetTotp())

		return sess.C().AuthenticateWithAuthenticator(sess.Ctx(t.Context()),
			&authv1.AuthenticateWithAuthenticatorRequest{
				AuthenticatorRef:  authenticatorRef(authn),
				ChallengeResponse: totpResponse(code),
			})
	}

	code := harness.TOTPCode(t, secret, harness.TOTPStep(time.Now())+1)

	tkn, err := authenticate(t, code)
	require.Nil(t, err, "could not authenticate with the registered TOTP Authenticator")
	require.NotEmpty(t, tkn.AccessToken)
	require.NotEmpty(t, tkn.RefreshToken)
	sess.SetToken(tkn)

	after := sess.Session(t)
	require.NotNil(t, after.Status.Authentication)

	info := after.Status.Authentication.Info
	require.NotNil(t, info)
	assert.Equal(t, corev1.Session_Status_Authentication_Info_AUTHENTICATOR, info.Type)
	require.NotNil(t, info.GetAuthenticator())
	require.NotNil(t, info.GetAuthenticator().AuthenticatorRef)
	assert.Equal(t, authn.Metadata.Uid, info.GetAuthenticator().AuthenticatorRef.Uid)
	assert.Equal(t, corev1.Authenticator_Status_TOTP, info.GetAuthenticator().Type)
	assert.Equal(t, before.Status.TotalAuthentications+1, after.Status.TotalAuthentications)

	t.Run("ReplayRejected", func(t *testing.T) {
		_, err := authenticate(t, code)
		require.NotNil(t, err, "a TOTP code must not be accepted a second time")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"a replayed TOTP code returned an unexpected error: %+v", err)
	})

	t.Run("InvalidCodeRejected", func(t *testing.T) {
		_, err := authenticate(t, wrongTOTPCode(code))
		require.NotNil(t, err, "an invalid TOTP code must not authenticate")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"an invalid TOTP code returned an unexpected error: %+v", err)
	})

	t.Run("WithoutBeginRejected", func(t *testing.T) {
		_, err := sess.C().AuthenticateWithAuthenticator(sess.Ctx(t.Context()),
			&authv1.AuthenticateWithAuthenticatorRequest{
				AuthenticatorRef: authenticatorRef(authn),
				ChallengeResponse: totpResponse(
					harness.TOTPCode(t, secret, harness.TOTPStep(time.Now())+2)),
			})
		require.NotNil(t, err,
			"an Authenticator response without a pending challenge must be rejected")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"an unsolicited Authenticator response returned an unexpected error: %+v", err)
	})
}

func testAuthenticatorAccess(t *testing.T, h *harness.H) {
	sess := newHumanSession(t, h)
	authn, _ := registerTOTPAuthenticator(t, sess, "e2e owned")

	t.Run("UnauthenticatedRejected", func(t *testing.T) {
		c := sess.C()
		ctx := t.Context()

		for name, fn := range map[string]func() error{
			"CreateAuthenticator": func() error {
				_, err := c.CreateAuthenticator(ctx, &authv1.CreateAuthenticatorRequest{
					Type: authv1.Authenticator_Status_TOTP,
				})
				return err
			},
			"ListAuthenticator": func() error {
				_, err := c.ListAuthenticator(ctx, &authv1.ListAuthenticatorOptions{})
				return err
			},
			"GetAuthenticator": func() error {
				_, err := c.GetAuthenticator(ctx,
					&metav1.GetOptions{Uid: authn.Metadata.Uid})
				return err
			},
			"DeleteAuthenticator": func() error {
				_, err := c.DeleteAuthenticator(ctx,
					&metav1.DeleteOptions{Uid: authn.Metadata.Uid})
				return err
			},
			"RegisterAuthenticatorBegin": func() error {
				_, err := c.RegisterAuthenticatorBegin(ctx,
					&authv1.RegisterAuthenticatorBeginRequest{
						AuthenticatorRef: authenticatorRef(authn),
					})
				return err
			},
			"GetAvailableAuthenticator": func() error {
				_, err := c.GetAvailableAuthenticator(ctx,
					&authv1.GetAvailableAuthenticatorRequest{})
				return err
			},
			"Logout": func() error {
				_, err := c.Logout(ctx, &authv1.LogoutRequest{})
				return err
			},
		} {
			err := fn()
			require.NotNil(t, err, "%s must require an authenticated Session", name)
			assert.True(t, grpcerr.IsUnauthenticated(err),
				"%s without a Session returned an unexpected error: %+v", name, err)
		}
	})

	t.Run("ForeignAuthenticatorRejected", func(t *testing.T) {
		other := newHumanSession(t, h)

		_, err := other.C().GetAuthenticator(other.Ctx(t.Context()),
			&metav1.GetOptions{Uid: authn.Metadata.Uid})
		require.NotNil(t, err, "an Authenticator must not be readable by another User")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"reading a foreign Authenticator returned an unexpected error: %+v", err)

		_, err = other.C().DeleteAuthenticator(other.Ctx(t.Context()),
			&metav1.DeleteOptions{Uid: authn.Metadata.Uid})
		require.NotNil(t, err, "an Authenticator must not be deletable by another User")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"deleting a foreign Authenticator returned an unexpected error: %+v", err)

		itmList, err := other.C().ListAuthenticator(other.Ctx(t.Context()),
			&authv1.ListAuthenticatorOptions{})
		require.Nil(t, err)
		assert.False(t, slices.ContainsFunc(itmList.Items,
			func(itm *authv1.Authenticator) bool {
				return itm.Metadata.Uid == authn.Metadata.Uid
			}), "a foreign Authenticator is listed for another User")
	})

	t.Run("UpdateAndDelete", func(t *testing.T) {
		updated, err := sess.C().UpdateAuthenticator(sess.Ctx(t.Context()), &authv1.Authenticator{
			Metadata: &metav1.Metadata{Name: authn.Metadata.Name},
			Spec:     &authv1.Authenticator_Spec{DisplayName: "e2e renamed"},
		})
		require.Nil(t, err)
		assert.Equal(t, "e2e renamed", updated.Spec.DisplayName)

		_, err = sess.C().DeleteAuthenticator(sess.Ctx(t.Context()),
			&metav1.DeleteOptions{Uid: authn.Metadata.Uid})
		require.Nil(t, err)

		_, err = sess.C().GetAuthenticator(sess.Ctx(t.Context()),
			&metav1.GetOptions{Uid: authn.Metadata.Uid})
		require.NotNil(t, err, "a deleted Authenticator must no longer be readable")
		assert.True(t, grpcerr.IsNotFound(err),
			"reading a deleted Authenticator returned an unexpected error: %+v", err)
	})
}

func testDeviceRegistration(t *testing.T, h *harness.H) {
	deviceInfo := func() *authv1.RegisterDeviceBeginRequest_Info {
		return &authv1.RegisterDeviceBeginRequest_Info{
			OsType:       authv1.RegisterDeviceBeginRequest_Info_LINUX,
			Hostname:     utilrand.GetRandomStringCanonical(8),
			Id:           utilrand.GetRandomStringHex(64),
			SerialNumber: utilrand.GetRandomStringCanonical(12),
			MacAddresses: []string{"02:42:ac:11:00:02"},
		}
	}

	t.Run("Register", func(t *testing.T) {
		sess := h.NewAuthSession(t, harness.AuthSessionOpts{
			SessionType: corev1.Session_Status_CLIENT,
		})

		require.Nil(t, sess.Session(t).Status.DeviceRef,
			"a fresh Session must not be bound to a Device")

		info := deviceInfo()

		begin, err := sess.C().RegisterDeviceBegin(sess.Ctx(t.Context()),
			&authv1.RegisterDeviceBeginRequest{Info: info})
		require.Nil(t, err, "could not begin the Device registration")
		require.NotEmpty(t, begin.Uid)

		_, err = sess.C().RegisterDeviceFinish(sess.Ctx(t.Context()),
			&authv1.RegisterDeviceFinishRequest{Uid: begin.Uid})
		require.Nil(t, err, "could not finish the Device registration")

		cur := sess.Session(t)
		require.NotNil(t, cur.Status.DeviceRef,
			"the Session must be bound to the registered Device")

		dev, err := h.CoreC().GetDevice(t.Context(),
			&metav1.GetOptions{Uid: cur.Status.DeviceRef.Uid})
		require.Nil(t, err)
		require.NotNil(t, dev.Status)
		assert.Equal(t, info.Id, dev.Status.Id)
		assert.Equal(t, info.Hostname, dev.Status.Hostname)
		assert.Equal(t, info.SerialNumber, dev.Status.SerialNumber)
		assert.Equal(t, corev1.Device_Status_LINUX, dev.Status.OsType)
		require.NotNil(t, dev.Status.UserRef)
		assert.Equal(t, sess.User.Metadata.Uid, dev.Status.UserRef.Uid)
		assert.Equal(t, []string{"02:42:ac:11:00:02"}, dev.Status.MacAddresses)

		t.Run("AlreadyRegistered", func(t *testing.T) {
			_, err := sess.C().RegisterDeviceBegin(sess.Ctx(t.Context()),
				&authv1.RegisterDeviceBeginRequest{Info: deviceInfo()})
			require.NotNil(t, err,
				"a Session that is already bound to a Device must not register another one")
			assert.True(t, grpcerr.AlreadyExists(err),
				"registering a second Device returned an unexpected error: %+v", err)
		})
	})

	t.Run("InvalidIDRejected", func(t *testing.T) {
		sess := h.NewAuthSession(t, harness.AuthSessionOpts{
			SessionType: corev1.Session_Status_CLIENT,
		})

		info := deviceInfo()
		info.Id = utilrand.GetRandomStringCanonical(64)

		_, err := sess.C().RegisterDeviceBegin(sess.Ctx(t.Context()),
			&authv1.RegisterDeviceBeginRequest{Info: info})
		require.NotNil(t, err, "a Device ID that is not a 64 character hex string must be rejected")
		assert.True(t, grpcerr.IsInvalidArg(err),
			"an invalid Device ID returned an unexpected error: %+v", err)
	})

	t.Run("ClientlessSessionRejected", func(t *testing.T) {
		sess := h.NewAuthSession(t, harness.AuthSessionOpts{
			SessionType: corev1.Session_Status_CLIENTLESS,
		})

		_, err := sess.C().RegisterDeviceBegin(sess.Ctx(t.Context()),
			&authv1.RegisterDeviceBeginRequest{Info: deviceInfo()})
		require.NotNil(t, err, "Device registration requires a CLIENT Session")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"registering a Device from a CLIENTLESS Session returned an unexpected error: %+v",
			err)
	})

	t.Run("UnknownRegistrationRejected", func(t *testing.T) {
		sess := h.NewAuthSession(t, harness.AuthSessionOpts{
			SessionType: corev1.Session_Status_CLIENT,
		})

		_, err := sess.C().RegisterDeviceFinish(sess.Ctx(t.Context()),
			&authv1.RegisterDeviceFinishRequest{
				Uid: utilrand.GetRandomStringLowercase(10),
			})
		require.NotNil(t, err,
			"finishing a Device registration that was never begun must be rejected")

		assert.Nil(t, sess.Session(t).Status.DeviceRef,
			"a failed Device registration must not bind the Session to a Device")
	})

	t.Run("ForeignIDRejected", func(t *testing.T) {
		owner := h.NewAuthSession(t, harness.AuthSessionOpts{
			SessionType: corev1.Session_Status_CLIENT,
		})

		info := deviceInfo()

		begin, err := owner.C().RegisterDeviceBegin(owner.Ctx(t.Context()),
			&authv1.RegisterDeviceBeginRequest{Info: info})
		require.Nil(t, err)

		_, err = owner.C().RegisterDeviceFinish(owner.Ctx(t.Context()),
			&authv1.RegisterDeviceFinishRequest{Uid: begin.Uid})
		require.Nil(t, err)

		other := h.NewAuthSession(t, harness.AuthSessionOpts{
			SessionType: corev1.Session_Status_CLIENT,
		})

		_, err = other.C().RegisterDeviceBegin(other.Ctx(t.Context()),
			&authv1.RegisterDeviceBeginRequest{Info: info})
		require.NotNil(t, err,
			"a Device that belongs to another User must not be claimed")
		assert.True(t, grpcerr.IsInvalidArg(err),
			"claiming a foreign Device returned an unexpected error: %+v", err)

		assert.Nil(t, other.Session(t).Status.DeviceRef,
			"a refused Device registration must not bind the Session to a Device")
	})
}

func testAuthServerLogout(t *testing.T, h *harness.H) {
	svc := h.NewPublicService(t, "default")

	sess := h.NewAuthSession(t, harness.AuthSessionOpts{
		UserType: corev1.User_Spec_WORKLOAD,
		Authorization: &corev1.User_Spec_Authorization{
			InlinePolicies: harness.InlineAllowAny("allow"),
		},
	})

	h.WaitAllowed(t, h.ServiceClient(svc, sess.Token().AccessToken))

	name := sess.Name()

	_, err := sess.C().Logout(sess.Ctx(t.Context()), &authv1.LogoutRequest{})
	require.Nil(t, err, "could not log out")

	_, err = h.CoreC().GetSession(t.Context(), &metav1.GetOptions{Name: name})
	require.NotNil(t, err, "logging out must delete the Session")
	assert.True(t, grpcerr.IsNotFound(err),
		"reading the Session of a logged out User returned an unexpected error: %+v", err)

	_, err = sess.C().AuthenticateWithRefreshToken(sess.Ctx(t.Context()),
		&authv1.AuthenticateWithRefreshTokenRequest{})
	require.NotNil(t, err, "the refresh token of a logged out Session must be rejected")
	assert.True(t, grpcerr.IsUnauthenticated(err),
		"refreshing a logged out Session returned an unexpected error: %+v", err)

	h.Eventually(t, "the access token of the logged out Session to be rejected",
		harness.DecisionBudget, func(ctx context.Context) error {
			got, err := h.StatusOf(ctx, h.ServiceClient(svc, sess.Token().AccessToken), "/")
			if err != nil {
				return err
			}
			if got == http.StatusOK {
				return errStillAllowed
			}
			if got != http.StatusUnauthorized && got != http.StatusForbidden {
				return errors.Errorf("unexpected status %d after logging out", got)
			}
			return nil
		})
}
