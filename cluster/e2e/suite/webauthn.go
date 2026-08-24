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
	"encoding/json"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

const clusterConfigBudget = 60 * time.Second

type passkeyRequestOptions struct {
	Challenge        string `json:"challenge"`
	RpID             string `json:"rpId"`
	UserVerification string `json:"userVerification"`
	Timeout          int    `json:"timeout"`
	AllowCredentials []struct {
		Id string `json:"id"`
	} `json:"allowCredentials"`
}

func testPasskeyLogin(t *testing.T, h *harness.H) {
	c := h.BrowserAuthC(t)

	begin := func(ctx context.Context) (*authv1.AuthenticateWithPasskeyBeginResponse, error) {
		return c.AuthenticateWithPasskeyBegin(h.BrowserCtx(ctx),
			&authv1.AuthenticateWithPasskeyBeginRequest{})
	}

	authenticate := func(ctx context.Context, response string) (*authv1.SessionToken, error) {
		return c.AuthenticateWithPasskey(h.BrowserCtx(ctx),
			&authv1.AuthenticateWithPasskeyRequest{Response: response})
	}

	setAuthenticator := func(t *testing.T, arg *corev1.ClusterConfig_Spec_Authenticator) {
		t.Helper()

		cc := h.ClusterConfig(t)
		cc.Spec.Authenticator = arg
		h.UpdateClusterConfig(t, cc)
	}

	original := h.ClusterConfig(t).Spec.Authenticator
	t.Cleanup(func() {
		cc := h.ClusterConfig(t)
		cc.Spec.Authenticator = original

		if _, err := h.CoreC().UpdateClusterConfig(context.Background(), cc); err != nil {
			zap.L().Warn("Could not restore the ClusterConfig Authenticator", zap.Error(err))
		}
	})

	setAuthenticator(t, nil)

	t.Run("DisabledWithoutClusterConfig", func(t *testing.T) {
		h.Eventually(t, "the Cluster to refuse Passkey logins", clusterConfigBudget,
			func(ctx context.Context) error {
				_, err := begin(ctx)
				if err == nil {
					return errors.Errorf("the Cluster still begins Passkey logins")
				}
				if !grpcerr.IsPermissionDenied(err) {
					return errors.Errorf(
						"beginning a Passkey login without enablePasskeyLogin "+
							"returned an unexpected error: %+v", err)
				}
				return nil
			})
	})

	setAuthenticator(t, &corev1.ClusterConfig_Spec_Authenticator{
		EnablePasskeyLogin: true,
	})

	var request string

	t.Run("EnabledByClusterConfig", func(t *testing.T) {
		h.Eventually(t, "the Cluster to begin Passkey logins", clusterConfigBudget,
			func(ctx context.Context) error {
				res, err := begin(ctx)
				if err != nil {
					return err
				}
				if res.Request == "" {
					return errors.Errorf("the Cluster returned an empty Passkey request")
				}
				request = res.Request
				return nil
			})
	})

	require.NotEmpty(t, request,
		"the Cluster never began a Passkey login. The authentication client must reach "+
			"the authServer with a browser User-Agent and an Origin of %s", h.RootURL())

	t.Run("RequestOptions", func(t *testing.T) {
		opts := &passkeyRequestOptions{}
		require.Nil(t, json.Unmarshal([]byte(request), opts),
			"the Passkey request is not valid JSON: %s", request)

		assert.Equal(t, h.Domain, opts.RpID,
			"the Passkey request must be scoped to the Cluster domain")
		assert.Equal(t, "required", opts.UserVerification,
			"Passkey logins must require user verification")
		assert.Empty(t, opts.AllowCredentials,
			"a Passkey login must be discoverable and must not enumerate credentials")
		assert.True(t, opts.Timeout > 0, "the Passkey request carries no timeout")
		assert.Equal(t, 43, len(opts.Challenge),
			"the Passkey challenge must be 32 random bytes")
	})

	t.Run("UnknownPasskeyRejected", func(t *testing.T) {
		dev := h.NewVirtualFIDO(t)

		_, err := authenticate(t.Context(), dev.Assertion(t, request))
		require.NotNil(t, err, "an unregistered Passkey must not authenticate")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"an unregistered Passkey returned an unexpected error: %+v", err)
	})

	t.Run("ChallengeIsSingleUse", func(t *testing.T) {
		res, err := begin(t.Context())
		require.Nil(t, err)

		dev := h.NewVirtualFIDO(t)
		response := dev.Assertion(t, res.Request)

		_, err = authenticate(t.Context(), response)
		require.NotNil(t, err)

		_, err = authenticate(t.Context(), response)
		require.NotNil(t, err, "a Passkey challenge must not be answered twice")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"replaying a Passkey challenge returned an unexpected error: %+v", err)
	})

	t.Run("NonBrowserRejected", func(t *testing.T) {
		plain := h.AuthC(t)

		_, err := plain.AuthenticateWithPasskeyBegin(h.BrowserCtx(t.Context()),
			&authv1.AuthenticateWithPasskeyBeginRequest{})
		require.NotNil(t, err, "Passkey logins require a browser User-Agent")
		assert.True(t, grpcerr.IsInvalidArg(err),
			"a non browser User-Agent returned an unexpected error: %+v", err)
	})

	t.Run("MissingOriginRejected", func(t *testing.T) {
		_, err := c.AuthenticateWithPasskeyBegin(t.Context(),
			&authv1.AuthenticateWithPasskeyBeginRequest{})
		require.NotNil(t, err, "Passkey logins require an Origin")
		assert.True(t, grpcerr.IsInvalidArg(err),
			"a missing Origin returned an unexpected error: %+v", err)
	})

	t.Run("ForeignOriginRejected", func(t *testing.T) {
		for _, origin := range []string{
			"https://attacker.example.com",
			h.RootURL() + ".attacker.example.com",
			"http://" + h.Domain,
		} {
			_, err := c.AuthenticateWithPasskeyBegin(
				h.OriginCtx(t.Context(), origin),
				&authv1.AuthenticateWithPasskeyBeginRequest{})
			require.NotNil(t, err, "the Origin %s must be rejected", origin)
			assert.True(t, grpcerr.IsInvalidArg(err),
				"the Origin %s returned an unexpected error: %+v", origin, err)
		}
	})

	t.Run("InvalidQueryRejected", func(t *testing.T) {
		_, err := c.AuthenticateWithPasskeyBegin(h.BrowserCtx(t.Context()),
			&authv1.AuthenticateWithPasskeyBeginRequest{
				Query: "octelium_req=invalid",
			})
		require.NotNil(t, err, "an invalid login query must be rejected")
		assert.True(t, grpcerr.IsInvalidArg(err),
			"an invalid login query returned an unexpected error: %+v", err)
	})

	t.Run("DisablingRevokesPasskeyLogin", func(t *testing.T) {
		setAuthenticator(t, &corev1.ClusterConfig_Spec_Authenticator{
			EnablePasskeyLogin: false,
		})

		h.Eventually(t, "the Cluster to refuse Passkey logins again", clusterConfigBudget,
			func(ctx context.Context) error {
				_, err := begin(ctx)
				if err == nil {
					return errors.Errorf("the Cluster still begins Passkey logins")
				}
				if !grpcerr.IsPermissionDenied(err) {
					return errors.Errorf(
						"beginning a Passkey login after disabling it "+
							"returned an unexpected error: %+v", err)
				}
				return nil
			})
	})
}

func testAuthenticatorFIDOAccess(t *testing.T, h *harness.H) {
	createFIDO := func(t *testing.T, sess *harness.AuthSession) error {
		t.Helper()

		_, err := sess.C().CreateAuthenticator(sess.Ctx(t.Context()),
			&authv1.CreateAuthenticatorRequest{
				Type:        authv1.Authenticator_Status_FIDO,
				DisplayName: "e2e fido",
			})
		return err
	}

	t.Run("ClientSessionRejected", func(t *testing.T) {
		err := createFIDO(t, h.NewAuthSession(t, harness.AuthSessionOpts{
			UserType:    corev1.User_Spec_HUMAN,
			SessionType: corev1.Session_Status_CLIENT,
		}))
		require.NotNil(t, err, "FIDO Authenticators require a browser Session")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"creating a FIDO Authenticator from a CLIENT Session "+
				"returned an unexpected error: %+v", err)
	})

	t.Run("NonBrowserClientlessSessionRejected", func(t *testing.T) {
		err := createFIDO(t, h.NewAuthSession(t, harness.AuthSessionOpts{
			UserType:    corev1.User_Spec_HUMAN,
			SessionType: corev1.Session_Status_CLIENTLESS,
		}))
		require.NotNil(t, err,
			"FIDO Authenticators require a browser Session even when CLIENTLESS")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"creating a FIDO Authenticator from a non browser CLIENTLESS Session "+
				"returned an unexpected error: %+v", err)
	})

	t.Run("WorkloadUserRejected", func(t *testing.T) {
		err := createFIDO(t, h.NewAuthSession(t, harness.AuthSessionOpts{
			UserType:    corev1.User_Spec_WORKLOAD,
			SessionType: corev1.Session_Status_CLIENTLESS,
		}))
		require.NotNil(t, err, "FIDO Authenticators require a HUMAN User")
		assert.True(t, grpcerr.IsPermissionDenied(err),
			"creating a FIDO Authenticator for a WORKLOAD User "+
				"returned an unexpected error: %+v", err)
	})
}
