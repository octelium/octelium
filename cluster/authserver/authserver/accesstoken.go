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
	"net/http"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (s *server) setInternalError(w http.ResponseWriter, err error) {
	zap.L().Debug("Internal error", zap.Error(err))
	w.WriteHeader(http.StatusInternalServerError)
}

func (s *server) generateAccessToken(sess *corev1.Session) (string, error) {
	if sess == nil {
		return "", errors.Errorf("generateAccessToken: Nil Session")
	}
	return s.jwkCtl.CreateAccessToken(sess)
}

func (s *server) generateRefreshToken(sess *corev1.Session) (string, error) {
	if sess == nil {
		return "", errors.Errorf("generateRefreshToken: Nil Session")
	}
	return s.jwkCtl.CreateRefreshToken(sess)
}

func (s *server) getCredentialFromToken(ctx context.Context, authTokenStr string) (*corev1.Credential, error) {

	claims, err := s.jwkCtl.VerifyCredential(authTokenStr)
	if err != nil {
		return nil, s.errUnauthenticatedErr(err)
	}

	tkn, err := s.octeliumC.CoreC().GetCredential(ctx, &rmetav1.GetOptions{Uid: claims.UID})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil, s.errUnauthenticated("The Credential no longer exists")
		}
		return nil, s.errInternalErr(err)
	}

	if tkn.Spec.IsDisabled {
		return nil, s.errUnauthenticated("Credential is disabled")
	}

	if tkn.Status.IsLocked {
		return nil, s.errUnauthenticated("Credential is locked")
	}

	if !utils.SecureStringEqual(claims.TokenID, tkn.Status.TokenID) {
		return nil, s.errUnauthenticated("Token name does not match")
	}

	if tkn.Spec.ExpiresAt.IsValid() && time.Now().After(tkn.Spec.ExpiresAt.AsTime()) {
		return nil, s.errUnauthenticated("Authentication token expired")
	}

	if tkn.Spec.MaxAuthentications > 0 && tkn.Status.TotalAuthentications >= tkn.Spec.MaxAuthentications {
		return nil, s.errUnauthenticated("Authentications for this Credential have been exceeded the max ")
	}

	return tkn, nil
}

func (s *server) getSessionFromRefreshToken(ctx context.Context, refreshToken string) (*corev1.Session, error) {
	if refreshToken == "" {
		return nil, s.errUnauthenticated("No refresh token supplied")
	}

	claims, err := s.jwkCtl.VerifyRefreshToken(refreshToken)
	if err != nil {
		return nil, s.errUnauthenticatedErr(err)
	}

	sess, err := s.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: claims.SessionUID})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			zap.L().Debug("Could not find Session from refresh token")
			return nil, s.errUnauthenticated("Session no longer exists")
		}
		return nil, s.errInternalErr(err)
	}

	if claims.SessionUID != sess.Metadata.Uid {
		return nil, s.errUnauthenticated("Invalid Session UID")
	}

	if sess.Status.Authentication.TokenID != claims.TokenID {
		return nil, s.errUnauthenticated("Invalid Session tokenID")
	}

	if ucorev1.ToSession(sess).IsExpired() {
		return nil, s.errUnauthenticated("Session expired")
	}

	if !ucorev1.ToSession(sess).HasValidRefreshToken() {
		return nil, s.errUnauthenticated("Invalid refresh token")
	}

	switch sess.Spec.State {
	case corev1.Session_Spec_REJECTED:
		return nil, s.errUnauthenticated("Session is rejected")
	}

	if sess.Status.IsLocked {
		return nil, s.errUnauthenticated("Session is locked")
	}

	return sess, nil
}

const maxAuthenticationsPerHour = 5

func (s *server) needsReAuth(sess *corev1.Session) bool {

	if sess == nil ||
		sess.Status == nil ||
		sess.Status.Authentication == nil ||
		sess.Status.Authentication.AccessTokenDuration == nil ||
		sess.Status.Authentication.SetAt == nil ||
		!sess.Status.Authentication.SetAt.IsValid() {
		return true
	}

	if !ucorev1.ToSession(sess).HasValidAccessToken() {
		return true
	}

	halfLife := umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToGo() / 2

	return time.Now().After(sess.Status.Authentication.SetAt.AsTime().Add(halfLife))
}

func (s *server) checkReauthRateLimit(sess *corev1.Session) error {
	count := 0

	now := time.Now()

	for _, auth := range sess.Status.LastAuthentications {
		if auth == nil || auth.SetAt == nil || !auth.SetAt.IsValid() {
			continue
		}

		if auth.SetAt.AsTime().After(now.Add(-time.Hour)) {
			count++
		}
	}

	if count < maxAuthenticationsPerHour {
		return nil
	}

	return s.errPermissionDenied("Too many authentications in the last hour")
}
