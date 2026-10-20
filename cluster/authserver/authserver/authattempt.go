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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/authevents"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
)

func (s *server) getAuthAttemptOpts(userAgent, clientAddr string) *authevents.AttemptOpts {
	ret := &authevents.AttemptOpts{
		UserAgent:  userAgent,
		ClientAddr: clientAddr,
	}

	if s.ccCtl != nil {
		ret.ClusterConfig = s.ccCtl.Get()
	}

	return ret
}

func (s *server) newAuthAttemptGRPC(ctx context.Context,
	typ corev1.Session_Status_Authentication_Info_Type) (context.Context, *authevents.Attempt) {
	return authevents.NewAttempt(ctx, typ, s.getAuthAttemptOpts(
		grpcutils.GetHeaderValueMust(ctx, "user-agent"),
		grpcutils.GetHeaderValueMust(ctx, vutils.GetDownstreamIPHeaderCanonical())))
}

func (s *server) newAuthAttemptHTTP(r *http.Request,
	typ corev1.Session_Status_Authentication_Info_Type) (*http.Request, *authevents.Attempt) {
	ctx, attempt := authevents.NewAttempt(r.Context(), typ, s.getAuthAttemptOpts(
		r.Header.Get("User-Agent"),
		r.Header.Get(vutils.GetDownstreamIPHeaderCanonical())))

	return r.WithContext(ctx), attempt
}

func (s *server) finishAuthAttempt(attempt *authevents.Attempt, err error) {
	s.authEvents.Finish(attempt, err)
}

func getAttemptIdentityProvider(idp *corev1.IdentityProvider) *corev1.Session_Status_Authentication_Info_IdentityProvider {
	return &corev1.Session_Status_Authentication_Info_IdentityProvider{
		IdentityProviderRef: umetav1.GetObjectReference(idp),
		Type:                idp.GetStatus().GetType(),
	}
}

func getSessionAuthenticatorMode(sess *corev1.Session) corev1.Session_Status_Authentication_Info_Authenticator_Mode {
	switch sess.Status.AuthenticatorAction {
	case corev1.Session_Status_AUTHENTICATION_REQUIRED,
		corev1.Session_Status_AUTHENTICATION_RECOMMENDED:
		return corev1.Session_Status_Authentication_Info_Authenticator_MFA
	default:
		return corev1.Session_Status_Authentication_Info_Authenticator_DEFAULT
	}
}

func getUserStateReason(usr *corev1.User) authevents.Reason {
	if usr.Spec.IsDisabled {
		return authevents.ReasonUserDeactivated
	}

	return authevents.ReasonUserLocked
}
