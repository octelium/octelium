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
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/sessionc"
	"go.uber.org/zap"
)

type webDevSessResp struct {
	sess *corev1.Session
}

func (s *server) createOrUpdateSessWeb(r *http.Request,
	usr *corev1.User, authResp *corev1.Session_Status_Authentication_Info,
	cc *corev1.ClusterConfig) (*webDevSessResp, error) {
	ctx := r.Context()
	cookie, err := r.Cookie("octelium_rt")
	if err != nil {
		zap.L().Debug("Could not find refresh token cookie. Creating a new webSession")
		return s.createWebDevSess(r, usr, authResp, nil, cc)
	}

	/*
		claims, err := s.jwkCtl.VerifyRefreshToken(cookie.Value)
		if err != nil {
			return s.createWebDevSess(r, usr, authResp, nil, cc)
		}

		sess, err := s.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: claims.SessionUID})
		if err != nil {
			if !grpcerr.IsNotFound(err) {
				return nil, err
			}
			return s.createWebDevSess(r, usr, authResp, nil, cc)
		}
	*/
	sess, err := s.getSessionFromRefreshToken(ctx, cookie.Value)
	if err != nil {
		zap.L().Debug("Could not get Session from refresh token. Creating a new webSession", zap.Error(err))
		return s.createWebDevSess(r, usr, authResp, nil, cc)
	}

	deleteSess := func() {

		_, err := s.octeliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{
			Uid: sess.Metadata.Uid,
		})
		if err != nil {
			zap.L().Debug("Could not delete old web Session",
				zap.String("name", sess.Metadata.Name), zap.Error(err))
		}
	}

	if authResp.GetIdentityProvider() == nil || authResp.GetIdentityProvider().IdentityProviderRef == nil ||
		sess.Status.InitialAuthentication == nil || sess.Status.InitialAuthentication.Info.GetIdentityProvider() == nil ||
		sess.Status.InitialAuthentication.Info.GetIdentityProvider().IdentityProviderRef == nil {
		// This shouldn't be happening in production
		deleteSess()
		return s.createWebDevSess(r, usr, authResp, nil, cc)
	}
	if authResp.GetIdentityProvider().IdentityProviderRef.Uid !=
		sess.Status.InitialAuthentication.Info.GetIdentityProvider().IdentityProviderRef.Uid {
		deleteSess()
		return s.createWebDevSess(r, usr, authResp, nil, cc)
	}

	zap.S().Debugf("Rotating the token for the Session: %s", sess.Metadata.Name)
	s.setCurrAuthentication(sess, authResp, r.Header.Get("User-Agent"), cc, r.Header.Get("X-Forwarded-For"))

	if authResp.GetIdentityProvider() != nil && authResp.GetIdentityProvider().PicURL != "" {
		sess.Metadata.PicURL = authResp.GetIdentityProvider().PicURL
	}
	sess, err = s.octeliumC.CoreC().UpdateSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	return &webDevSessResp{
		sess: sess,
	}, nil
}

func (s *server) createWebDevSess(r *http.Request, usr *corev1.User,
	authRespInfo *corev1.Session_Status_Authentication_Info, dev *corev1.Device,
	cc *corev1.ClusterConfig) (*webDevSessResp, error) {
	ctx := r.Context()

	var err error
	if err := s.checkMaxSessionsPerUser(ctx, usr, cc); err != nil {
		return nil, err
	}
	sess, err := sessionc.CreateSession(ctx,
		&sessionc.CreateSessionOpts{
			OcteliumC:          s.octeliumC,
			ClusterConfig:      cc,
			Usr:                usr,
			Device:             dev,
			AuthenticationInfo: authRespInfo,
			SessType:           corev1.Session_Status_CLIENTLESS,
			IsBrowser:          true,
			UserAgent:          r.Header.Get("User-Agent"),
			XFF:                r.Header.Get("X-Forwarded-For"),
		})
	if err != nil {
		return nil, err
	}

	return &webDevSessResp{
		sess: sess,
	}, nil
}

func (s *server) setCurrAuthenticationGRPC(ctx context.Context, sess *corev1.Session, cc *corev1.ClusterConfig, authInfo *corev1.Session_Status_Authentication_Info) {
	s.setCurrAuthentication(sess, authInfo,
		grpcutils.GetHeaderValueMust(ctx, "User-Agent"), cc,
		grpcutils.GetHeaderValueMust(ctx, "X-Forwarded-For"))
}

func (s *server) setCurrAuthentication(sess *corev1.Session, authInfo *corev1.Session_Status_Authentication_Info, userAgent string, cc *corev1.ClusterConfig, xff string) {
	sessionc.SetCurrAuthentication(&sessionc.SetCurrAuthenticationOpts{
		Session:       sess,
		ClusterConfig: cc,
		AuthInfo:      authInfo,
		UserAgent:     userAgent,
		XFF:           xff,
	})
}
