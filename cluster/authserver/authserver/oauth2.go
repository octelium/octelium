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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/oscope"
	"github.com/octelium/octelium/cluster/common/sessionc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (s *server) handleOAuth2Token(w http.ResponseWriter, r *http.Request) {

	grantType := r.FormValue("grant_type")

	switch grantType {
	case "client_credentials":
		s.handleOAuth2TokenClientCredentials(w, r)
	default:
		s.returnOAuth2Err(w, "unsupported_grant_type", 400)
		return
	}

}

func (s *server) handleOAuth2TokenClientCredentials(w http.ResponseWriter, r *http.Request) {
	var err error
	ctx := r.Context()
	w.Header().Set("Content-Type", "application/json")

	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")

	tkn, err := s.getCredentialFromToken(ctx, clientSecret)
	if err != nil {
		zap.L().Debug("Could not get authentication Token", zap.Error(err))
		s.returnOAuth2Err(w, "invalid_client", 401)
		return
	}

	if tkn.Spec.Type != corev1.Credential_Spec_OAUTH2 {
		zap.L().Debug("Credential is not OAUTH2")
		s.returnOAuth2Err(w, "invalid_client", 401)
		return
	}

	if tkn.Status.Id != clientID {
		zap.L().Debug("oauth2 clientID mismatch", zap.Error(err))
		s.returnOAuth2Err(w, "invalid_client", 401)
		return
	}

	scopeStr := r.Form.Get("scope")
	scopes, err := checkAndGetOAuthScopeStr(scopeStr)
	if err != nil {
		s.returnOAuth2Err(w, "invalid_scope", 401)
		return
	}

	usr, err := s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
		Uid: tkn.Status.UserRef.Uid,
	})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			s.returnOAuth2Err(w, "invalid_client", 400)
			return
		}
		s.returnOAuth2Err(w, "server_error", 500)
		return
	}

	if usr.Spec.Type != corev1.User_Spec_WORKLOAD {
		s.returnOAuth2Err(w, "invalid_request", 400)
		return
	}

	if usr.Spec.IsDisabled {
		s.returnOAuth2Err(w, "invalid_request", 400)
		return
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		s.returnOAuth2Err(w, "server_error", 500)
		return
	}

	sessList, err := s.octeliumC.CoreC().ListSession(ctx, &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterFieldEQValStr("status.credentialRef.uid", tkn.Metadata.Uid),
		},
	})
	if err != nil {
		s.returnOAuth2Err(w, "server_error", 500)
		return
	}
	var sess *corev1.Session
	if len(sessList.Items) > 0 {
		sess = sessList.Items[0]

		s.setCurrAuthentication(sess, &corev1.Session_Status_Authentication_Info{
			Type: corev1.Session_Status_Authentication_Info_CREDENTIAL,
			Details: &corev1.Session_Status_Authentication_Info_Credential_{
				Credential: &corev1.Session_Status_Authentication_Info_Credential{
					CredentialRef: umetav1.GetObjectReference(tkn),
					Type:          tkn.Spec.Type,
					TokenID:       tkn.Status.TokenID,
				},
			},
		}, r.Header.Get("User-Agent"), cc, r.Header.Get("X-Forwarded-For"))

		sess, err = s.octeliumC.CoreC().UpdateSession(ctx, sess)
		if err != nil {
			s.returnOAuth2Err(w, "server_error", 500)
			return
		}
	} else {

		if err := s.checkMaxSessionsPerUser(ctx, usr, cc); err != nil {
			s.returnOAuth2Err(w, "invalid_request", 400)
			return
		}
		sess, err = sessionc.CreateSession(ctx, &sessionc.CreateSessionOpts{
			OcteliumC:     s.octeliumC,
			ClusterConfig: cc,
			Usr:           usr,
			SessType:      corev1.Session_Status_CLIENTLESS,
			Scopes:        scopes,
			Authorization: func() *corev1.Session_Spec_Authorization {
				if tkn.Spec.Authorization == nil {
					return nil
				}
				return &corev1.Session_Spec_Authorization{
					Policies:       tkn.Spec.Authorization.Policies,
					InlinePolicies: tkn.Spec.Authorization.InlinePolicies,
				}
			}(),
			AuthenticationInfo: &corev1.Session_Status_Authentication_Info{
				Type: corev1.Session_Status_Authentication_Info_CREDENTIAL,
				Details: &corev1.Session_Status_Authentication_Info_Credential_{
					Credential: &corev1.Session_Status_Authentication_Info_Credential{
						CredentialRef: umetav1.GetObjectReference(tkn),
						Type:          tkn.Spec.Type,
						TokenID:       tkn.Status.TokenID,
					},
				},
			},
			CredentialRef: umetav1.GetObjectReference(tkn),
			UserAgent:     r.Header.Get("User-Agent"),
			XFF:           r.Header.Get("X-Forwarded-For"),
		})
		if err != nil {
			s.returnOAuth2Err(w, "server_error", 500)
			return
		}
	}

	if err := s.updateAndAutoDeleteCredential(ctx, tkn); err != nil {
		s.returnOAuth2Err(w, "server_error", 500)
		return
	}

	accessToken, err := s.generateAccessToken(sess)
	if err != nil {
		s.returnOAuth2Err(w, "server_error", 500)
		return
	}

	resp := &oauthAccessTokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(umetav1.ToDuration(sess.Status.Authentication.AccessTokenDuration).ToSeconds()),
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		s.returnOAuth2Err(w, "server_error", 500)
		return
	}

	w.Write(respBytes)
}

func checkAndGetOAuthScopeStr(arg string) ([]*corev1.Scope, error) {
	argLen := len(arg)
	if argLen == 0 {
		return nil, nil
	}
	if argLen > 2048 {
		return nil, errors.Errorf("Too long scopes")
	}
	if !govalidator.IsASCII(arg) {
		return nil, errors.Errorf("Invalid scope argument")
	}

	scopeStrs := strings.Split(arg, " ")

	return oscope.GetScopes(scopeStrs)

}

type oauth2ErrorResponse struct {
	Error string `json:"error,omitempty"`
}

func (s *server) returnOAuth2Err(w http.ResponseWriter, errCode string, statusCode int) {

	resp := &oauth2ErrorResponse{
		Error: errCode,
	}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(statusCode)
	w.Write(respBytes)
}

type oauthAccessTokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type oauth2Metadata struct {
	Issuer                            string   `json:"issuer"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
}

func (s *server) handleOAuth2Metadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(oauth2Metadata{
		Issuer:                 s.rootURL,
		TokenEndpoint:          fmt.Sprintf("%s/oauth2/token", s.rootURL),
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported: []string{
			"client_credentials",
		},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_post",
		},
	})
}
