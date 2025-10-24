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
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/apis/rsc/rratelimitv1"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators/fido"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators/totp"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators/tpm"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (s *server) doAuthenticateAuthenticator(ctx context.Context,
	cc *corev1.ClusterConfig,
	resp *authv1.AuthenticateWithAuthenticatorRequest,
	usr *corev1.User, sess *corev1.Session) (*corev1.Session_Status_Authentication_Info, error) {
	var err error

	if resp == nil || resp.ChallengeResponse == nil {
		return nil, s.errInvalidArg("Nil Authenticator response")
	}

	authn, err := s.getAuthenticator(ctx, resp.AuthenticatorRef, sess)
	if err != nil {
		return nil, err
	}

	if !authn.Status.IsRegistered {
		return nil, s.errPermissionDenied("Authenticator is not registered")
	}

	if err := s.checkAuthenticatorRateLimit(ctx, authn); err != nil {
		return nil, err
	}

	nullifyCurrAndUpdate := func() error {
		s.prependToLastAttempts(authn)
		authn, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
		if err != nil {
			return s.errInternalErr(err)
		}
		return nil
	}

	if authn.Status.AuthenticationAttempt == nil ||
		authn.Status.AuthenticationAttempt.SessionRef == nil ||
		authn.Status.AuthenticationAttempt.CreatedAt == nil ||
		!authn.Status.AuthenticationAttempt.CreatedAt.IsValid() ||
		authn.Status.AuthenticationAttempt.EncryptedChallengeRequest == nil {
		return nil, s.errPermissionDenied("No valid current authentication attempt...")
	}

	if authn.Status.AuthenticationAttempt.SessionRef.Uid != sess.Metadata.Uid {
		return nil, s.errPermissionDenied("No valid current authentication attempt")
	}

	if s.isAuthenticationAttemptTimeoutExceeded(authn) {
		if err := nullifyCurrAndUpdate(); err != nil {
			return nil, err
		}

		return nil, s.errPermissionDenied("No valid current authentication attempt")
	}

	challengeReqBytes, err := authenticators.DecryptData(ctx,
		s.octeliumC, authn.Status.AuthenticationAttempt.EncryptedChallengeRequest)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	challengeReq := &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest{}
	if err := pbutils.Unmarshal(challengeReqBytes, challengeReq); err != nil {
		return nil, s.errInternalErr(err)
	}

	var factor authenticators.Factor

	switch challengeReq.Type.(type) {

	case *authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_Fido:
		if resp.ChallengeResponse.GetFido() == nil {
			return nil, s.errInvalidArg("Mismatch auth factor type")
		}
		if authn.Status.Type != corev1.Authenticator_Status_FIDO {
			return nil, s.errInvalidArg("Invalid Authenticator type")
		}

	case *authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_Totp:
		if resp.ChallengeResponse.GetTotp() == nil {
			return nil, s.errInvalidArg("Mismatch auth factor type")
		}
		if authn.Status.Type != corev1.Authenticator_Status_TOTP {
			return nil, s.errInvalidArg("Invalid Authenticator type")
		}
	case *authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_Tpm:
		if resp.ChallengeResponse.GetTpm() == nil {
			return nil, s.errInvalidArg("Mismatch auth factor type")
		}
		if authn.Status.Type != corev1.Authenticator_Status_TPM {
			return nil, s.errInvalidArg("Invalid Authenticator type")
		}
	default:
		return nil, s.errInvalidArg("Invalid challengeRequest type")
	}

	factor, err = s.getAuthenticatorCtl(ctx, authn, usr, cc)
	if err != nil {
		return nil, err
	}

	finishResp, err := factor.Finish(ctx, &authenticators.FinishReq{
		Resp:             resp,
		ChallengeRequest: challengeReq,
	})
	if err != nil {
		zap.L().Debug("Could not do Authenticator finish", zap.Any("authn", authn), zap.Error(err))
		authn.Status.FailedAuthentications = authn.Status.FailedAuthentications + 1
		nullifyCurrAndUpdate()
		if authenticators.IsErrInvalidAuth(err) {
			return nil, s.errPermissionDenied("Invalid authentication")
		}
		return nil, s.errInternalErr(err)
	}

	authn.Status.SuccessfulAuthentications = authn.Status.SuccessfulAuthentications + 1

	authInfo := &corev1.Session_Status_Authentication_Info{
		Type: corev1.Session_Status_Authentication_Info_AUTHENTICATOR,
		Details: &corev1.Session_Status_Authentication_Info_Authenticator_{
			Authenticator: &corev1.Session_Status_Authentication_Info_Authenticator{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
				Type:             authn.Status.Type,
				Mode: func() corev1.Session_Status_Authentication_Info_Authenticator_Mode {
					switch sess.Status.AuthenticatorAction {
					case corev1.Session_Status_AUTHENTICATION_REQUIRED,
						corev1.Session_Status_AUTHENTICATION_RECOMMENDED:
						return corev1.Session_Status_Authentication_Info_Authenticator_MFA
					default:
						return corev1.Session_Status_Authentication_Info_Authenticator_DEFAULT
					}
				}(),
				Info: func() *corev1.Session_Status_Authentication_Info_Authenticator_Info {
					if authn.Status.Type == corev1.Authenticator_Status_FIDO && finishResp.Cred != nil {
						return &corev1.Session_Status_Authentication_Info_Authenticator_Info{
							Type: &corev1.Session_Status_Authentication_Info_Authenticator_Info_Fido{
								Fido: s.getSessionAuthenticatorInfoFIDO(finishResp.Cred, authn),
							},
						}
					}

					return nil
				}(),
			},
		},
	}

	if err := s.doPostAuthenticatorAuthenticationRules(ctx, cc, authn, sess, usr, authInfo); err != nil {
		return nil, s.errPermissionDeniedErr(err)
	}

	if err := nullifyCurrAndUpdate(); err != nil {
		return nil, err
	}

	return authInfo, nil
}

func (s *server) getSessionAuthenticatorInfoFIDO(cred *webauthn.Credential,
	authn *corev1.Authenticator) *corev1.Session_Status_Authentication_Info_Authenticator_Info_FIDO {
	ret := &corev1.Session_Status_Authentication_Info_Authenticator_Info_FIDO{
		UserPresent:  cred.Flags.UserPresent,
		UserVerified: cred.Flags.UserVerified,
	}
	if authn.Status.Info != nil && authn.Status.Info.GetFido() != nil {
		fido := authn.Status.Info.GetFido()
		ret.IsHardware = fido.IsHardware
		ret.IsSoftware = fido.IsSoftware
		ret.IsPasskey = fido.IsPasskey
		ret.IsAttestationVerified = fido.IsAttestationVerified
		ret.Aaguid = fido.Aaguid
	}

	return ret
}

func (s *server) doPostAuthenticatorAuthenticationRules(ctx context.Context,
	cc *corev1.ClusterConfig, authn *corev1.Authenticator,
	sess *corev1.Session, usr *corev1.User,
	authInfo *corev1.Session_Status_Authentication_Info) error {
	if cc.Spec.Authenticator == nil || len(cc.Spec.Authenticator.PostAuthenticationRules) == 0 {
		return nil
	}

	inputMap := map[string]any{
		"ctx": map[string]any{
			"authenticator": pbutils.MustConvertToMap(authn),
			"user":          pbutils.MustConvertToMap(usr),
			"session":       pbutils.MustConvertToMap(sess),
			"info":          pbutils.MustConvertToMap(authInfo),
		},
	}

	for _, rule := range cc.Spec.Authenticator.PostAuthenticationRules {
		isMatched, err := s.celEngine.EvalCondition(ctx, rule.Condition, inputMap)
		if err != nil {
			zap.L().Debug("Could not eval postAuthentication condition", zap.Error(err))
			continue
		}

		if isMatched {
			switch rule.Effect {
			case corev1.ClusterConfig_Spec_Authenticator_Rule_ALLOW:
				return nil
			case corev1.ClusterConfig_Spec_Authenticator_Rule_DENY:
				return errors.Errorf("Denied by postAuthentication rule")
			}
		}
	}

	return nil
}

func (s *server) getAuthenticator(ctx context.Context,
	authnRef *metav1.ObjectReference, sess *corev1.Session) (*corev1.Authenticator, error) {

	if err := apivalidation.CheckObjectRef(authnRef, &apivalidation.CheckGetOptionsOpts{}); err != nil {
		return nil, s.errInvalidArgErr(err)
	}
	authn, err := s.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
		Uid:  authnRef.Uid,
		Name: authnRef.Name,
	})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil, s.errNotFoundErr(err)
		}
		return nil, s.errInternalErr(err)
	}

	if authn.Status.UserRef == nil {
		return nil, s.errInternal("Nil Authenticator UserRef")
	}
	if authn.Status.UserRef.Uid != sess.Status.UserRef.Uid {
		return nil, s.errPermissionDenied("Authenticator does not belong to the User")
	}

	return authn, nil
}

func (s *server) doAuthenticateAuthenticatorBegin(ctx context.Context,
	req *authv1.AuthenticateAuthenticatorBeginRequest) (*authv1.AuthenticateAuthenticatorBeginResponse, error) {
	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	authn, err := s.getAuthenticator(ctx, req.AuthenticatorRef, sess)
	if err != nil {
		return nil, err
	}

	if !authn.Status.IsRegistered {
		return nil, s.errInvalidArg("Authenticator is not registered")
	}

	if sess.Status.RequiredAuthenticatorRef != nil {
		if sess.Status.RequiredAuthenticatorRef.Uid != authn.Metadata.Uid {
			return nil, s.errPermissionDenied("This is not the required Session Authenticator")
		}
	} else {
		res, err := s.getAvailableAuthenticators(ctx, sess, usr)
		if err != nil {
			return nil, err
		}

		if idx := slices.IndexFunc(res.AvailableAuthenticators, func(itm *corev1.Authenticator) bool {
			return itm.Metadata.Uid == authn.Metadata.Uid
		}); idx < 0 {
			return nil, s.errPermissionDenied("Authenticator is not available for this Session")
		}
	}

	if err := s.checkAuthenticatorRateLimit(ctx, authn); err != nil {
		return nil, err
	}

	if sess.Status.DeviceRef != nil && authn.Status.DeviceRef != nil {
		if sess.Status.DeviceRef.Uid != authn.Status.DeviceRef.Uid {
			return nil, s.errPermissionDenied("Invalid Authenticator Device")
		}
	}

	switch sess.Status.Type {
	case corev1.Session_Status_CLIENT:
		switch authn.Status.Type {
		case corev1.Authenticator_Status_TPM, corev1.Authenticator_Status_TOTP:
		default:
			return nil, s.errPermissionDenied("Invalid Session type")
		}
	case corev1.Session_Status_CLIENTLESS:
		if sess.Status.IsBrowser {
			switch authn.Status.Type {
			case corev1.Authenticator_Status_FIDO, corev1.Authenticator_Status_TOTP:
			default:
				return nil, s.errPermissionDenied("Invalid Session type")
			}
		} else {
			return nil, s.errPermissionDenied("Invalid Session type")
		}
	}

	s.prependToLastAttempts(authn)

	fac, err := s.getAuthenticatorCtl(ctx, authn, usr, cc)
	if err != nil {
		return nil, err
	}

	authn.Status.AuthenticationAttempt = &corev1.Authenticator_Status_AuthenticationAttempt{
		CreatedAt:        pbutils.Now(),
		SessionRef:       umetav1.GetObjectReference(sess),
		EncryptedDataMap: make(map[string]*corev1.Authenticator_Status_EncryptedData),
		DataMap:          make(map[string][]byte),
	}

	ret, err := fac.Begin(ctx, &authenticators.BeginReq{
		Req: req,
	})
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	authn.Status.TotalAuthenticationAttempts = authn.Status.TotalAuthenticationAttempts + 1

	challengeReqBytes, err := pbutils.Marshal(ret.Response.ChallengeRequest)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	encryptedChallengeRequest, err := authenticators.EncryptData(ctx, s.octeliumC, challengeReqBytes)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	authn.Status.AuthenticationAttempt.EncryptedChallengeRequest = encryptedChallengeRequest

	_, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	return ret.Response, nil
}

func (s *server) validatePreChallenge(req *authv1.RegisterAuthenticatorBeginRequest_PreChallenge) error {
	if req == nil {
		return nil
	}

	checkBytes := func(arg []byte, fieldName string) error {
		argLen := len(arg)
		if argLen == 0 {
			return s.errInvalidArg("Empty %s", fieldName)
		}
		if argLen > 3000 {
			return s.errInvalidArg("Invalid %s", fieldName)
		}
		return nil
	}
	if req.GetTpm() != nil {
		arg := req.GetTpm()
		if err := checkBytes(arg.AkBytes, "akBytes"); err != nil {
			return err
		}
		if len(arg.GetEkCertificateDER()) == 0 && len(arg.GetEkPublicKey()) == 0 {
			return s.errInvalidArg("Either an ekCert or ekPubKey must be provided")
		}

		if arg.GetEkCertificateDER() != nil {
			if err := checkBytes(arg.GetEkCertificateDER(), "ekCert"); err != nil {
				return err
			}
		}

		if arg.GetEkPublicKey() != nil {
			if err := checkBytes(arg.GetEkPublicKey(), "ekCert"); err != nil {
				return err
			}
		}

		if arg.AttestationParameters == nil {
			return s.errInvalidArg("Nil attestationParams")
		}

		if err := checkBytes(arg.AttestationParameters.Public, "public"); err != nil {
			return err
		}
		if err := checkBytes(arg.AttestationParameters.CreateAttestation, "createAttestation"); err != nil {
			return err
		}
		if err := checkBytes(arg.AttestationParameters.CreateData, "createData"); err != nil {
			return err
		}
		if err := checkBytes(arg.AttestationParameters.CreateSignature, "createSignature"); err != nil {
			return err
		}
	}

	return nil
}

func (s *server) doRegisterAuthenticatorBegin(ctx context.Context,
	req *authv1.RegisterAuthenticatorBeginRequest) (*authv1.RegisterAuthenticatorBeginResponse, error) {

	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.checkSessionValid(sess); err != nil {
		return nil, err
	}

	switch sess.Status.AuthenticatorAction {
	case corev1.Session_Status_AUTHENTICATION_REQUIRED:
		return nil, s.errPermissionDenied("Cannot modify Authenticators")
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	if err := s.validatePreChallenge(req.PreChallenge); err != nil {
		return nil, err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	authn, err := s.getAuthenticator(ctx, req.AuthenticatorRef, sess)
	if err != nil {
		return nil, err
	}

	var fac authenticators.Factor

	if authn.Status.IsRegistered {
		return nil, s.errInvalidArg("Authenticator already registered")
	}

	authn.Status.AuthenticationAttempt = nil
	authn.Status.LastAuthenticationAttempts = nil

	fac, err = s.getAuthenticatorCtl(ctx, authn, usr, cc)
	if err != nil {
		return nil, err
	}

	authn.Status.AuthenticationAttempt = &corev1.Authenticator_Status_AuthenticationAttempt{
		CreatedAt:        pbutils.Now(),
		SessionRef:       umetav1.GetObjectReference(sess),
		EncryptedDataMap: make(map[string]*corev1.Authenticator_Status_EncryptedData),
		DataMap:          make(map[string][]byte),
	}

	ret, err := fac.BeginRegistration(ctx, &authenticators.BeginRegistrationReq{
		Req: req,
	})
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	challengeReqBytes, err := pbutils.Marshal(ret.Response.ChallengeRequest)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	encryptedChallengeRequest, err := authenticators.EncryptData(ctx, s.octeliumC, challengeReqBytes)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	authn.Status.AuthenticationAttempt.EncryptedChallengeRequest = encryptedChallengeRequest

	_, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	return ret.Response, nil
}

func (s *server) getAuthenticatorCtl(ctx context.Context,
	authn *corev1.Authenticator, usr *corev1.User,
	cc *corev1.ClusterConfig) (authenticators.Factor, error) {

	opts := &authenticators.Opts{
		User:          usr,
		Authenticator: authn,
		OcteliumC:     s.octeliumC,
		ClusterConfig: cc,
	}

	var ret authenticators.Factor
	var err error
	switch authn.Status.Type {
	case corev1.Authenticator_Status_FIDO:
		ret, err = fido.NewFactor(ctx, opts, s.mdsProvider)
	case corev1.Authenticator_Status_TOTP:
		ret, err = totp.NewFactor(ctx, opts)
	case corev1.Authenticator_Status_TPM:
		ret, err = tpm.NewFactor(ctx, opts)
	default:
		return nil, s.errInvalidArg("Unknown factor type")
	}

	if err != nil {
		return nil, s.errInvalidArg("Could not create authenticator ctl")
	}

	return ret, nil
}

func (s *server) checkAuthenticatorRateLimit(ctx context.Context, authn *corev1.Authenticator) error {

	type rateLimit struct {
		window *metav1.Duration
		limit  int64
		key    string
	}

	rateLimits := []*rateLimit{
		{
			key: fmt.Sprintf("octelium:authn:1:%s", authn.Metadata.Uid),
			window: &metav1.Duration{
				Type: &metav1.Duration_Minutes{
					Minutes: 3,
				},
			},
			limit: 20,
		},
		{
			key: fmt.Sprintf("octelium:authn:2:%s", authn.Metadata.Uid),
			window: &metav1.Duration{
				Type: &metav1.Duration_Minutes{
					Minutes: 60,
				},
			},
			limit: 100,
		},
	}

	for _, rl := range rateLimits {
		res, err := s.octeliumC.RateLimitC().CheckSlidingWindow(ctx,
			&rratelimitv1.CheckSlidingWindowRequest{
				Key:    []byte(rl.key),
				Window: rl.window,
				Limit:  rl.limit,
			})
		if err != nil {
			return s.errInternalErr(err)
		}

		if !res.IsAllowed {
			return s.errInvalidArg("Authenticator rate limit exceeded")
		}
	}

	return nil
}

func (s *server) doRegisterAuthenticatorFinish(ctx context.Context,
	req *authv1.RegisterAuthenticatorFinishRequest) (*authv1.RegisterAuthenticatorFinishResponse, error) {
	var err error

	if req.ChallengeResponse == nil {
		return nil, s.errInvalidArg("Nil Authenticator response")
	}

	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.validateChallengeResponse(req.ChallengeResponse); err != nil {
		return nil, err
	}

	if err := s.checkSessionValid(sess); err != nil {
		return nil, err
	}

	usr, err := s.getUserFromSession(ctx, sess)
	if err != nil {
		return nil, err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	authn, err := s.getAuthenticator(ctx, req.AuthenticatorRef, sess)
	if err != nil {
		return nil, err
	}

	nullifyCurrAndUpdate := func() error {
		authn.Status.AuthenticationAttempt = nil
		authn, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
		if err != nil {
			return s.errInternalErr(err)
		}
		return nil
	}

	if authn.Status.AuthenticationAttempt == nil ||
		authn.Status.AuthenticationAttempt.SessionRef == nil {
		return nil, s.errPermissionDenied("No valid current authentication attempt")
	}

	if authn.Status.AuthenticationAttempt.SessionRef.Uid != sess.Metadata.Uid {
		return nil, s.errPermissionDenied("No valid current authentication attempt")
	}

	if authn.Status.IsRegistered {
		return nil, s.errInvalidArg("Authenticator is already registered")
	}

	if s.isAuthenticationAttemptTimeoutExceeded(authn) {
		if err := nullifyCurrAndUpdate(); err != nil {
			return nil, err
		}

		return nil, s.errPermissionDenied("No valid current authentication attempt")
	}

	if authn.Status.AuthenticationAttempt == nil ||
		!authn.Status.AuthenticationAttempt.CreatedAt.IsValid() ||
		authn.Status.AuthenticationAttempt.EncryptedChallengeRequest == nil {
		return nil, s.errInternal("Nil AuthenticationAttempt")
	}

	challengeReqBytes, err := authenticators.DecryptData(ctx,
		s.octeliumC, authn.Status.AuthenticationAttempt.EncryptedChallengeRequest)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	challengeReq := &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest{}
	if err := pbutils.Unmarshal(challengeReqBytes, challengeReq); err != nil {
		return nil, s.errInternalErr(err)
	}

	var factor authenticators.Factor

	switch challengeReq.Type.(type) {

	case *authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_Fido:
		if req.ChallengeResponse.GetFido() == nil {
			return nil, s.errInvalidArg("Mismatch auth factor type")
		}
		if authn.Status.Type != corev1.Authenticator_Status_FIDO {
			return nil, s.errInvalidArg("Invalid Authenticator type")
		}

	case *authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_Totp:
		if req.ChallengeResponse.GetTotp() == nil {
			return nil, s.errInvalidArg("Mismatch auth factor type")
		}
		if authn.Status.Type != corev1.Authenticator_Status_TOTP {
			return nil, s.errInvalidArg("Invalid Authenticator type")
		}

	case *authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_Tpm:
		if req.ChallengeResponse.GetTpm() == nil {
			return nil, s.errInvalidArg("Mismatch auth factor type")
		}
		if authn.Status.Type != corev1.Authenticator_Status_TPM {
			return nil, s.errInvalidArg("Invalid Authenticator type")
		}
	default:
		return nil, s.errInvalidArg("Invalid challengeRequest type")
	}

	factor, err = s.getAuthenticatorCtl(ctx, authn, usr, cc)
	if err != nil {
		return nil, err
	}

	if _, err := factor.FinishRegistration(ctx, &authenticators.FinishRegistrationReq{
		Resp:             req,
		ChallengeRequest: challengeReq,
	}); err != nil {
		nullifyCurrAndUpdate()
		if authenticators.IsErrInvalidAuth(err) {
			return nil, s.errPermissionDenied("Invalid registration")
		}
		return nil, s.errInternalErr(err)
	}

	authn.Status.AuthenticationAttempt = nil
	authn.Status.IsRegistered = true
	authn.Status.DeviceRef = sess.Status.DeviceRef

	switch sess.Status.AuthenticatorAction {
	case corev1.Session_Status_REGISTRATION_RECOMMENDED,
		corev1.Session_Status_REGISTRATION_REQUIRED:
		sess, err = s.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: sess.Metadata.Uid,
		})
		if err != nil {
			return nil, s.errInternalErr(err)
		}

		sess.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET
		_, err = s.octeliumC.CoreC().UpdateSession(ctx, sess)
		if err != nil {
			return nil, s.errInternalErr(err)
		}
	}

	authn, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	return &authv1.RegisterAuthenticatorFinishResponse{}, nil
}

func (s *server) isAuthenticationAttemptTimeoutExceeded(authn *corev1.Authenticator) bool {
	return authn.Status.AuthenticationAttempt.CreatedAt.AsTime().Before(time.Now().Add(-20 * time.Minute))
}

func (s *server) validateChallengeResponse(req *authv1.ChallengeResponse) error {
	if req == nil {
		return s.errInvalidArg("Nil Response")
	}

	switch req.Type.(type) {

	case *authv1.ChallengeResponse_Totp:
		if req.GetTotp().Response == "" {
			return s.errInvalidArg("Empty TOTP response")
		}

		if len(strings.TrimSpace(req.GetTotp().Response)) > 16 {
			return s.errInvalidArg("Invalid TOTP response")
		}
	case *authv1.ChallengeResponse_Fido:
		if req.GetFido().Response == "" {
			return s.errInvalidArg("Empty FIDO response")
		}

		if len(req.GetFido().Response) > 30000 {
			return s.errInvalidArg("Response is too long")
		}
	case *authv1.ChallengeResponse_Tpm:
		respLen := len(req.GetTpm().Response)
		if respLen < 8 || respLen > 256 {
			return s.errInvalidArg("Invalid response")
		}
	default:
		return s.errInvalidArg("Invalid authenticator response")
	}

	return nil
}

func (s *server) prependToLastAttempts(a *corev1.Authenticator) {

	if a.Status.AuthenticationAttempt == nil {
		return
	}

	maxLen := 10

	if len(a.Status.LastAuthenticationAttempts) >= maxLen {
		a.Status.LastAuthenticationAttempts = a.Status.LastAuthenticationAttempts[:maxLen-2]
	}

	a.Status.LastAuthenticationAttempts = append([]*corev1.Authenticator_Status_AuthenticationAttempt{
		a.Status.AuthenticationAttempt,
	}, a.Status.LastAuthenticationAttempts...)

	a.Status.AuthenticationAttempt = nil

	for _, itm := range a.Status.LastAuthenticationAttempts {
		itm.DataMap = nil
		itm.EncryptedChallengeRequest = nil
		itm.EncryptedDataMap = nil
	}
}
