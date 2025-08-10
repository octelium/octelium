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
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators/totp"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators/tpm"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators/vwebauthn"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
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

	nullifyCurrAndUpdate := func() error {
		ucorev1.ToAuthenticator(authn).PrependToLastAttempts()
		authn, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
		if err != nil {
			return s.errInternalErr(err)
		}
		return nil
	}

	if authn.Status.AuthenticationAttempt == nil ||
		authn.Status.AuthenticationAttempt.SessionRef == nil {
		return nil, s.errPermissionDenied("No valid current authentication attempt...")
	}

	if authn.Status.AuthenticationAttempt.SessionRef.Uid != sess.Metadata.Uid {
		return nil, s.errPermissionDenied("No valid current authentication attempt")
	}

	if authn.Status.AuthenticationAttempt.CreatedAt.AsTime().
		Add(-60 * time.Second).After(time.Now()) {

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

	challengeReqBytes, err := authenticators.DecryptData(ctx, s.octeliumC, authn.Status.AuthenticationAttempt.EncryptedChallengeRequest)
	if err != nil {
		return nil, err
	}

	challengeReq := &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest{}
	if err := pbutils.Unmarshal(challengeReqBytes, challengeReq); err != nil {
		return nil, err
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

	if err := factor.Finish(ctx, &authenticators.FinishReq{
		Resp:             resp,
		ChallengeRequest: challengeReq,
	}); err != nil {
		authn.Status.FailedAuthentications = authn.Status.FailedAuthentications + 1
		if err := nullifyCurrAndUpdate(); err != nil {
			return nil, err
		}
		return nil, err
	}

	authn.Status.SuccessfulAuthentications = authn.Status.SuccessfulAuthentications + 1
	if err := nullifyCurrAndUpdate(); err != nil {
		return nil, err
	}

	return &corev1.Session_Status_Authentication_Info{
		Type: corev1.Session_Status_Authentication_Info_AUTHENTICATOR,
		Details: &corev1.Session_Status_Authentication_Info_Authenticator_{
			Authenticator: &corev1.Session_Status_Authentication_Info_Authenticator{
				AuthenticatorRef: umetav1.GetObjectReference(authn),
				Type:             authn.Status.Type,
			},
		},
	}, nil
}

func (s *server) getAuthenticator(ctx context.Context, authnRef *metav1.ObjectReference, sess *corev1.Session) (*corev1.Authenticator, error) {

	if err := apivalidation.CheckObjectRef(authnRef, &apivalidation.CheckGetOptionsOpts{}); err != nil {
		return nil, s.errInvalidArgErr(err)
	}
	authn, err := s.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
		Uid:  authnRef.Uid,
		Name: authnRef.Name,
	})
	if err != nil {
		if grpcerr.IsNotFound(err) {
			return nil, s.errInvalidArgErr(err)
		}
		return nil, s.errInternalErr(err)
	}

	if authn.Status.UserRef == nil {
		return nil, s.errInternal("Nil Authenticator UserRef")
	}
	if authn.Status.UserRef.Uid != sess.Status.UserRef.Uid {
		return nil, s.errInvalidArg("Authenticator does not belong to the User")
	}

	return authn, nil
}

func (s *server) doAuthenticateAuthenticatorBegin(ctx context.Context, req *authv1.AuthenticateAuthenticatorBeginRequest) (*authv1.AuthenticateAuthenticatorBeginResponse, error) {
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

	if authn.Status.AuthenticationAttempt != nil {

		if authn.Status.AuthenticationAttempt.CreatedAt.AsTime().Add(2 * time.Second).After(time.Now()) {
			ucorev1.ToAuthenticator(authn).PrependToLastAttempts()
			_, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
			if err != nil {
				return nil, err
			}

			return nil, errors.Errorf("Authenticator rate limit exceeded")
		}

		ucorev1.ToAuthenticator(authn).PrependToLastAttempts()
	}

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
		return nil, err
	}

	authn.Status.TotalAuthenticationAttempts = authn.Status.TotalAuthenticationAttempts + 1

	challengeReqBytes, err := pbutils.Marshal(ret.Response.ChallengeRequest)
	if err != nil {
		return nil, err
	}

	encryptedChallengeRequest, err := authenticators.EncryptData(ctx, s.octeliumC, challengeReqBytes)
	if err != nil {
		return nil, err
	}

	authn.Status.AuthenticationAttempt.EncryptedChallengeRequest = encryptedChallengeRequest

	_, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
	if err != nil {
		return nil, err
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

func (s *server) doRegisterAuthenticatorBegin(ctx context.Context, req *authv1.RegisterAuthenticatorBeginRequest) (*authv1.RegisterAuthenticatorBeginResponse, error) {

	sess, err := s.getSessionFromGRPCCtx(ctx)
	if err != nil {
		return nil, err
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
		return nil, errors.Errorf("Authenticator already registered")
	}

	authn.Status.AuthenticationAttempt = nil
	authn.Status.LastAuthenticationAttempts = nil
	/*
		if authn.Status.AuthenticationAttempt != nil {

			if authn.Status.AuthenticationAttempt.CreatedAt.AsTime().Add(2 * time.Second).After(time.Now()) {
				ucorev1.ToAuthenticator(authn).PrependToLastAttempts()
				_, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
				if err != nil {
					return nil, err
				}

				return nil, errors.Errorf("Authenticator rate limit exceeded")
			}

			ucorev1.ToAuthenticator(authn).PrependToLastAttempts()
		}

		if len(authn.Status.LastAuthenticationAttempts) > 0 {
			if authn.Status.LastAuthenticationAttempts[0].CreatedAt.AsTime().Add(2 * time.Second).After(time.Now()) {
				return nil, errors.Errorf("Authenticator rate limit exceeded..")
			}
		}
	*/

	/*
		authFactor, err := s.octeliumC.CoreC().GetIdentityProvider(ctx, &rmetav1.GetOptions{
			Uid: authn.Status.IdentityProviderRef.Uid,
		})
		if err != nil {
			return nil, err
		}
	*/

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
		return nil, err
	}

	// authn.Status.TotalAuthenticationAttempts = authn.Status.TotalAuthenticationAttempts + 1

	challengeReqBytes, err := pbutils.Marshal(ret.Response.ChallengeRequest)
	if err != nil {
		return nil, err
	}

	encryptedChallengeRequest, err := authenticators.EncryptData(ctx, s.octeliumC, challengeReqBytes)
	if err != nil {
		return nil, err
	}

	authn.Status.AuthenticationAttempt.EncryptedChallengeRequest = encryptedChallengeRequest

	_, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
	if err != nil {
		return nil, err
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
	switch authn.Status.Type {
	case corev1.Authenticator_Status_FIDO:
		return vwebauthn.NewFactor(ctx, opts, s.mdsProvider)
	case corev1.Authenticator_Status_TOTP:
		return totp.NewFactor(ctx, opts)
	case corev1.Authenticator_Status_TPM:
		return tpm.NewFactor(ctx, opts)
	default:
		return nil, errors.Errorf("Unknown factor type")
	}
}

func (s *server) doRegisterAuthenticatorFinish(ctx context.Context, req *authv1.RegisterAuthenticatorFinishRequest) (*authv1.RegisterAuthenticatorFinishResponse, error) {
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

	zap.L().Debug("Got Session from creds", zap.Any("sess", sess))

	if !s.needsReAuth(sess) {
		return nil, s.errAlreadyExists("The Session is valid and does not need a authenticatorFinish")
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

	if authn.Status.AuthenticationAttempt.CreatedAt.AsTime().
		Add(-60 * time.Second).After(time.Now()) {

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

	challengeReqBytes, err := authenticators.DecryptData(ctx, s.octeliumC, authn.Status.AuthenticationAttempt.EncryptedChallengeRequest)
	if err != nil {
		return nil, err
	}

	challengeReq := &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest{}
	if err := pbutils.Unmarshal(challengeReqBytes, challengeReq); err != nil {
		return nil, err
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

	if err := factor.FinishRegistration(ctx, &authenticators.FinishRegistrationReq{
		Resp:             req,
		ChallengeRequest: challengeReq,
	}); err != nil {
		if err := nullifyCurrAndUpdate(); err != nil {
			return nil, err
		}
		return nil, err
	}

	authn.Status.AuthenticationAttempt = nil
	authn.Status.IsRegistered = true
	authn.Status.DeviceRef = sess.Status.DeviceRef

	authn, err = s.octeliumC.CoreC().UpdateAuthenticator(ctx, authn)
	if err != nil {
		return nil, s.errInternalErr(err)
	}

	return &authv1.RegisterAuthenticatorFinishResponse{}, nil
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
			return s.errInvalidArg("Empty WebAuthN response")
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
