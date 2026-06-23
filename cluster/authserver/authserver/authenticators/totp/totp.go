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

package totp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils"
	"github.com/pquerna/otp"
	otptotp "github.com/pquerna/otp/totp"
	"go.uber.org/zap"
)

const (
	defaultPeriodSeconds uint = 30
	defaultSkew          uint = 1
	defaultDigits             = 6
)

type TOTPFactor struct {
	cc *corev1.ClusterConfig

	octeliumC octeliumc.ClientInterface
	opts      *authenticators.Opts
}

func NewFactor(ctx context.Context, o *authenticators.Opts) (*TOTPFactor, error) {
	return &TOTPFactor{
		cc:        o.ClusterConfig,
		octeliumC: o.OcteliumC,
		opts:      o,
	}, nil
}

func (c *TOTPFactor) Begin(ctx context.Context, req *authenticators.BeginReq) (*authenticators.BeginResp, error) {
	return &authenticators.BeginResp{
		Response: &authv1.AuthenticateAuthenticatorBeginResponse{
			ChallengeRequest: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest{
				Type: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_Totp{
					Totp: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_TOTP{},
				},
			},
		},
	}, nil
}

func (c *TOTPFactor) Finish(ctx context.Context, reqCtx *authenticators.FinishReq) (*authenticators.FinishResp, error) {
	resp := reqCtx.Resp
	authn := c.opts.Authenticator

	if resp == nil {
		return nil, authenticators.ErrInvalidAuthMsg("Nil response")
	}

	if resp.ChallengeResponse == nil || resp.ChallengeResponse.GetTotp() == nil {
		return nil, authenticators.ErrInvalidAuthMsg("Response is not TOTP")
	}

	if authn == nil || authn.Status.Info == nil || authn.Status.Info.GetTotp() == nil {
		return nil, authenticators.ErrInvalidAuthMsg("Invalid req...")
	}

	totpInfo := authn.Status.Info.GetTotp()
	if totpInfo.GetSharedSecret() == nil {
		return nil, authenticators.ErrInvalidAuthMsg("Invalid TOTP authenticator")
	}

	zap.L().Debug("Getting TOTP secret from User auth factor state")

	secretBytes, err := authenticators.DecryptData(ctx, c.octeliumC, totpInfo.GetSharedSecret())
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	matchedStep, isValid, err := validateAndGetAcceptedTimeStep(
		strings.TrimSpace(resp.ChallengeResponse.GetTotp().Response),
		string(secretBytes),
		now,
		getValidateOpts(totpInfo),
	)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, authenticators.ErrInvalidAuthMsg("Invalid code")
	}

	if matchedStep <= totpInfo.GetLastAcceptedTimeStep() {
		return nil, authenticators.ErrInvalidAuthMsg("TOTP code already used")
	}

	totpInfo.LastAcceptedTimeStep = matchedStep
	totpInfo.LastAcceptedAt = pbutils.Timestamp(now)

	return &authenticators.FinishResp{}, nil
}

func (c *TOTPFactor) BeginRegistration(ctx context.Context, req *authenticators.BeginRegistrationReq) (*authenticators.BeginRegistrationResp, error) {
	authn := c.opts.Authenticator

	k, err := otptotp.Generate(otptotp.GenerateOpts{
		Issuer:      fmt.Sprintf("Octelium - %s", c.cc.Status.Domain),
		AccountName: authenticators.GetDisplayName(authn, c.opts.User),
		Period:      defaultPeriodSeconds,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, err
	}

	sharedSecret, err := authenticators.EncryptData(ctx, c.octeliumC, []byte(k.Secret()))
	if err != nil {
		return nil, err
	}

	authn.Status.Info = &corev1.Authenticator_Status_Info{
		Type: &corev1.Authenticator_Status_Info_Totp{
			Totp: &corev1.Authenticator_Status_Info_TOTP{
				SharedSecret:  sharedSecret,
				PeriodSeconds: uint32(defaultPeriodSeconds),
				Digits:        defaultDigits,
				Algorithm:     corev1.Authenticator_Status_Info_TOTP_SHA1,
			},
		},
	}

	return &authenticators.BeginRegistrationResp{
		Response: &authv1.RegisterAuthenticatorBeginResponse{
			ChallengeRequest: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest{
				Type: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_Totp{
					Totp: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_TOTP{
						Url: k.URL(),
					},
				},
			},
		},
	}, nil
}

func (c *TOTPFactor) FinishRegistration(ctx context.Context, reqCtx *authenticators.FinishRegistrationReq) (*authenticators.FinishRegistrationResp, error) {
	if _, err := c.Finish(ctx, &authenticators.FinishReq{
		Resp: &authv1.AuthenticateWithAuthenticatorRequest{
			AuthenticatorRef:  reqCtx.Resp.AuthenticatorRef,
			ChallengeResponse: reqCtx.Resp.ChallengeResponse,
		},
		ChallengeRequest: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest{
			Type: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_Totp{
				Totp: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_TOTP{},
			},
		},
	}); err != nil {
		return nil, err
	}

	return &authenticators.FinishRegistrationResp{}, nil
}

func validateAndGetAcceptedTimeStep(
	passcode string,
	secret string,
	now time.Time,
	opts otptotp.ValidateOpts,
) (uint64, bool, error) {
	if passcode == "" {
		return 0, false, nil
	}

	if opts.Period == 0 {
		opts.Period = defaultPeriodSeconds
	}

	currentStep := now.Unix() / int64(opts.Period)

	optsNoSkew := opts
	optsNoSkew.Skew = 0

	var matchedStep int64 = -1

	for delta := -int64(opts.Skew); delta <= int64(opts.Skew); delta++ {
		step := currentStep + delta
		if step < 0 {
			continue
		}

		stepTime := time.Unix(step*int64(opts.Period), 0).UTC()

		expected, err := otptotp.GenerateCodeCustom(secret, stepTime, optsNoSkew)
		if err != nil {
			return 0, false, err
		}

		if utils.SecureBytesEqual([]byte(expected), []byte(passcode)) {
			if step > matchedStep {
				matchedStep = step
			}
		}
	}

	if matchedStep < 0 {
		return 0, false, nil
	}

	return uint64(matchedStep), true, nil
}

func getValidateOpts(info *corev1.Authenticator_Status_Info_TOTP) otptotp.ValidateOpts {
	return otptotp.ValidateOpts{
		Period:    getPeriodSeconds(info),
		Skew:      defaultSkew,
		Digits:    getDigits(info),
		Algorithm: getAlgorithm(info),
	}
}

func getPeriodSeconds(info *corev1.Authenticator_Status_Info_TOTP) uint {
	if info == nil || info.GetPeriodSeconds() == 0 {
		return defaultPeriodSeconds
	}

	return uint(info.GetPeriodSeconds())
}

func getDigits(info *corev1.Authenticator_Status_Info_TOTP) otp.Digits {
	if info == nil {
		return otp.DigitsSix
	}

	switch info.GetDigits() {
	case 8:
		return otp.DigitsEight
	default:
		return otp.DigitsSix
	}
}

func getAlgorithm(info *corev1.Authenticator_Status_Info_TOTP) otp.Algorithm {
	if info == nil {
		return otp.AlgorithmSHA1
	}

	switch info.GetAlgorithm() {
	case corev1.Authenticator_Status_Info_TOTP_SHA256:
		return otp.AlgorithmSHA256
	case corev1.Authenticator_Status_Info_TOTP_SHA512:
		return otp.AlgorithmSHA512
	default:
		return otp.AlgorithmSHA1
	}
}
