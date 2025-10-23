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

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
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

	var err error

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

	zap.L().Debug("Getting TOTP secret from User auth factor state")

	secretBytes, err := authenticators.DecryptData(ctx, c.octeliumC, authn.Status.Info.GetTotp().GetSharedSecret())
	if err != nil {
		return nil, err
	}

	isValid := totp.Validate(resp.ChallengeResponse.GetTotp().Response, string(secretBytes))
	if !isValid {
		return nil, authenticators.ErrInvalidAuthMsg("Invalid code")
	}

	return &authenticators.FinishResp{}, nil
}

func (c *TOTPFactor) BeginRegistration(ctx context.Context, req *authenticators.BeginRegistrationReq) (*authenticators.BeginRegistrationResp, error) {

	authn := c.opts.Authenticator

	k, err := totp.Generate(totp.GenerateOpts{
		Issuer:      fmt.Sprintf("Octelium - %s", c.cc.Status.Domain),
		AccountName: authenticators.GetDisplayName(authn, c.opts.User),
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
				SharedSecret: sharedSecret,
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
