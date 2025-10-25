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

package fido

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	factors "github.com/octelium/octelium/cluster/authserver/authserver/authenticators"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type WebAuthNFactor struct {
	cc *corev1.ClusterConfig

	octeliumC octeliumc.ClientInterface
	opts      *factors.Opts
	mds       metadata.Provider
}

func NewFactor(ctx context.Context, o *factors.Opts, mds metadata.Provider) (*WebAuthNFactor, error) {
	return &WebAuthNFactor{
		cc: o.ClusterConfig,

		octeliumC: o.OcteliumC,
		opts:      o,
		mds:       mds,
	}, nil
}

func (c *WebAuthNFactor) Begin(ctx context.Context, req *factors.BeginReq) (*factors.BeginResp, error) {

	webauthnctl, err := c.getWebauthnCtl(c.opts.Authenticator)
	if err != nil {
		return nil, err
	}

	webauthnUsr := NewWebAuthnUsr(c.opts.Authenticator, c.opts.User)
	authn := c.opts.Authenticator

	if authn.Status.AuthenticationAttempt.DataMap == nil {
		authn.Status.AuthenticationAttempt.DataMap = make(map[string][]byte)
	}

	assertion, sessData, err := webauthnctl.BeginLogin(webauthnUsr)
	if err != nil {
		return nil, err
	}

	authn.Status.AuthenticationAttempt.DataMap["session"], err = json.Marshal(sessData)
	if err != nil {
		return nil, err
	}

	requestOptsBytes, err := json.Marshal(assertion.Response)
	if err != nil {
		return nil, err
	}

	ret := &authv1.AuthenticateAuthenticatorBeginResponse{

		ChallengeRequest: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest{
			Type: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_Fido{
				Fido: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest_FIDO{
					Request: string(requestOptsBytes),
				},
			},
		},
	}

	return &factors.BeginResp{
		Response: ret,
	}, nil
}

func (c *WebAuthNFactor) getWebauthnCtl(authn *corev1.Authenticator) (*webauthn.WebAuthn, error) {
	var authenticatorAttachment protocol.AuthenticatorAttachment

	if authn.Status.IsRegistered && authn.Status.GetInfo() != nil &&
		authn.Status.GetInfo().GetFido() != nil {
		switch authn.Status.GetInfo().GetFido().Type {
		case corev1.Authenticator_Status_Info_FIDO_PLATFORM:
			authenticatorAttachment = protocol.Platform
		case corev1.Authenticator_Status_Info_FIDO_ROAMING:
			authenticatorAttachment = protocol.CrossPlatform
		}
	}

	return webauthn.New(&webauthn.Config{
		RPDisplayName: "Octelium",
		RPID:          c.cc.Status.Domain,
		Debug:         ldflags.IsDev(),
		RPOrigins:     []string{fmt.Sprintf("https://%s", c.cc.Status.Domain)},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        DefaultTimeout(),
			Registration: DefaultTimeout(),
		},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: authenticatorAttachment,

			UserVerification: protocol.VerificationPreferred,
		},
		AttestationPreference: protocol.PreferDirectAttestation,
		MDS:                   c.mds,
	})
}

func (c *WebAuthNFactor) Finish(ctx context.Context, reqCtx *factors.FinishReq) (*authenticators.FinishResp, error) {

	resp := reqCtx.Resp
	authn := c.opts.Authenticator

	ret := &authenticators.FinishResp{}

	if resp == nil || resp.ChallengeResponse == nil || resp.ChallengeResponse.GetFido() == nil ||
		resp.ChallengeResponse.GetFido().Response == "" {
		return nil, authenticators.ErrInvalidAuthMsg("Invalid Response")
	}

	webauthnctl, err := c.getWebauthnCtl(authn)
	if err != nil {
		return nil, err
	}

	webauthnUsr := NewWebAuthnUsr(authn, c.opts.User)

	if authn.Status.AuthenticationAttempt == nil || authn.Status.AuthenticationAttempt.DataMap == nil {
		return nil, authenticators.ErrInvalidAuthMsg("No authenticationAttempt dataMap")
	}

	sessData := &webauthn.SessionData{}
	if err := json.Unmarshal(authn.Status.AuthenticationAttempt.DataMap["session"], sessData); err != nil {
		return nil, err
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(
		strings.NewReader(resp.ChallengeResponse.GetFido().Response))
	if err != nil {
		return nil, authenticators.ErrInvalidAuth(err)
	}

	cred, err := webauthnctl.ValidateLogin(webauthnUsr, *sessData, parsedResponse)
	if err != nil {
		return nil, authenticators.ErrInvalidAuth(err)
	}

	if sessData.UserVerification == protocol.VerificationRequired && !cred.Flags.UserVerified {
		return nil, authenticators.ErrInvalidAuthMsg("User is not verified")
	}

	zap.L().Debug("webauthn login successful", zap.Any("cred", cred))

	ret.Cred = cred

	return ret, nil
}

func NewWebAuthnUsr(authn *corev1.Authenticator, usr *corev1.User) *WebauthnUser {
	return &WebauthnUser{
		authn: authn,
		usr:   usr,
	}
}

type WebauthnUser struct {
	authn *corev1.Authenticator
	usr   *corev1.User
}

func (u *WebauthnUser) WebAuthnID() []byte {
	uid, _ := uuid.Parse(u.usr.Metadata.Uid)
	return uid[:]
}

func (u *WebauthnUser) WebAuthnName() string {
	if u.usr.Spec.Email != "" {
		return strings.ToLower(u.usr.Spec.Email)
	}
	return u.usr.Metadata.Name
}

func (u *WebauthnUser) WebAuthnDisplayName() string {
	if u.authn.Spec.DisplayName != "" {
		return u.authn.Spec.DisplayName
	}
	return ""
}

func (u *WebauthnUser) WebAuthnIcon() string {
	return ""
}

func (u *WebauthnUser) WebAuthnCredentials() []webauthn.Credential {

	if u.authn.Status.Info == nil || u.authn.Status.Info.GetFido() == nil {
		return nil
	}

	fido := u.authn.Status.Info.GetFido()

	aaguid, _ := uuid.Parse(fido.Aaguid)

	return []webauthn.Credential{
		{
			ID:        fido.Id,
			PublicKey: fido.PublicKey,
			Flags: webauthn.CredentialFlags{
				BackupEligible: fido.BackupEligible,
			},
			AttestationType: func() string {

				/*
					if fido.IsAttestationVerified {
						return ""
					}
				*/

				// Skip MDS attestation verification in authentication ceremony
				return "none"
			}(),
			Authenticator: webauthn.Authenticator{
				AAGUID: aaguid[:],
			},
		},
	}

}

func (c *WebAuthNFactor) BeginRegistration(ctx context.Context,
	req *factors.BeginRegistrationReq) (*factors.BeginRegistrationResp, error) {
	webauthnctl, err := c.getWebauthnCtl(c.opts.Authenticator)
	if err != nil {
		return nil, err
	}

	webauthnUsr := NewWebAuthnUsr(c.opts.Authenticator, c.opts.User)
	authn := c.opts.Authenticator

	if authn.Status.AuthenticationAttempt.DataMap == nil {
		authn.Status.AuthenticationAttempt.DataMap = make(map[string][]byte)
	}

	creation, sessData, err := webauthnctl.BeginRegistration(webauthnUsr,
		webauthn.WithCredentialParameters([]protocol.CredentialParameter{
			{
				Type:      protocol.PublicKeyCredentialType,
				Algorithm: webauthncose.AlgEdDSA,
			},
			{
				Type:      protocol.PublicKeyCredentialType,
				Algorithm: webauthncose.AlgES256,
			},
			{
				Type:      protocol.PublicKeyCredentialType,
				Algorithm: webauthncose.AlgRS256,
			},
		}),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithExtensions(protocol.AuthenticationExtensions{
			"credProps": true,
		}))
	if err != nil {
		return nil, err
	}

	authn.Status.AuthenticationAttempt.DataMap["session"], err = json.Marshal(sessData)
	if err != nil {
		return nil, err
	}

	createOptsBytes, err := json.Marshal(creation.Response)
	if err != nil {
		return nil, err
	}

	ret := &authv1.RegisterAuthenticatorBeginResponse{

		ChallengeRequest: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest{
			Type: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_Fido{
				Fido: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_FIDO{
					Request: string(createOptsBytes),
				},
			},
		},
	}

	return &factors.BeginRegistrationResp{
		Response: ret,
	}, nil
}

func (c *WebAuthNFactor) FinishRegistration(ctx context.Context,
	reqCtx *factors.FinishRegistrationReq) (*authenticators.FinishRegistrationResp, error) {

	resp := reqCtx.Resp
	authn := c.opts.Authenticator

	if resp == nil || resp.ChallengeResponse == nil || resp.ChallengeResponse.GetFido() == nil ||
		resp.ChallengeResponse.GetFido().Response == "" {
		return nil, authenticators.ErrInvalidAuthMsg("Invalid Response")
	}

	webauthnctl, err := c.getWebauthnCtl(authn)
	if err != nil {
		return nil, err
	}

	webauthnUsr := NewWebAuthnUsr(authn, c.opts.User)

	if authn.Status.AuthenticationAttempt.DataMap == nil {
		return nil, errors.Errorf("No authenticationAttempt dataMap")
	}

	sessData := &webauthn.SessionData{}
	if err := json.Unmarshal(authn.Status.AuthenticationAttempt.DataMap["session"], sessData); err != nil {
		return nil, err
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(
		strings.NewReader(resp.ChallengeResponse.GetFido().Response))
	if err != nil {
		return nil, authenticators.ErrInvalidAuth(err)
	}

	cred, err := webauthnctl.CreateCredential(webauthnUsr, *sessData, parsedResponse)
	if err != nil {
		return nil, authenticators.ErrInvalidAuth(err)
	}

	zap.L().Debug("Successful CreateCredential", zap.Any("cred", cred))

	if sessData.UserVerification == protocol.VerificationRequired && !cred.Flags.UserVerified {
		return nil, authenticators.ErrInvalidAuthMsg("User is not verified")
	}

	idHash := vutils.Sha256Sum(cred.ID)

	{
		authnList, err := c.octeliumC.CoreC().ListAuthenticator(ctx, &rmetav1.ListOptions{
			Filters: []*rmetav1.ListOptions_Filter{
				urscsrv.FilterFieldEQValStr("status.info.webauthn.idHash",
					base64.StdEncoding.EncodeToString(idHash)),
			},
		})
		if err != nil {
			return nil, err
		}

		if len(authnList.Items) > 0 {
			return nil, authenticators.ErrInvalidAuthMsg("Invalid credential ID")
		}
	}

	var isResidentKey bool
	if parsedResponse.ClientExtensionResults != nil {
		if credProps, ok := parsedResponse.ClientExtensionResults["credProps"].(map[string]any); ok {
			isResidentKey = credProps["rk"].(bool)
		}
	}

	aaguid, err := uuid.FromBytes(cred.Authenticator.AAGUID)
	if err != nil {
		return nil, authenticators.ErrInvalidAuthMsg("Invalid AAGUID")
	}

	authn.Status.Info = &corev1.Authenticator_Status_Info{
		Type: &corev1.Authenticator_Status_Info_Fido{
			Fido: &corev1.Authenticator_Status_Info_FIDO{
				Id:             cred.ID,
				IdHash:         idHash,
				PublicKey:      cred.PublicKey,
				BackupEligible: cred.Flags.BackupEligible,
				Aaguid:         aaguid.String(),
				IsPasskey:      isResidentKey,
				Type: func() corev1.Authenticator_Status_Info_FIDO_Type {
					switch cred.Authenticator.Attachment {
					case protocol.Platform:
						return corev1.Authenticator_Status_Info_FIDO_PLATFORM
					case protocol.CrossPlatform:
						return corev1.Authenticator_Status_Info_FIDO_ROAMING
					}
					return corev1.Authenticator_Status_Info_FIDO_TYPE_UNKNOWN
				}(),
				IsAttestationVerified: func() bool {
					switch parsedResponse.Response.AttestationObject.Format {
					case "none":
						return false
					default:
						if c.mds != nil {
							if err := cred.Verify(c.mds); err == nil {
								return true
							} else {
								zap.L().Debug("Could not verify attestation", zap.Error(err))
							}
						}

						return false
					}
				}(),
			},
		},
	}

	if c.mds != nil {
		if entry, err := c.mds.GetEntry(ctx, aaguid); err == nil && entry != nil {
			zap.L().Debug("Found mds entry", zap.Any("entry", entry))
			authn.Status.Description = entry.MetadataStatement.Description

			fido := authn.Status.Info.GetFido()
			keyProtection := entry.MetadataStatement.KeyProtection

			fido.IsSoftware = slices.Contains(keyProtection, "software")
			fido.IsHardware = (slices.Contains(keyProtection, "hardware") &&
				slices.Contains(keyProtection, "secure_element")) ||
				(slices.Contains(keyProtection, "hardware") &&
					slices.Contains(keyProtection, "tee"))
		} else if err != nil {
			zap.L().Debug("Could not get MDS entry",
				zap.String("aaguid", aaguid.String()), zap.Error(err))
		}
	}

	return &authenticators.FinishRegistrationResp{}, nil
}

func DefaultTimeout() webauthn.TimeoutConfig {
	return webauthn.TimeoutConfig{
		Enforce:    true,
		Timeout:    120 * time.Second,
		TimeoutUVD: 120 * time.Second,
	}
}
