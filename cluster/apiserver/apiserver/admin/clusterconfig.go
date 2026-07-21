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

package admin

import (
	"context"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	apisrvcommon "github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/pkg/grpcerr"
)

const (
	ccMaxRules             = 256
	ccMaxRuleNameLen       = 128
	ccMaxSessionsPerUser   = 1000
	ccMaxDevicesPerUser    = 1000
	ccMaxDNSServers        = 32
	ccMaxDNSServerLen      = 256
	ccMaxXFFNumTrustedHops = 64
	ccMaxURLLen            = 1024
	ccMaxNameLen           = 256
)

func (s *Server) GetClusterConfig(ctx context.Context, req *corev1.GetClusterConfigRequest) (*corev1.ClusterConfig, error) {
	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return cc, nil
}

func (s *Server) UpdateClusterConfig(ctx context.Context, req *corev1.ClusterConfig) (*corev1.ClusterConfig, error) {

	if err := s.validateClusterConfig(ctx, req); err != nil {
		return nil, err
	}

	cfg, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	apisrvcommon.MetadataUpdate(cfg.Metadata, req.Metadata)
	cfg.Spec = req.Spec

	ccOut, err := s.octeliumC.CoreC().UpdateClusterConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	return ccOut, nil
}

func (s *Server) validateClusterConfig(ctx context.Context, req *corev1.ClusterConfig) error {

	if err := apivalidation.ValidateCommon(req, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{},
	}); err != nil {
		return err
	}

	if req.Spec == nil {
		return grpcutils.InvalidArg("Nil spec")
	}

	if err := s.validateClusterConfigSpec(ctx, req); err != nil {
		return grpcutils.InvalidArgWithErr(err)
	}

	return nil
}

func (s *Server) validateClusterConfigSpec(ctx context.Context, c *corev1.ClusterConfig) error {

	if err := validateSession(c); err != nil {
		return err
	}

	if err := validateCCDevice(c); err != nil {
		return err
	}

	if err := validateIngress(c); err != nil {
		return err
	}

	if err := validateGateway(c); err != nil {
		return err
	}

	if err := validateDNS(c); err != nil {
		return err
	}

	if err := s.validateCCAuthorization(ctx, c); err != nil {
		return err
	}

	if err := s.validateCCAuthenticator(ctx, c); err != nil {
		return err
	}

	if err := s.validateAuthentication(ctx, c); err != nil {
		return err
	}

	return nil
}

func validateSession(c *corev1.ClusterConfig) error {
	if c.Spec.Session == nil {
		return nil
	}

	if human := c.Spec.Session.Human; human != nil {
		if err := apivalidation.ValidateDuration(human.ClientDuration); err != nil {
			return err
		}
		if err := apivalidation.ValidateDuration(human.ClientlessDuration); err != nil {
			return err
		}

		if err := apivalidation.ValidateDuration(human.RefreshTokenDuration); err != nil {
			return err
		}

		if err := apivalidation.ValidateDuration(human.AccessTokenDuration); err != nil {
			return err
		}

		if human.MaxPerUser > ccMaxSessionsPerUser {
			return grpcutils.InvalidArg("Session maxPerUser is too large: %d", human.MaxPerUser)
		}

		if err := validateSessionDefaultState(human.DefaultState); err != nil {
			return err
		}
	}

	if workload := c.Spec.Session.Workload; workload != nil {
		if err := apivalidation.ValidateDuration(workload.ClientDuration); err != nil {
			return err
		}
		if err := apivalidation.ValidateDuration(workload.ClientlessDuration); err != nil {
			return err
		}

		if err := apivalidation.ValidateDuration(workload.RefreshTokenDuration); err != nil {
			return err
		}

		if err := apivalidation.ValidateDuration(workload.AccessTokenDuration); err != nil {
			return err
		}

		if workload.MaxPerUser > ccMaxSessionsPerUser {
			return grpcutils.InvalidArg("Session maxPerUser is too large: %d", workload.MaxPerUser)
		}

		if err := validateSessionDefaultState(workload.DefaultState); err != nil {
			return err
		}
	}

	return nil
}

func validateSessionDefaultState(state corev1.Session_Spec_State) error {
	switch state {
	case corev1.Session_Spec_STATE_UNKNOWN,
		corev1.Session_Spec_ACTIVE,
		corev1.Session_Spec_PENDING:
		return nil
	default:
		return grpcutils.InvalidArg("Invalid Session defaultState: %s", state.String())
	}
}

func validateCCDevice(c *corev1.ClusterConfig) error {
	if c.Spec.Device == nil {
		return nil
	}

	if human := c.Spec.Device.Human; human != nil {
		if human.MaxPerUser > ccMaxDevicesPerUser {
			return grpcutils.InvalidArg("Device maxPerUser is too large: %d", human.MaxPerUser)
		}

		if err := validateDeviceDefaultState(human.DefaultState); err != nil {
			return err
		}
	}

	if workload := c.Spec.Device.Workload; workload != nil {
		if workload.MaxPerUser > ccMaxDevicesPerUser {
			return grpcutils.InvalidArg("Device maxPerUser is too large: %d", workload.MaxPerUser)
		}

		if err := validateDeviceDefaultState(workload.DefaultState); err != nil {
			return err
		}
	}

	return nil
}

func validateDeviceDefaultState(state corev1.Device_Spec_State) error {
	switch state {
	case corev1.Device_Spec_STATE_UNKNOWN,
		corev1.Device_Spec_ACTIVE,
		corev1.Device_Spec_PENDING:
		return nil
	default:
		return grpcutils.InvalidArg("Invalid Device defaultState: %s", state.String())
	}
}

func validateGateway(c *corev1.ClusterConfig) error {
	if c.Spec.Gateway == nil {
		return nil
	}
	if err := apivalidation.ValidateDuration(c.Spec.Gateway.WireguardKeyRotationDuration); err != nil {
		return err
	}

	return nil
}

func (s *Server) validateCCAuthorization(ctx context.Context, c *corev1.ClusterConfig) error {
	if c.Spec.Authorization == nil {
		return nil
	}

	if err := s.validatePolicyOwner(ctx, c.Spec.Authorization); err != nil {
		return err
	}

	return nil
}

func validateDNS(c *corev1.ClusterConfig) error {
	if c.Spec.Dns == nil {
		return nil
	}

	zone := c.Spec.Dns.FallbackZone
	if zone == nil {
		return nil
	}

	if err := apivalidation.ValidateDuration(zone.CacheDuration); err != nil {
		return err
	}

	if len(zone.Servers) > ccMaxDNSServers {
		return grpcutils.InvalidArg("Too many DNS servers")
	}

	for _, srv := range zone.Servers {
		if srv == "" {
			return grpcutils.InvalidArg("Empty DNS server")
		}

		if len(srv) > ccMaxDNSServerLen {
			return grpcutils.InvalidArg("DNS server is too long")
		}

		switch {
		case govalidator.IsDNSName(srv), govalidator.IsIP(srv), govalidator.IsURL(srv):
		default:
			return grpcutils.InvalidArg("Invalid DNS server: %s", srv)
		}
	}

	return nil
}

func (s *Server) validateCCAuthenticator(ctx context.Context, c *corev1.ClusterConfig) error {
	if c.Spec.Authenticator == nil {
		return nil
	}

	cfg := c.Spec.Authenticator

	{
		if len(cfg.AuthenticationEnforcementRules) > ccMaxRules {
			return grpcutils.InvalidArg("Too many AuthenticationRules")
		}

		for _, r := range cfg.AuthenticationEnforcementRules {
			if err := s.validateCCAuthenticatorEnforcementRule(ctx, r); err != nil {
				return err
			}
		}
	}

	{
		if len(cfg.PostAuthenticationRules) > ccMaxRules {
			return grpcutils.InvalidArg("Too many PostAuthenticationRules")
		}

		for _, r := range cfg.PostAuthenticationRules {
			if r == nil {
				return grpcutils.InvalidArg("Nil Rule")
			}

			if len(r.Name) > ccMaxRuleNameLen {
				return grpcutils.InvalidArg("Rule name is too long")
			}

			if err := s.validateCondition(ctx, r.Condition); err != nil {
				return err
			}

			switch r.Effect {
			case corev1.ClusterConfig_Spec_Authenticator_Rule_ALLOW,
				corev1.ClusterConfig_Spec_Authenticator_Rule_DENY:
			default:
				return grpcutils.InvalidArg("Rule effect must be set")
			}
		}
	}

	{
		if len(cfg.RegistrationEnforcementRules) > ccMaxRules {
			return grpcutils.InvalidArg("Too many RegistrationRules")
		}

		for _, r := range cfg.RegistrationEnforcementRules {
			if err := s.validateCCAuthenticatorEnforcementRule(ctx, r); err != nil {
				return err
			}
		}
	}

	if err := validateCCAuthenticatorDefaultState(cfg.DefaultState); err != nil {
		return err
	}

	if err := validateCCAuthenticatorFIDO(cfg.Fido); err != nil {
		return err
	}

	return nil
}

func (s *Server) validateCCAuthenticatorEnforcementRule(ctx context.Context,
	r *corev1.ClusterConfig_Spec_Authenticator_EnforcementRule) error {
	if r == nil {
		return grpcutils.InvalidArg("Nil EnforcementRule")
	}

	if err := s.validateCondition(ctx, r.Condition); err != nil {
		return err
	}

	switch r.Effect {
	case corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_ENFORCE,
		corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_IGNORE,
		corev1.ClusterConfig_Spec_Authenticator_EnforcementRule_RECOMMEND:
	default:
		return grpcutils.InvalidArg("Rule effect must be set")
	}

	return nil
}

func validateCCAuthenticatorDefaultState(state corev1.Authenticator_Spec_State) error {
	switch state {
	case corev1.Authenticator_Spec_STATE_UNKNOWN,
		corev1.Authenticator_Spec_ACTIVE,
		corev1.Authenticator_Spec_PENDING:
		return nil
	default:
		return grpcutils.InvalidArg("Invalid Authenticator defaultState: %s", state.String())
	}
}

func validateCCAuthenticatorFIDO(fido *corev1.ClusterConfig_Spec_Authenticator_FIDO) error {
	if fido == nil {
		return nil
	}

	switch fido.AttestationConveyancePreference {
	case corev1.ClusterConfig_Spec_Authenticator_FIDO_ATTESTATION_CONVEYANCE_PREFERENCE_UNSET,
		corev1.ClusterConfig_Spec_Authenticator_FIDO_DIRECT,
		corev1.ClusterConfig_Spec_Authenticator_FIDO_INDIRECT,
		corev1.ClusterConfig_Spec_Authenticator_FIDO_NONE,
		corev1.ClusterConfig_Spec_Authenticator_FIDO_ENTERPRISE:
		return nil
	default:
		return grpcutils.InvalidArg("Invalid FIDO attestationConveyancePreference")
	}
}

func validateIngress(c *corev1.ClusterConfig) error {
	if c.Spec.Ingress == nil {
		return nil
	}

	if c.Spec.Ingress.XffNumTrustedHops < 0 {
		return grpcutils.InvalidArg("xffNumTrustedHops cannot be negative")
	}

	if c.Spec.Ingress.XffNumTrustedHops > ccMaxXFFNumTrustedHops {
		return grpcutils.InvalidArg("xffNumTrustedHops is too large: %d", c.Spec.Ingress.XffNumTrustedHops)
	}

	return nil
}

func (s *Server) validateAuthentication(ctx context.Context, c *corev1.ClusterConfig) error {
	if c.Spec.Authentication == nil {
		return nil
	}

	geo := c.Spec.Authentication.Geolocation
	if geo == nil {
		return nil
	}

	mmdb := geo.GetMmdb()
	if mmdb == nil {
		return grpcutils.InvalidArg("Geolocation type must be set")
	}

	switch {
	case mmdb.GetFromConfig() != "":
		if err := apivalidation.ValidateName(mmdb.GetFromConfig(), 0, 0); err != nil {
			return err
		}

		if _, err := s.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{
			Name: mmdb.GetFromConfig(),
		}); err != nil {
			if grpcerr.IsNotFound(err) {
				return grpcutils.InvalidArg("This Config does not exist: %s", mmdb.GetFromConfig())
			}

			return grpcutils.InternalWithErr(err)
		}

		return nil
	case mmdb.GetUpstream() != nil:
		return s.validateMMDBUpstream(ctx, mmdb.GetUpstream())
	default:
		return grpcutils.InvalidArg("MMDB type must be set")
	}
}

func (s *Server) validateMMDBUpstream(ctx context.Context,
	up *corev1.ClusterConfig_Spec_Authentication_Geolocation_MMDB_Upstream) error {

	if up.Url == "" {
		return grpcutils.InvalidArg("MMDB upstream URL must be set")
	}

	if len(up.Url) > ccMaxURLLen {
		return grpcutils.InvalidArg("MMDB upstream URL is too long")
	}

	if !govalidator.IsURL(up.Url) {
		return grpcutils.InvalidArg("Invalid MMDB upstream URL: %s", up.Url)
	}

	if !strings.HasPrefix(up.Url, "http://") && !strings.HasPrefix(up.Url, "https://") {
		return grpcutils.InvalidArg("MMDB upstream URL scheme must be http or https: %s", up.Url)
	}

	auth := up.Auth
	if auth == nil {
		return nil
	}

	switch {
	case auth.GetBearer() != nil:
		if auth.GetBearer().GetFromSecret() == "" {
			return grpcutils.InvalidArg("MMDB upstream bearer auth must set fromSecret")
		}

		if err := s.validateSecretOwner(ctx, auth.GetBearer()); err != nil {
			return err
		}
	case auth.GetBasic() != nil:
		basic := auth.GetBasic()
		if basic.Username == "" {
			return grpcutils.InvalidArg("MMDB upstream basic auth must set username")
		}
		if len(basic.Username) > ccMaxNameLen {
			return grpcutils.InvalidArg("MMDB upstream basic auth username is too long")
		}

		if err := s.validateSecretOwner(ctx, basic.GetPassword()); err != nil {
			return err
		}
	case auth.GetCustom() != nil:
		custom := auth.GetCustom()
		if custom.Header == "" {
			return grpcutils.InvalidArg("MMDB upstream custom auth must set header")
		}

		if len(custom.Header) > ccMaxNameLen {
			return grpcutils.InvalidArg("MMDB upstream custom auth header is too long")
		}

		if err := s.validateSecretOwner(ctx, custom.GetValue()); err != nil {
			return err
		}
	case auth.GetQuery() != nil:
		query := auth.GetQuery()
		if query.Key == "" {
			return grpcutils.InvalidArg("MMDB upstream query auth must set key")
		}

		if len(query.Key) > ccMaxNameLen {
			return grpcutils.InvalidArg("MMDB upstream query auth key is too long")
		}

		if err := s.validateSecretOwner(ctx, query.GetValue()); err != nil {
			return err
		}
	default:
		return grpcutils.InvalidArg("MMDB upstream auth type must be set")
	}

	return nil
}
