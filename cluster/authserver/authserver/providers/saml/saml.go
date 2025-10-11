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

package saml

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"

	"github.com/asaskevich/govalidator"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type Connector struct {
	c         *corev1.IdentityProvider
	cc        *corev1.ClusterConfig
	sp        *saml.ServiceProvider
	celEngine *celengine.CELEngine
}

func NewConnector(ctx context.Context, opts *utils.ProviderOpts) (*Connector, error) {

	if opts.Provider.Spec.GetSaml() == nil {
		return nil, errors.Errorf("Not a SAML provider")
	}
	conf := opts.Provider.Spec.GetSaml()

	idpMetadata, err := func() (*saml.EntityDescriptor, error) {

		switch conf.MetadataType.(type) {
		case *corev1.IdentityProvider_Spec_SAML_Metadata:
			return samlsp.ParseMetadata([]byte(conf.GetMetadata()))
		case *corev1.IdentityProvider_Spec_SAML_MetadataURL:
			idpMetadataURL, err := url.Parse(conf.GetMetadataURL())
			if err != nil {
				return nil, err
			}
			return samlsp.FetchMetadata(ctx, http.DefaultClient, *idpMetadataURL)
		default:
			return nil, errors.Errorf("Either metadata or metadataURL must be supplied")
		}
	}()
	if err != nil {
		return nil, err
	}

	ret := &Connector{
		c:         opts.Provider,
		cc:        opts.ClusterConfig,
		celEngine: opts.CELEngine,
		sp: &saml.ServiceProvider{
			EntityID: func() string {
				if conf.EntityID != "" {
					return conf.EntityID
				}
				return fmt.Sprintf("https://%s", opts.ClusterConfig.Status.Domain)
			}(),
			AcsURL: func() url.URL {
				ret, _ := url.Parse(utils.GetCallbackURL(opts.ClusterConfig.Status.Domain))
				return *ret
			}(),

			IDPMetadata: idpMetadata,
			ForceAuthn: func() *bool {
				if conf.ForceAuthn {
					return utils_types.BoolToPtr(true)
				}
				return nil
			}(),
		},
	}

	return ret, nil
}

func (c *Connector) Name() string {
	return c.c.Metadata.Name
}

func (c *Connector) AuthenticateAssertion(ctx context.Context,
	req *authv1.AuthenticateWithAssertionRequest) (*corev1.User, *corev1.Session_Status_Authentication_Info, error) {
	return nil, nil, errors.Errorf("AuthenticateAssertion is unimplemented")
}

func (c *Connector) Provider() *corev1.IdentityProvider {
	return c.c
}

func (c *Connector) Type() string {
	return "saml"
}

func (c *Connector) LoginURL(state string) (string, string, error) {

	ssoURL := c.sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)

	authenReq, err := c.sp.MakeAuthenticationRequest(ssoURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", "", err
	}

	url, err := authenReq.Redirect(state, c.sp)
	if err != nil {
		return "", "", err
	}

	return url.String(), authenReq.ID, nil
}

func (c *Connector) HandleCallback(r *http.Request, reqID string) (*corev1.Session_Status_Authentication_Info, error) {

	conf := c.c.Spec.GetSaml()

	assertion, err := c.sp.ParseResponse(r, []string{reqID})
	if err != nil {
		merr := err.(*saml.InvalidResponseError)
		zap.L().Debug("Could not validate SAML responses", zap.Error(merr), zap.Error(merr.PrivateErr))
		return nil, err
	}

	var assertionStr string
	if assertionBytes, err := xml.Marshal(assertion); err == nil {
		assertionStr = string(assertionBytes)
	}

	identifier := getValStr(assertion, getAttrIdentifier(conf))
	email := ""
	if govalidator.IsEmail(identifier) {
		email = identifier
	} else {
		email = getValStr(assertion, defaultEmailAttr)
	}

	ret := &corev1.Session_Status_Authentication_Info{
		Type: corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER,
		Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
			IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
				IdentityProviderRef: umetav1.GetObjectReference(c.c),
				Type:                corev1.IdentityProvider_Status_SAML,

				Identifier: identifier,
				Email:      email,
			},
		},
		Aal: utils.GetAAL(r.Context(), &utils.GetAALReq{
			CelEngine: c.celEngine,
			Rules:     c.c.Spec.AalRules,
			Assertion: assertionStr,
		}),
	}

	return ret, nil

}

func getValStr(assertion *saml.Assertion, name string) string {
	for _, attrStatement := range assertion.AttributeStatements {
		for _, attr := range attrStatement.Attributes {
			if attr.Name == name {
				if len(attr.Values) > 0 {
					return attr.Values[0].Value
				}
			}
		}
	}
	return ""
}

const defaultEmailAttr = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"

func getAttrIdentifier(conf *corev1.IdentityProvider_Spec_SAML) string {
	if conf.IdentifierAttribute != "" {
		return conf.IdentifierAttribute
	}

	return defaultEmailAttr
}
