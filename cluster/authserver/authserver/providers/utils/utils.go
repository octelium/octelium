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

package utils

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gosimple/slug"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	vutils "github.com/octelium/octelium/pkg/utils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type StartAuthInfo struct {
	LoginURL string
	State    string
}

type Provider interface {
	Name() string
	Type() string
	LoginURL(state string) (string, string, error)
	HandleCallback(r *http.Request, reqID string) (*corev1.Session_Status_Authentication_Info, error)
	Provider() *corev1.IdentityProvider
	AuthenticateAssertion(ctx context.Context, req *authv1.AuthenticateWithAssertionRequest) (*corev1.User, *corev1.Session_Status_Authentication_Info, error)
}

func GetCallbackURL(domain string) string {
	return fmt.Sprintf("https://%s/callback", domain)
}

type ProviderOpts struct {
	OcteliumC     octeliumc.ClientInterface
	Provider      *corev1.IdentityProvider
	ClusterConfig *corev1.ClusterConfig
	CELEngine     *celengine.CELEngine
}

type GetUserFromIdentifierOpts struct {
	OcteliumC            octeliumc.ClientInterface
	IdentityProviderName string
	Identifier           string
	UserType             corev1.User_Spec_Type
}

func GetUserFromIdentifier(ctx context.Context, opts *GetUserFromIdentifierOpts) (*corev1.User, error) {

	if opts.Identifier == "" {
		return nil, errors.Errorf("Empty identifier")
	}

	listOptions := &rmetav1.ListOptions{
		SpecLabels: map[string]string{
			fmt.Sprintf("auth-%s", opts.IdentityProviderName): slug.Make(opts.Identifier),
		},
	}

	usrs, err := opts.OcteliumC.CoreC().ListUser(ctx, listOptions)
	if err != nil {
		return nil, errors.Errorf("Internal error")
	}

	switch len(usrs.Items) {
	case 1:
	default:
		if len(usrs.Items) > 1 {
			zap.L().Warn("Multiple Users are assigned to the same identifier",
				zap.Any("specLeabels", listOptions.SpecLabels))
		}
		return nil, errors.Errorf("This User does not exist")
	}

	usr := usrs.Items[0]

	zap.L().Debug("Matched authenticated User with identifier",
		zap.Any("user", usr), zap.String("identifier", opts.Identifier),
		zap.String("idp", opts.IdentityProviderName))

	if usr.Spec.IsDisabled {
		return nil, errors.Errorf("Deactivated User")
	}

	if usr.Spec.Type != opts.UserType {
		return nil, errors.Errorf("Invalid User type")
	}

	userAccount := func() *corev1.User_Spec_Authentication_Identity {
		if usr.Spec.Authentication == nil {
			return nil
		}
		for _, acc := range usr.Spec.Authentication.Identities {
			if acc.IdentityProvider == opts.IdentityProviderName {
				return acc
			}
		}
		return nil
	}()

	if userAccount == nil {
		return nil, errors.Errorf("The User authentication account does not exist")
	}

	if !vutils.SecureStringEqual(userAccount.Identifier, opts.Identifier) {
		return nil, errors.Errorf("The User identifier does not match the account")
	}

	return usr, nil
}

type GetAALReq struct {
	CelEngine    *celengine.CELEngine
	Rules        []*corev1.IdentityProvider_Spec_AALRule
	AssertionMap map[string]any
	Assertion    string
}

func GetAAL(ctx context.Context, req *GetAALReq) corev1.Session_Status_Authentication_Info_AAL {
	if len(req.Rules) == 0 {
		return corev1.Session_Status_Authentication_Info_AAL_UNSET
	}

	zap.L().Debug("Starting getAAL", zap.Any("req", req))

	reqMap := map[string]any{
		"ctx": map[string]any{
			"assertionMap": req.AssertionMap,
			"assertion":    req.Assertion,
		},
	}

	for _, rule := range req.Rules {
		match, err := req.CelEngine.EvalCondition(ctx, rule.Condition, reqMap)
		if err != nil {
			zap.L().Warn("Could not evalCondition for getAAL", zap.Error(err))
			continue
		}

		if match {
			return corev1.Session_Status_Authentication_Info_AAL(rule.Aal)
		}
	}

	return corev1.Session_Status_Authentication_Info_AAL_UNSET
}
