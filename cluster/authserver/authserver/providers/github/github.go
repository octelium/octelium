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

package github

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/go-github/v33/github"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type Connector struct {
	c         *corev1.IdentityProvider
	cc        *corev1.ClusterConfig
	celEngine *celengine.CELEngine
	secret    string
}

func NewConnector(ctx context.Context, opts *utils.ProviderOpts) (*Connector, error) {

	if opts.Provider.Spec.GetGithub() == nil {
		return nil, errors.Errorf("Not a Github connector")
	}

	ret := &Connector{
		c:         opts.Provider,
		cc:        opts.ClusterConfig,
		celEngine: opts.CELEngine,
	}

	sec, err := opts.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
		Name: opts.Provider.Spec.GetGithub().ClientSecret.GetFromSecret(),
	})
	if err != nil {
		return nil, err
	}

	ret.secret = ucorev1.ToSecret(sec).GetValueStr()

	return ret, nil
}

func (c *Connector) Name() string {
	return c.c.Metadata.Name
}

func (c *Connector) Provider() *corev1.IdentityProvider {
	return c.c
}

func (c *Connector) Type() string {
	return "github"
}

func (c *Connector) LoginURL(state string) (string, string, error) {

	return c.oauth2Config().AuthCodeURL(state), "", nil
}

func (c *Connector) oauth2Config() *oauth2.Config {
	config := c.c.Spec.GetGithub()

	return &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: c.secret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
		},
		Scopes:      []string{"user:email"},
		RedirectURL: utils.GetCallbackURL(c.cc.Status.Domain),
	}
}

func (c *Connector) HandleCallback(r *http.Request, reqID string) (*corev1.Session_Status_Authentication_Info, error) {
	oauth2Config := c.oauth2Config()

	ctx := r.Context()

	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return nil, errors.Errorf("%s", q.Get("error_description"))
	}

	token, err := oauth2Config.Exchange(ctx, q.Get("code"))
	if err != nil {
		return nil, errors.Errorf("Could not get token: %v", err)
	}

	if !token.Valid() {
		return nil, errors.Errorf("Invalid token")
	}

	client := oauth2Config.Client(ctx, token)

	githubClient := github.NewClient(client)

	user, _, err := githubClient.Users.Get(ctx, "")
	if err != nil {
		return nil, errors.Errorf("Could not get user")
	}

	userMap := make(map[string]any)
	if userBytes, err := json.Marshal(user); err == nil {
		if err := json.Unmarshal(userBytes, &userMap); err != nil {
			zap.L().Warn("Could not unmarshal github user to map", zap.Error(err))
		}
	} else {
		zap.L().Warn("Could not marshal github user", zap.Error(err))
	}

	ret := &corev1.Session_Status_Authentication_Info{
		Type: corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER,
		Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
			IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
				IdentityProviderRef: umetav1.GetObjectReference(c.c),
				Type:                corev1.IdentityProvider_Status_GITHUB,
			},
		},
		Aal: utils.GetAAL(ctx, &utils.GetAALReq{
			CelEngine:    c.celEngine,
			Rules:        c.c.Spec.AalRules,
			AssertionMap: userMap,
		}),
	}

	if user.Login != nil {
		ret.GetIdentityProvider().Identifier = *user.Login
	}

	if user.Email != nil {
		ret.GetIdentityProvider().Email = *user.Email
	}

	if user.AvatarURL != nil {
		ret.GetIdentityProvider().PicURL = *user.AvatarURL
	}

	return ret, nil
}

func (c *Connector) AuthenticateAssertion(ctx context.Context, req *authv1.AuthenticateWithAssertionRequest) (*corev1.User, *corev1.Session_Status_Authentication_Info, error) {
	return nil, nil, errors.Errorf("AuthenticateAssertion is unimplemented")
}
