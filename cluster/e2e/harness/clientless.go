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

package harness

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/pkg/errors"
)

const DecisionBudget = 30 * time.Second

func (h *H) AccessToken(t *testing.T, usr *corev1.User) string {
	t.Helper()

	cred := h.CreateCredential(t, CredentialOpts{
		User:        usr.Metadata.Name,
		Type:        corev1.Credential_Spec_ACCESS_TOKEN,
		SessionType: corev1.Session_Status_CLIENTLESS,
	})

	tkn := h.CredentialToken(t, cred)
	if tkn.GetAccessToken() == nil {
		t.Fatalf("The Credential %s did not yield an access token", cred.Metadata.Name)
	}

	return tkn.GetAccessToken().AccessToken
}

func (h *H) ServiceURL(svc *corev1.Service) string {
	return fmt.Sprintf("https://%s", vutils.GetServicePublicFQDN(svc, h.Domain))
}

func (h *H) ServiceClient(svc *corev1.Service, accessToken string) *resty.Client {
	c := h.HTTP().SetBaseURL(h.ServiceURL(svc))
	if accessToken != "" {
		c = c.SetAuthScheme("Bearer").SetAuthToken(accessToken)
	}
	return c
}

func (h *H) StatusOf(ctx context.Context, c *resty.Client, path string) (int, error) {
	res, err := c.R().SetContext(ctx).Get(path)
	if err != nil {
		return 0, err
	}
	return res.StatusCode(), nil
}

func (h *H) WaitStatus(t *testing.T, c *resty.Client, path string, want int) time.Duration {
	t.Helper()

	return h.Within(t, fmt.Sprintf("GET %s to return %d", path, want), DecisionBudget,
		func(ctx context.Context) error {
			got, err := h.StatusOf(ctx, c, path)
			if err != nil {
				return err
			}
			if got != want {
				return errors.Errorf("got status %d, want %d", got, want)
			}
			return nil
		})
}

func (h *H) WaitAllowed(t *testing.T, c *resty.Client) time.Duration {
	t.Helper()
	return h.WaitStatus(t, c, "/", http.StatusOK)
}

func (h *H) WaitDenied(t *testing.T, c *resty.Client) time.Duration {
	t.Helper()
	return h.WaitStatus(t, c, "/", http.StatusForbidden)
}

func (h *H) NewPublicService(t *testing.T, namespace string) *corev1.Service {
	t.Helper()

	name := h.Name()
	if namespace != "" && namespace != "default" {
		name = fmt.Sprintf("%s.%s", name, namespace)
	}

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{Name: name},
		Spec: &corev1.Service_Spec{
			Mode:     corev1.Service_Spec_HTTP,
			IsPublic: true,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Container_{
						Container: &corev1.Service_Spec_Config_Upstream_Container{
							Image: "nginx",
							Port:  80,
						},
					},
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	return svc
}
