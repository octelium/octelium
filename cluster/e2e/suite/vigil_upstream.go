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

package suite

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bearerAuth(secretName string) *corev1.Service_Spec_Config_HTTP_Auth {
	return &corev1.Service_Spec_Config_HTTP_Auth{
		Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_{
			Bearer: &corev1.Service_Spec_Config_HTTP_Auth_Bearer{
				Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_FromSecret{
					FromSecret: secretName,
				},
			},
		},
	}
}

func basicAuth(username, secretName string) *corev1.Service_Spec_Config_HTTP_Auth {
	return &corev1.Service_Spec_Config_HTTP_Auth{
		Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_{
			Basic: &corev1.Service_Spec_Config_HTTP_Auth_Basic{
				Username: username,
				Password: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password{
					Type: &corev1.Service_Spec_Config_HTTP_Auth_Basic_Password_FromSecret{
						FromSecret: secretName,
					},
				},
			},
		},
	}
}

func testVigilSecretManager(t *testing.T, h *harness.H) {
	v := newVigilCtx(t, h)
	v.record(t, http.StatusOK, "")

	value := utilrand.GetRandomStringCanonical(24)
	secret := h.CreateSecret(t, "", value)

	waitAuthorization := func(t *testing.T, what, want string) {
		t.Helper()

		v.waitSeen(t, what, "/", func(r *seenRequest) error {
			if got := r.Header.Get("Authorization"); got != want {
				return errors.Errorf("the upstream saw the Authorization %q, want %q",
					got, want)
			}
			return nil
		})
	}

	t.Run("BearerFromSecret", func(t *testing.T) {
		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{Auth: bearerAuth(secret.Metadata.Name)})

		waitAuthorization(t, "the upstream to receive the bearer token of the Secret",
			fmt.Sprintf("Bearer %s", value))
	})

	t.Run("SecretRotation", func(t *testing.T) {
		rotated := utilrand.GetRandomStringCanonical(24)
		h.UpdateSecret(t, secret.Metadata.Name, rotated)

		waitAuthorization(t, "the upstream to receive the rotated bearer token",
			fmt.Sprintf("Bearer %s", rotated))
	})

	t.Run("BasicFromSecret", func(t *testing.T) {
		password := utilrand.GetRandomStringCanonical(24)
		h.UpdateSecret(t, secret.Metadata.Name, password)

		username := utilrand.GetRandomStringCanonical(8)
		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{
			Auth: basicAuth(username, secret.Metadata.Name),
		})

		waitAuthorization(t, "the upstream to receive the basic credentials of the Secret",
			fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString(
				[]byte(fmt.Sprintf("%s:%s", username, password)))))
	})
}

func testVigilLoadBalancer(t *testing.T, h *harness.H) {
	upstream := h.StartHTTPUpstream(t, nil)

	svc := h.CreateService(t, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
		},
		Spec: &corev1.Service_Spec{
			Mode:        corev1.Service_Spec_HTTP,
			IsPublic:    true,
			IsAnonymous: true,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{
						Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{
							Endpoints: []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
								{
									Url:  fmt.Sprintf("http://localhost:%d", upstream.Port),
									User: "root",
								},
							},
						},
					},
				},
			},
		},
	})

	h.MustWaitService(t, svc.Metadata.Name)

	client := h.ServiceClient(svc, "")
	noRetry := h.HTTPNoRetry().SetBaseURL(h.ServiceURL(svc))

	t.Run("NoUpstream", func(t *testing.T) {
		h.Eventually(t, "the Service without a connected upstream to fail",
			harness.DecisionBudget, func(ctx context.Context) error {
				got, err := h.StatusOf(ctx, noRetry, "/")
				if err != nil {
					return err
				}
				if got != http.StatusBadGateway {
					return errUnexpectedStatus(got, http.StatusBadGateway)
				}
				return nil
			})
	})

	t.Run("SessionUpstream", func(t *testing.T) {
		upstream.SetServeFn(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("loadbalanced"))
		})

		conn := h.Connect(t, harness.ConnectOpts{Serve: []string{svc.Metadata.Name}})

		res := h.WaitGetStatus(t, client, "/", http.StatusOK)
		require.Equal(t, "loadbalanced", res.String())

		require.Nil(t, conn.Disconnect())

		h.Eventually(t, "the Service to fail again once its upstream disconnects",
			harness.DecisionBudget, func(ctx context.Context) error {
				got, err := h.StatusOf(ctx, noRetry, "/")
				if err != nil {
					return err
				}
				if got != http.StatusBadGateway {
					return errUnexpectedStatus(got, http.StatusBadGateway)
				}
				return nil
			})
	})
}

func testVigilLoadBalancerUpdates(t *testing.T, h *harness.H) {
	var backends []*corev1.Service
	values := []string{h.Name(), h.Name()}
	for _, value := range values {
		backend := newManagedHTTPService(t, h,
			[]*corev1.Service_Spec_Config_Upstream_Container_Env{
				{
					Name: "OCTELIUM_E2E_RESPONSE",
					Type: &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: value},
				},
			}, 1)
		h.MustWaitServiceUpstream(t, backend.Metadata.Name)
		backends = append(backends, backend)
	}

	endpoint := func(idx int) *corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint {
		return &corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
			Url: fmt.Sprintf("http://%s.%s.svc:80",
				k8sutils.GetSvcK8sUpstreamHostname(backends[idx], ""), vutils.K8sNS),
		}
	}

	svc := h.CreateService(t, &corev1.Service{
		Spec: &corev1.Service_Spec{
			Mode:        corev1.Service_Spec_HTTP,
			IsPublic:    true,
			IsAnonymous: true,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{
						Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{
							Endpoints: []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{endpoint(0)},
						},
					},
				},
			},
		},
	})
	h.MustWaitService(t, svc.Metadata.Name)

	c := h.HTTPNoRetry().SetBaseURL(h.ServiceURL(svc))
	t.Cleanup(c.GetClient().CloseIdleConnections)
	get := func(ctx context.Context) (string, error) {
		res, err := c.R().SetContext(ctx).Get("/")
		if err != nil {
			return "", err
		}
		if res.StatusCode() != http.StatusOK {
			return "", errUnexpectedStatus(res.StatusCode(), http.StatusOK)
		}
		return res.String(), nil
	}
	check := func(ctx context.Context, want string) error {
		got, err := get(ctx)
		if err != nil {
			return err
		}
		if got != want {
			return errors.Errorf("the load balancer returned %q, want %q", got, want)
		}
		return nil
	}

	h.Eventually(t, "the initial endpoint to serve requests", harness.DecisionBudget,
		func(ctx context.Context) error {
			return check(ctx, values[0])
		})

	t.Run("ReplaceEndpoint", func(t *testing.T) {
		svc.Spec.Config.Upstream.GetLoadbalance().Endpoints =
			[]*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{endpoint(1)}
		svc = h.UpdateService(t, svc)

		h.Eventually(t, "the replacement endpoint to serve requests", harness.DecisionBudget,
			func(ctx context.Context) error {
				return check(ctx, values[1])
			})

		h.Consistently(t, "the removed endpoint to receive no more requests", decisionSettle,
			func(ctx context.Context) error {
				return check(ctx, values[1])
			})
	})

	t.Run("ReaddEndpoint", func(t *testing.T) {
		svc.Spec.Config.Upstream.GetLoadbalance().Endpoints =
			[]*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{endpoint(0), endpoint(1)}
		svc = h.UpdateService(t, svc)

		seen := map[string]bool{}
		h.Eventually(t, "both endpoints to serve requests from the same client",
			harness.DecisionBudget, func(ctx context.Context) error {
				got, err := get(ctx)
				if err != nil {
					return err
				}
				if got != values[0] && got != values[1] {
					return errors.Errorf("the load balancer returned an unknown backend %q", got)
				}
				seen[got] = true
				if len(seen) != 2 {
					return errors.Errorf("only %d endpoints have served requests", len(seen))
				}
				return nil
			})
	})
}

func testVigilSecretLifecycle(t *testing.T, h *harness.H) {
	v := newVigilCtx(t, h)

	value := h.Name()
	secret := h.CreateSecret(t, "", value)
	var expected atomic.Value
	expected.Store("Bearer " + value)
	v.upstream.SetServeFn(func(w http.ResponseWriter, r *http.Request) {
		v.seen.Store(&seenRequest{Header: r.Header.Clone()})
		if r.Header.Get("Authorization") != expected.Load().(string) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{Auth: bearerAuth(secret.Metadata.Name)})

	c := h.HTTPNoRetry()
	t.Cleanup(c.GetClient().CloseIdleConnections)
	check := func(ctx context.Context, want string) error {
		v.seen.Store(nil)
		res, err := c.R().SetContext(ctx).Get(v.url("/"))
		if err != nil {
			return err
		}
		status := http.StatusOK
		if want == "" {
			status = http.StatusUnauthorized
		}
		if res.StatusCode() != status {
			return errUnexpectedStatus(res.StatusCode(), status)
		}
		got := v.seen.Load()
		if got == nil {
			return errors.Errorf("the request has not reached the upstream")
		}
		if got.Header.Get("Authorization") != want {
			return errors.Errorf("the upstream did not receive the expected credentials")
		}
		return nil
	}
	wait := func(t *testing.T, what, want string) {
		t.Helper()
		h.Eventually(t, what, harness.DecisionBudget, func(ctx context.Context) error {
			return check(ctx, want)
		})
	}

	wait(t, "the upstream to receive the initial credentials", "Bearer "+value)

	t.Run("DeleteAndRecreate", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), harness.DecisionBudget)
		defer cancel()
		_, err := h.CoreC().DeleteSecret(ctx, &metav1.DeleteOptions{Uid: secret.Metadata.Uid})
		require.Nil(t, err)

		wait(t, "the deleted credentials to stop reaching the upstream", "")
		h.Consistently(t, "the deleted credentials to stay absent", decisionSettle,
			func(ctx context.Context) error {
				return check(ctx, "")
			})

		before := secret.Metadata.Uid
		value = h.Name()
		secret = h.CreateSecret(t, secret.Metadata.Name, value)
		assert.NotEqual(t, before, secret.Metadata.Uid)
		expected.Store("Bearer " + value)

		wait(t, "the recreated Secret to supply new credentials", "Bearer "+value)

		value = h.Name()
		h.UpdateSecret(t, secret.Metadata.Name, value)
		expected.Store("Bearer " + value)
		wait(t, "the recreated Secret to remain watched after rotation", "Bearer "+value)
	})

	t.Run("ReferenceChanged", func(t *testing.T) {
		value := h.Name()
		replacement := h.CreateSecret(t, "", value)
		v.setHTTP(t, &corev1.Service_Spec_Config_HTTP{Auth: bearerAuth(replacement.Metadata.Name)})
		want := "Bearer " + value
		expected.Store(want)
		wait(t, "the replacement Secret to supply credentials", want)

		h.UpdateSecret(t, secret.Metadata.Name, h.Name())
		h.Consistently(t, "rotation of the old Secret to leave the new credentials intact",
			decisionSettle, func(ctx context.Context) error {
				return check(ctx, want)
			})
	})
}
