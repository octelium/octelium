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
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newManagedService(t *testing.T, h *harness.H, image string, port uint32) *corev1.Service {
	t.Helper()

	return h.CreateService(t, &corev1.Service{
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Container_{
						Container: &corev1.Service_Spec_Config_Upstream_Container{
							Image: image,
							Port:  port,
						},
					},
				},
			},
		},
	})
}

func newManagedHTTPService(t *testing.T, h *harness.H,
	env []*corev1.Service_Spec_Config_Upstream_Container_Env, replicas uint32) *corev1.Service {
	t.Helper()

	return h.CreateService(t, &corev1.Service{
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Container_{
						Container: &corev1.Service_Spec_Config_Upstream_Container{
							Image:    "nginx",
							Port:     80,
							Replicas: replicas,
							Command:  []string{"/bin/sh", "-c"},
							Args: []string{
								`printf '%s' "$OCTELIUM_E2E_RESPONSE" > /usr/share/nginx/html/index.html; exec nginx -g 'daemon off;'`,
							},
							Env: env,
							ReadinessProbe: &corev1.Service_Spec_Config_Upstream_Container_Probe{
								Type: &corev1.Service_Spec_Config_Upstream_Container_Probe_HttpGet{
									HttpGet: &corev1.Service_Spec_Config_Upstream_Container_Probe_HTTPGet{
										Path: "/",
										Port: 80,
									},
								},
							},
						},
					},
				},
			},
		},
	})
}

func testNocturneKubernetesSecret(t *testing.T, h *harness.H) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)

	secrets := h.K8sC().CoreV1().Secrets(vutils.K8sNS)
	secret, err := secrets.Create(ctx, &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{Name: h.Name()},
		Data:       map[string][]byte{"unused": []byte("unused")},
	}, k8smetav1.CreateOptions{})
	cancel()
	require.Nil(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		secrets.Delete(ctx, secret.Name, k8smetav1.DeleteOptions{})
	})
	updateSecret := func(t *testing.T) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		ret, err := secrets.Update(ctx, secret, k8smetav1.UpdateOptions{})
		require.Nil(t, err)
		secret = ret
	}

	svc := newManagedHTTPService(t, h,
		[]*corev1.Service_Spec_Config_Upstream_Container_Env{
			{
				Name: "OCTELIUM_E2E_RESPONSE",
				Type: &corev1.Service_Spec_Config_Upstream_Container_Env_KubernetesSecretRef_{
					KubernetesSecretRef: &corev1.Service_Spec_Config_Upstream_Container_Env_KubernetesSecretRef{
						Name: secret.Name,
						Key:  "response",
					},
				},
			},
		}, 2)
	upstream := k8sutils.GetSvcK8sUpstreamHostname(svc, "")

	if !t.Run("MissingKey", func(t *testing.T) {
		h.Eventually(t, "both upstream replicas to wait for the missing Secret key",
			harness.DeploymentBudget, func(ctx context.Context) error {
				pods, err := h.ServicePods(ctx, svc.Metadata.Name)
				if err != nil {
					return err
				}
				var blocked int
				for _, pod := range pods {
					for _, cs := range pod.Status.ContainerStatuses {
						if cs.Name == "backend" && cs.State.Waiting != nil &&
							cs.State.Waiting.Reason == "CreateContainerConfigError" {
							blocked++
							if cs.Ready {
								return errors.Errorf("the upstream with a missing Secret key is ready")
							}
							if !strings.Contains(cs.State.Waiting.Message, "response") {
								return errors.Errorf("the upstream failed for another reason: %s",
									cs.State.Waiting.Message)
							}
						}
					}
				}
				if blocked != 2 {
					return errors.Errorf("%d upstream replicas are waiting for the key, want 2", blocked)
				}
				return nil
			})
	}) {
		return
	}

	value := h.Name()
	secret.Data["response"] = []byte(value)
	updateSecret(t)

	h.MustWaitServiceUpstream(t, svc.Metadata.Name)
	h.MustWaitService(t, svc.Metadata.Name)
	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{svc.Metadata.Name: h.Port()},
	})
	c := h.HTTPNoRetry().SetBaseURL(conn.URL(svc.Metadata.Name))
	t.Cleanup(c.GetClient().CloseIdleConnections)

	check := func(ctx context.Context, want string) error {
		res, err := c.R().SetContext(ctx).Get("/")
		if err != nil {
			return err
		}
		if res.StatusCode() != http.StatusOK {
			return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
		}
		if res.String() != want {
			return errors.Errorf("the upstream returned %q, want %q", res.String(), want)
		}
		return nil
	}

	t.Run("KeyRestored", func(t *testing.T) {
		h.Eventually(t, "the recovered upstream to serve the Secret value",
			harness.DeploymentBudget, func(ctx context.Context) error {
				dep, err := h.K8sDeployment(ctx, upstream)
				if err != nil {
					return err
				}
				if dep.Status.ReadyReplicas != 2 {
					return errors.Errorf("the upstream has %d ready replicas, want 2", dep.Status.ReadyReplicas)
				}
				return check(ctx, value)
			})
	})

	t.Run("KeyChanged", func(t *testing.T) {
		rotated := h.Name()
		secret.Data["rotated"] = []byte(rotated)
		updateSecret(t)

		svc.Spec.Config.Upstream.GetContainer().Env[0].GetKubernetesSecretRef().Key = "rotated"
		svc = h.UpdateService(t, svc)

		h.Eventually(t, "both upstream replicas to roll out the new Secret key",
			harness.DeploymentBudget, func(ctx context.Context) error {
				dep, err := h.K8sDeployment(ctx, upstream)
				if err != nil {
					return err
				}
				containers := dep.Spec.Template.Spec.Containers
				if len(containers) != 1 || len(containers[0].Env) != 1 ||
					containers[0].Env[0].ValueFrom == nil ||
					containers[0].Env[0].ValueFrom.SecretKeyRef == nil {
					return errors.Errorf("the Deployment has no Secret environment variable")
				}
				ref := containers[0].Env[0].ValueFrom.SecretKeyRef
				if ref.Name != secret.Name || ref.Key != "rotated" {
					return errors.Errorf("the Deployment still references the old Secret key")
				}
				if dep.Status.ObservedGeneration != dep.Generation ||
					dep.Status.UpdatedReplicas != 2 || dep.Status.ReadyReplicas != 2 ||
					dep.Status.Replicas != 2 {
					return errors.Errorf("the upstream rollout is not complete")
				}
				return check(ctx, rotated)
			})

		h.Consistently(t, "every request to use the new Secret key", decisionSettle,
			func(ctx context.Context) error {
				return check(ctx, rotated)
			})
	})
}

func waitServiceAddresses(t *testing.T, h *harness.H,
	name string, want int) []*corev1.Service_Status_Address {
	t.Helper()

	var ret []*corev1.Service_Status_Address
	h.Eventually(t, fmt.Sprintf("the Service to report %d addresses", want),
		harness.DeploymentBudget, func(ctx context.Context) error {
			svc, err := h.CoreC().GetService(ctx, &metav1.GetOptions{Name: name})
			if err != nil {
				return err
			}
			if svc.Status == nil {
				return errors.Errorf("the Service has no status")
			}
			if len(svc.Status.Addresses) != want {
				return errors.Errorf("the Service reports %d addresses, want %d",
					len(svc.Status.Addresses), want)
			}
			for _, address := range svc.Status.Addresses {
				if address.PodRef == nil || address.PodRef.Uid == "" {
					return errors.Errorf("a Service address has no Pod reference")
				}
				if address.DualStackIP == nil ||
					(address.DualStackIP.Ipv4 == "" && address.DualStackIP.Ipv6 == "") {
					return errors.Errorf("the Pod %s has no Service IP address",
						address.PodRef.Name)
				}
			}
			ret = svc.Status.Addresses
			return nil
		})

	return ret
}

func testNocturne(t *testing.T, h *harness.H) {
	t.Run("Reconciliation", func(t *testing.T) {
		svc := newManagedService(t, h, "nginx", 80)
		hostname := h.SvcHostname(svc)

		h.WaitK8sObjectsPresent(t, hostname)

		ready := h.Within(t, "the Service Deployment to become available",
			harness.DeploymentBudget, func(ctx context.Context) error {
				return h.WaitDeployment(ctx, hostname)
			})

		zap.L().Info("Service reconciliation", zap.Duration("ready", ready))

		dep := h.MustK8sDeployment(t, hostname)
		require.Equal(t, 1, len(dep.OwnerReferences))
		assert.Equal(t, "ConfigMap", dep.OwnerReferences[0].Kind)
		assert.Equal(t, hostname, dep.OwnerReferences[0].Name)
	})

	t.Run("Replicas", func(t *testing.T) {
		svc := newManagedService(t, h, "nginx", 80)
		hostname := h.SvcHostname(svc)

		h.MustWaitService(t, svc.Metadata.Name)
		waitServiceAddresses(t, h, svc.Metadata.Name, 1)

		svc.Spec.Deployment = &corev1.Service_Spec_Deployment{Replicas: 2}
		svc = h.UpdateService(t, svc)

		h.Eventually(t, "the Deployment to scale to the requested replicas",
			harness.DeploymentBudget, func(ctx context.Context) error {
				dep, err := h.K8sDeployment(ctx, hostname)
				if err != nil {
					return err
				}
				if dep.Spec.Replicas == nil {
					return errors.Errorf("the Deployment has no explicit replica count")
				}
				if *dep.Spec.Replicas != 2 {
					return errors.Errorf("the Deployment requests %d replicas, want 2",
						*dep.Spec.Replicas)
				}
				if dep.Status.ReadyReplicas != 2 {
					return errors.Errorf("the Deployment has %d ready replicas, want 2",
						dep.Status.ReadyReplicas)
				}
				return nil
			})

		addresses := waitServiceAddresses(t, h, svc.Metadata.Name, 2)
		assert.NotEqual(t, addresses[0].PodRef.Uid, addresses[1].PodRef.Uid)

		svc = h.GetService(t, svc.Metadata.Name)
		svc.Spec.Deployment.Replicas = 1
		svc = h.UpdateService(t, svc)

		h.Eventually(t, "the Deployment to scale back to one replica",
			harness.DeploymentBudget, func(ctx context.Context) error {
				dep, err := h.K8sDeployment(ctx, hostname)
				if err != nil {
					return err
				}
				if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 {
					return errors.Errorf("the Deployment does not request one replica")
				}
				if dep.Status.ReadyReplicas != 1 {
					return errors.Errorf("the Deployment has %d ready replicas, want 1",
						dep.Status.ReadyReplicas)
				}
				return nil
			})

		waitServiceAddresses(t, h, svc.Metadata.Name, 1)
	})

	t.Run("UpstreamEnvFromSecret", func(t *testing.T) {
		value := utilrand.GetRandomStringCanonical(32)
		secret := h.CreateSecret(t, "", value)

		svc := h.CreateService(t, &corev1.Service{
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Container_{
							Container: &corev1.Service_Spec_Config_Upstream_Container{
								Image: "nginx",
								Port:  80,
								Env: []*corev1.Service_Spec_Config_Upstream_Container_Env{
									{
										Name: "OCTELIUM_E2E_SECRET",
										Type: &corev1.Service_Spec_Config_Upstream_Container_Env_FromSecret{
											FromSecret: secret.Metadata.Name,
										},
									},
								},
							},
						},
					},
				},
			},
		})

		h.MustWaitServiceUpstream(t, svc.Metadata.Name)

		upstream := k8sutils.GetSvcK8sUpstreamHostname(svc, "")
		secretName := fmt.Sprintf("svc-env-%s-%s", svc.Metadata.Uid, secret.Metadata.Uid)

		k8sSec, err := h.K8sC().CoreV1().Secrets(vutils.K8sNS).
			Get(t.Context(), secretName, k8smetav1.GetOptions{})
		require.Nil(t, err)
		assert.Equal(t, []byte(value), k8sSec.Data["data"])

		dep := h.MustK8sDeployment(t, upstream)
		require.Equal(t, 1, len(dep.Spec.Template.Spec.Containers))
		require.Equal(t, 1, len(dep.Spec.Template.Spec.Containers[0].Env))
		env := dep.Spec.Template.Spec.Containers[0].Env[0]
		assert.Equal(t, "OCTELIUM_E2E_SECRET", env.Name)
		require.NotNil(t, env.ValueFrom)
		require.NotNil(t, env.ValueFrom.SecretKeyRef)
		assert.Equal(t, secretName, env.ValueFrom.SecretKeyRef.Name)
		assert.Equal(t, "data", env.ValueFrom.SecretKeyRef.Key)

		out := h.MustOutput(t, fmt.Sprintf(
			"kubectl exec -n %s deployment/%s -c backend -- printenv OCTELIUM_E2E_SECRET",
			vutils.K8sNS, upstream))
		assert.Equal(t, value+"\n", string(out))
	})

	t.Run("UpstreamRollout", func(t *testing.T) {
		svc := newManagedService(t, h, "nginx:1.27", 80)
		upstream := k8sutils.GetSvcK8sUpstreamHostname(svc, "")

		h.MustWaitServiceUpstream(t, svc.Metadata.Name)

		before := h.MustK8sDeployment(t, upstream)
		assert.Equal(t, "nginx:1.27", before.Spec.Template.Spec.Containers[0].Image)

		svc.Spec.Config.Upstream.GetContainer().Image = "nginx:1.28"
		svc = h.UpdateService(t, svc)

		h.Eventually(t, "the upstream Deployment to roll out the new image",
			harness.DeploymentBudget, func(ctx context.Context) error {
				dep, err := h.K8sDeployment(ctx, upstream)
				if err != nil {
					return err
				}
				if got := dep.Spec.Template.Spec.Containers[0].Image; got != "nginx:1.28" {
					return errors.Errorf("the upstream runs the image %q, want %q",
						got, "nginx:1.28")
				}
				return nil
			})

		h.MustWaitServiceUpstream(t, svc.Metadata.Name)
	})

	t.Run("GarbageCollection", func(t *testing.T) {
		svc := newManagedService(t, h, "nginx", 80)
		hostname := h.SvcHostname(svc)
		upstream := k8sutils.GetSvcK8sUpstreamHostname(svc, "")

		h.MustWaitService(t, svc.Metadata.Name)
		h.MustWaitServiceUpstream(t, svc.Metadata.Name)
		h.WaitK8sObjectsPresent(t, hostname)

		h.DeleteService(t, svc)

		collected := h.WaitK8sObjectsGone(t, hostname)
		h.WaitK8sObjectsGone(t, upstream)

		zap.L().Info("Service garbage collection", zap.Duration("elapsed", collected))

		h.Eventually(t, "the deleted Service to disappear from the API",
			harness.DecisionBudget, func(ctx context.Context) error {
				_, err := h.CoreC().GetService(ctx,
					&metav1.GetOptions{Name: svc.Metadata.Name})
				if err == nil {
					return errors.Errorf("the Service still exists")
				}
				if !grpcerr.IsNotFound(err) {
					return err
				}
				return nil
			})
	})

	t.Run("NamespaceScopedNaming", func(t *testing.T) {
		ns := h.EnsureTestNamespace(t)

		svc := h.CreateService(t, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.%s", h.Name(), ns.Metadata.Name),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
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

		require.NotNil(t, svc.Status.NamespaceRef)
		assert.Equal(t, ns.Metadata.Name, svc.Status.NamespaceRef.Name)
		assert.True(t, svc.Status.Port > 0)

		h.MustWaitService(t, svc.Metadata.Name)

		h.Eventually(t, "the Service to be assigned addresses", propagationBudget,
			func(ctx context.Context) error {
				cur := h.GetService(t, svc.Metadata.Name)
				if len(cur.Status.Addresses) == 0 {
					return errors.Errorf("The Service has no addresses yet")
				}
				return nil
			})
	})
}

func testNocturneUpstreamReadiness(t *testing.T, h *harness.H) {
	value := h.Name()
	svc := newManagedHTTPService(t, h,
		[]*corev1.Service_Spec_Config_Upstream_Container_Env{
			{
				Name: "OCTELIUM_E2E_RESPONSE",
				Type: &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: value},
			},
		}, 2)
	h.MustWaitServiceUpstream(t, svc.Metadata.Name)
	h.MustWaitService(t, svc.Metadata.Name)
	upstream := k8sutils.GetSvcK8sUpstreamHostname(svc, "")
	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{svc.Metadata.Name: h.Port()},
	})
	c := h.HTTPNoRetry().SetBaseURL(conn.URL(svc.Metadata.Name))
	t.Cleanup(c.GetClient().CloseIdleConnections)
	check := func(ctx context.Context, want string) error {
		res, err := c.R().SetContext(ctx).Get("/")
		if err != nil {
			return err
		}
		if res.StatusCode() != http.StatusOK {
			return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
		}
		if res.String() != want {
			return errors.Errorf("the upstream returned %q, want %q", res.String(), want)
		}
		return nil
	}
	h.Eventually(t, "the initial upstream replicas to serve requests",
		harness.DeploymentBudget, func(ctx context.Context) error { return check(ctx, value) })

	updated := h.Name()
	svc = h.GetService(t, svc.Metadata.Name)
	container := svc.Spec.Config.Upstream.GetContainer()
	container.Env[0].Type = &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: updated}
	container.ReadinessProbe.GetHttpGet().Path = "/octelium-e2e-missing-readiness"
	container.ReadinessProbe.PeriodSeconds = 1
	container.ReadinessProbe.TimeoutSeconds = 1
	container.ReadinessProbe.FailureThreshold = 1
	svc = h.UpdateService(t, svc)

	h.Eventually(t, "the unhealthy replacement to leave the healthy upstream replicas serving traffic",
		harness.DeploymentBudget, func(ctx context.Context) error {
			dep, err := h.K8sDeployment(ctx, upstream)
			if err != nil {
				return err
			}
			if dep.Status.ObservedGeneration != dep.Generation ||
				dep.Status.UpdatedReplicas == 0 || dep.Status.ReadyReplicas != 2 {
				return errors.Errorf("the upstream rollout has not reached the readiness gate")
			}
			pods, err := h.ServicePods(ctx, svc.Metadata.Name)
			if err != nil {
				return err
			}
			var blocked bool
			for _, pod := range pods {
				for _, spec := range pod.Spec.Containers {
					if spec.Name != "backend" || spec.ReadinessProbe == nil ||
						spec.ReadinessProbe.HTTPGet == nil ||
						spec.ReadinessProbe.HTTPGet.Path != "/octelium-e2e-missing-readiness" {
						continue
					}
					for _, cs := range pod.Status.ContainerStatuses {
						if cs.Name == "backend" && cs.State.Running != nil && !cs.Ready {
							blocked = true
						}
					}
				}
			}
			if !blocked {
				return errors.Errorf("no replacement upstream is waiting for its readiness probe")
			}
			return check(ctx, value)
		})

	h.Consistently(t, "requests to keep using the healthy upstream replicas", decisionSettle,
		func(ctx context.Context) error { return check(ctx, value) })

	svc = h.GetService(t, svc.Metadata.Name)
	svc.Spec.Config.Upstream.GetContainer().ReadinessProbe.GetHttpGet().Path = "/"
	svc = h.UpdateService(t, svc)
	h.Eventually(t, "the corrected readiness probe to allow the replacement replicas to serve requests",
		harness.DeploymentBudget, func(ctx context.Context) error {
			dep, err := h.K8sDeployment(ctx, upstream)
			if err != nil {
				return err
			}
			if dep.Status.ObservedGeneration != dep.Generation ||
				dep.Status.UpdatedReplicas != 2 || dep.Status.ReadyReplicas != 2 || dep.Status.Replicas != 2 {
				return errors.Errorf("the upstream rollout is not complete")
			}
			return check(ctx, updated)
		})
	h.Consistently(t, "requests to use the replacement upstream replicas", decisionSettle,
		func(ctx context.Context) error { return check(ctx, updated) })
	waitServiceAddressesMatchPods(t, h, svc.Metadata.Name)
}

func testNocturneReconciliationLoad(t *testing.T, h *harness.H) {
	values := []string{h.Name(), h.Name()}
	var services []*corev1.Service
	publish := map[string]int{}
	for _, value := range values {
		svc := newManagedHTTPService(t, h,
			[]*corev1.Service_Spec_Config_Upstream_Container_Env{
				{
					Name: "OCTELIUM_E2E_RESPONSE",
					Type: &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: value},
				},
			}, 2)
		svc.Spec.Deployment = &corev1.Service_Spec_Deployment{Replicas: 2}
		svc = h.UpdateService(t, svc)
		h.MustWaitServiceUpstream(t, svc.Metadata.Name)
		h.MustWaitService(t, svc.Metadata.Name)
		services = append(services, svc)
		publish[svc.Metadata.Name] = h.Port()
	}
	conn := h.Connect(t, harness.ConnectOpts{Publish: publish})
	c := h.HTTPNoRetry()
	t.Cleanup(c.GetClient().CloseIdleConnections)
	var misroutes atomic.Int64
	succeeded := make([]atomic.Int64, len(services))
	check := func(ctx context.Context, idx int) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		res, err := c.R().SetContext(ctx).Get(conn.URL(services[idx].Metadata.Name))
		if err != nil {
			return err
		}
		if res.StatusCode() != http.StatusOK {
			return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
		}
		if res.String() != values[idx] {
			misroutes.Add(1)
			return errors.Errorf("the Service %s returned %q, want %q",
				services[idx].Metadata.Name, res.String(), values[idx])
		}
		succeeded[idx].Add(1)
		return nil
	}
	for idx := range services {
		h.Eventually(t, "the Service to serve its own upstream response", harness.DeploymentBudget,
			func(ctx context.Context) error { return check(ctx, idx) })
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan *harness.PoolResult, 1)
	go func() {
		defer close(done)
		done <- harness.RunFor(ctx, 5*time.Minute, 16, func(ctx context.Context, worker, iteration int) error {
			return check(ctx, (worker+iteration)%len(services))
		})
	}()
	defer cancel()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	for _, replicas := range []uint32{3, 1, 2} {
		for _, svc := range services {
			current := h.GetService(t, svc.Metadata.Name)
			current.Spec.Deployment.Replicas = replicas
			h.UpdateService(t, current)
		}
		seen := map[string]string{}
		for _, svc := range services {
			h.MustWaitService(t, svc.Metadata.Name)
			waitServiceAddresses(t, h, svc.Metadata.Name, int(replicas))
			for _, addr := range waitServiceAddressesMatchPods(t, h, svc.Metadata.Name) {
				assert.NotContains(t, seen, addr.PodRef.Uid,
					"a Pod must not appear in the addresses of multiple Services")
				seen[addr.PodRef.Uid] = svc.Metadata.Name
			}
		}
	}

	for _, svc := range services {
		addresses := waitServiceAddresses(t, h, svc.Metadata.Name, 2)
		victim := addresses[0].PodRef
		err := h.K8sC().CoreV1().Pods(vutils.K8sNS).Delete(t.Context(), victim.Name, k8smetav1.DeleteOptions{})
		require.Nil(t, err)
		waitServiceDropsPod(t, h, svc.Metadata.Name, victim)
		waitServiceAddresses(t, h, svc.Metadata.Name, 2)
		waitServiceAddressesMatchPods(t, h, svc.Metadata.Name)
	}
	for idx := range services {
		h.Eventually(t, "the Service to recover after Pod churn", harness.DeploymentBudget,
			func(ctx context.Context) error { return check(ctx, idx) })
		assert.Positive(t, succeeded[idx].Load())
	}
	cancel()
	result := <-done
	assert.Positive(t, result.Succeeded)
	assert.Zero(t, misroutes.Load(), "requests must never reach another Service's upstream")
	harness.LogPool("Nocturne reconciliation under HTTP load", result)
}

func testNocturneUpstreamCleanup(t *testing.T, h *harness.H) {
	sharedValue := h.Name()
	removedValue := h.Name()
	otherValue := h.Name()
	shared := h.CreateSecret(t, "", sharedValue)
	removed := h.CreateSecret(t, "", removedValue)
	env := func(name string) []*corev1.Service_Spec_Config_Upstream_Container_Env {
		return []*corev1.Service_Spec_Config_Upstream_Container_Env{
			{
				Name: "OCTELIUM_E2E_RESPONSE",
				Type: &corev1.Service_Spec_Config_Upstream_Container_Env_FromSecret{FromSecret: name},
			},
		}
	}
	svc := newManagedHTTPService(t, h, env(shared.Metadata.Name), 1)
	other := newManagedHTTPService(t, h,
		[]*corev1.Service_Spec_Config_Upstream_Container_Env{
			{Name: "OCTELIUM_E2E_RESPONSE", Type: &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: otherValue}},
		}, 1)
	defaultConfig := proto.Clone(svc.Spec.Config).(*corev1.Service_Spec_Config)
	keep := proto.Clone(defaultConfig).(*corev1.Service_Spec_Config)
	keep.Name = "keep"
	remove := proto.Clone(defaultConfig).(*corev1.Service_Spec_Config)
	remove.Name = "remove"
	remove.Upstream.GetContainer().Env = env(removed.Metadata.Name)
	rule := func(name string) *corev1.Service_Spec_DynamicConfig_Rule {
		return &corev1.Service_Spec_DynamicConfig_Rule{
			Condition: &corev1.Condition{Type: &corev1.Condition_Match{
				Match: fmt.Sprintf(`"x-e2e-config" in ctx.request.http.headers && ctx.request.http.headers["x-e2e-config"] == %q`, name),
			}},
			Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: name},
		}
	}
	svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
		Configs: []*corev1.Service_Spec_Config{keep, remove},
		Rules:   []*corev1.Service_Spec_DynamicConfig_Rule{rule("keep"), rule("remove")},
	}
	svc = h.UpdateService(t, svc)
	h.MustWaitService(t, svc.Metadata.Name, other.Metadata.Name)
	h.MustWaitServiceUpstream(t, svc.Metadata.Name, other.Metadata.Name)
	for _, name := range []string{"keep", "remove"} {
		h.MustWaitDeployment(t, k8sutils.GetSvcK8sUpstreamHostname(svc, name))
	}
	proxy := h.MustK8sDeployment(t, h.SvcHostname(svc))
	otherUpstream := h.MustK8sDeployment(t, k8sutils.GetSvcK8sUpstreamHostname(other, ""))
	sharedName := fmt.Sprintf("svc-env-%s-%s", svc.Metadata.Uid, shared.Metadata.Uid)
	sharedK8s, err := h.K8sC().CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), sharedName, k8smetav1.GetOptions{})
	require.Nil(t, err)
	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{svc.Metadata.Name: h.Port(), other.Metadata.Name: h.Port()},
	})
	c := h.HTTPNoRetry()
	t.Cleanup(c.GetClient().CloseIdleConnections)
	check := func(t *testing.T, name, config, want string) {
		t.Helper()
		h.Eventually(t, "the Service to serve its retained upstream", harness.DeploymentBudget,
			func(ctx context.Context) error {
				req := c.R().SetContext(ctx)
				if config != "" {
					req.SetHeader("X-E2E-Config", config)
				}
				res, err := req.Get(conn.URL(name))
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
				}
				if res.String() != want {
					return errors.Errorf("the Service returned %q, want %q", res.String(), want)
				}
				return nil
			})
	}
	waitGone := func(t *testing.T, config string) {
		t.Helper()
		h.WaitK8sObjectsGone(t, k8sutils.GetSvcK8sUpstreamHostname(svc, config))
		if config == "default" {
			config = defaultConfig.Name
		}
		h.Eventually(t, "the removed upstream Pods and ReplicaSets to be collected", harness.K8sGCBudget,
			func(ctx context.Context) error {
				opts := k8smetav1.ListOptions{LabelSelector: fmt.Sprintf(
					"octelium.com/svc-uid=%s,octelium.com/component=svc-k8s-upstream,octelium.com/svc-upstream-cfg=%s",
					svc.Metadata.Uid, config)}
				pods, err := h.K8sC().CoreV1().Pods(vutils.K8sNS).List(ctx, opts)
				if err != nil {
					return err
				}
				sets, err := h.K8sC().AppsV1().ReplicaSets(vutils.K8sNS).List(ctx, opts)
				if err != nil {
					return err
				}
				if len(pods.Items) != 0 || len(sets.Items) != 0 {
					return errors.Errorf("the removed upstream still has %d Pods and %d ReplicaSets", len(pods.Items), len(sets.Items))
				}
				return nil
			})
	}
	waitSecretGone := func(t *testing.T, name string) {
		t.Helper()
		h.Eventually(t, "the unused upstream Secret to be removed", harness.DecisionBudget,
			func(ctx context.Context) error {
				_, err := h.K8sC().CoreV1().Secrets(vutils.K8sNS).Get(ctx, name, k8smetav1.GetOptions{})
				if k8serr.IsNotFound(err) {
					return nil
				}
				if err != nil {
					return err
				}
				return errors.Errorf("the unused upstream Secret still exists")
			})
	}
	checkPreserved := func(t *testing.T) {
		t.Helper()
		assert.Equal(t, proxy.UID, h.MustK8sDeployment(t, proxy.Name).UID)
		assert.Equal(t, otherUpstream.UID, h.MustK8sDeployment(t, otherUpstream.Name).UID)
		for _, secret := range []*corev1.Secret{shared, removed} {
			current, err := h.CoreC().GetSecret(t.Context(), &metav1.GetOptions{Uid: secret.Metadata.Uid})
			require.Nil(t, err)
			assert.Equal(t, secret.Metadata.Uid, current.Metadata.Uid)
		}
		check(t, other.Metadata.Name, "", otherValue)
	}
	checkShared := func(t *testing.T) {
		t.Helper()
		current, err := h.K8sC().CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), sharedName, k8smetav1.GetOptions{})
		require.Nil(t, err)
		assert.Equal(t, sharedK8s.UID, current.UID)
	}
	check(t, svc.Metadata.Name, "", sharedValue)
	check(t, svc.Metadata.Name, "keep", sharedValue)
	check(t, svc.Metadata.Name, "remove", removedValue)

	if !t.Run("RemoveNamed", func(t *testing.T) {
		svc = h.GetService(t, svc.Metadata.Name)
		svc.Spec.DynamicConfig.Configs = svc.Spec.DynamicConfig.Configs[:1]
		svc.Spec.DynamicConfig.Rules = svc.Spec.DynamicConfig.Rules[:1]
		svc = h.UpdateService(t, svc)
		waitGone(t, "remove")
		waitSecretGone(t, fmt.Sprintf("svc-env-%s-%s", svc.Metadata.Uid, removed.Metadata.Uid))
		checkShared(t)
		check(t, svc.Metadata.Name, "", sharedValue)
		check(t, svc.Metadata.Name, "keep", sharedValue)
		checkPreserved(t)
	}) {
		return
	}
	if !t.Run("RenameNamed", func(t *testing.T) {
		svc = h.GetService(t, svc.Metadata.Name)
		svc.Spec.DynamicConfig.Configs[0].Name = "renamed"
		svc.Spec.DynamicConfig.Rules = []*corev1.Service_Spec_DynamicConfig_Rule{rule("renamed")}
		svc = h.UpdateService(t, svc)
		h.MustWaitDeployment(t, k8sutils.GetSvcK8sUpstreamHostname(svc, "renamed"))
		waitGone(t, "keep")
		checkShared(t)
		check(t, svc.Metadata.Name, "renamed", sharedValue)
		checkPreserved(t)
	}) {
		return
	}
	if !t.Run("DefaultToURL", func(t *testing.T) {
		svc = h.GetService(t, svc.Metadata.Name)
		svc.Spec.Config.Upstream = &corev1.Service_Spec_Config_Upstream{
			Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "http://" + k8sutils.GetSvcK8sUpstreamFQDN(other, "")},
		}
		svc = h.UpdateService(t, svc)
		waitGone(t, "default")
		checkShared(t)
		check(t, svc.Metadata.Name, "", otherValue)
		check(t, svc.Metadata.Name, "renamed", sharedValue)
		checkPreserved(t)
	}) {
		return
	}
	if !t.Run("RemoveAllNamed", func(t *testing.T) {
		svc = h.GetService(t, svc.Metadata.Name)
		svc.Spec.DynamicConfig = nil
		svc = h.UpdateService(t, svc)
		waitGone(t, "renamed")
		waitSecretGone(t, sharedName)
		check(t, svc.Metadata.Name, "", otherValue)
		checkPreserved(t)
	}) {
		return
	}
	t.Run("RestoreContainer", func(t *testing.T) {
		svc = h.GetService(t, svc.Metadata.Name)
		svc.Spec.Config = proto.Clone(defaultConfig).(*corev1.Service_Spec_Config)
		svc = h.UpdateService(t, svc)
		h.MustWaitServiceUpstream(t, svc.Metadata.Name)
		check(t, svc.Metadata.Name, "", sharedValue)
		current, err := h.K8sC().CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), sharedName, k8smetav1.GetOptions{})
		require.Nil(t, err)
		assert.NotEqual(t, sharedK8s.UID, current.UID)
		checkPreserved(t)
	})
}

func testNocturneSessionUpstreamLoad(t *testing.T, h *harness.H) {
	first := h.StartHTTPUpstream(t, nil)
	first.SetServeFn(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("first"))
	})
	second := h.StartHTTPUpstream(t, nil)
	second.SetServeFn(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("second"))
	})

	var services []*corev1.Service
	publish := make(map[string]int)
	for range 8 {
		svc := h.CreateService(t, &corev1.Service{
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: fmt.Sprintf("http://localhost:%d", first.Port),
						},
					},
				},
			},
		})
		h.MustWaitService(t, svc.Metadata.Name)
		services = append(services, svc)
		publish[svc.Metadata.Name] = h.Port()
	}

	conn := h.Connect(t, harness.ConnectOpts{ServeAll: true, Publish: publish})
	sessName := h.Status(t).Session.Metadata.Name
	sess := h.GetSession(t, sessName)
	require.NotNil(t, sess.Status.Connection)
	initial := sess.Status.Connection
	listenerPorts := make(map[string]int32)
	removed := make(map[string]bool)
	clients := make(map[string]*resty.Client)
	for _, svc := range services {
		c := h.HTTPNoRetry().SetBaseURL(conn.URL(svc.Metadata.Name))
		t.Cleanup(c.GetClient().CloseIdleConnections)
		clients[svc.Metadata.Uid] = c
	}

	waitUpstreams := func(t *testing.T, port int, body string) {
		t.Helper()
		h.Eventually(t, "all Session upstreams to match the current Services",
			harness.DecisionBudget, func(ctx context.Context) error {
				current, err := h.CoreC().GetSession(ctx, &metav1.GetOptions{Name: sessName})
				if err != nil {
					return err
				}
				if !current.Status.IsConnected || current.Status.Connection == nil {
					return errors.Errorf("the Session is no longer connected")
				}
				c := current.Status.Connection
				if !proto.Equal(initial.StartedAt, c.StartedAt) || c.Type != initial.Type ||
					!proto.Equal(initial.ServiceOptions, c.ServiceOptions) ||
					!slices.Equal(initial.X25519PublicKey, c.X25519PublicKey) ||
					!slices.EqualFunc(initial.Addresses, c.Addresses,
						func(a, b *metav1.DualStackNetwork) bool { return proto.Equal(a, b) }) {
					return errors.Errorf("the Session connection changed during upstream reconciliation")
				}
				ports := make(map[int32]bool)
				for _, u := range c.Upstreams {
					if ports[u.Port] {
						return errors.Errorf("multiple upstreams use listener port %d", u.Port)
					}
					ports[u.Port] = true
				}
				for _, svc := range services {
					u := connectionUpstream(c, svc)
					if removed[svc.Metadata.Uid] {
						if u != nil {
							return errors.Errorf("the deleted Service %s is still served", svc.Metadata.Name)
						}
						continue
					}
					if u == nil || u.Backend == nil || u.Backend.Host != "localhost" ||
						u.Backend.Port != int32(port) || u.Port == 0 {
						return errors.Errorf("the Service %s has not received its current backend", svc.Metadata.Name)
					}
					if old, ok := listenerPorts[svc.Metadata.Uid]; ok && old != u.Port {
						return errors.Errorf("the Service %s listener port changed", svc.Metadata.Name)
					}
					listenerPorts[svc.Metadata.Uid] = u.Port
				}
				return nil
			})

		h.Eventually(t, "every retained Service to reach its current client backend",
			harness.DecisionBudget, func(ctx context.Context) error {
				for _, svc := range services {
					if removed[svc.Metadata.Uid] {
						continue
					}
					res, err := clients[svc.Metadata.Uid].R().SetContext(ctx).Get("/")
					if err != nil {
						return err
					}
					if res.StatusCode() != http.StatusOK || res.String() != body {
						return errors.Errorf("the Service %s returned status %d and body %q, want %q",
							svc.Metadata.Name, res.StatusCode(), res.String(), body)
					}
				}
				return nil
			})
	}

	for _, tc := range []struct {
		name string
		port int
		body string
	}{
		{"AddHosts", first.Port, "first"},
		{"ChangeBackends", second.Port, "second"},
		{"RestoreBackends", first.Port, "first"},
	} {
		if !t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), harness.DecisionBudget)
			defer cancel()
			start := make(chan struct{})
			errs := make(chan error, len(services))
			for i, svc := range services {
				svc.Spec.Config.Upstream.User = "root"
				svc.Spec.Config.Upstream.Type = &corev1.Service_Spec_Config_Upstream_Url{
					Url: fmt.Sprintf("http://localhost:%d", tc.port),
				}
				go func() {
					<-start
					res, err := h.CoreC().UpdateService(ctx, svc)
					if err == nil {
						services[i] = res
					}
					errs <- err
				}()
			}
			close(start)
			var failed bool
			for range len(services) {
				if !assert.Nil(t, <-errs) {
					failed = true
				}
			}
			if failed {
				return
			}
			waitUpstreams(t, tc.port, tc.body)
		}) {
			return
		}
	}

	t.Run("DeleteHosts", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), harness.DecisionBudget)
		defer cancel()
		start := make(chan struct{})
		errs := make(chan error, len(services)/2)
		for i, svc := range services {
			if i%2 != 0 {
				continue
			}
			removed[svc.Metadata.Uid] = true
			go func() {
				<-start
				_, err := h.CoreC().DeleteService(ctx, &metav1.DeleteOptions{Uid: svc.Metadata.Uid})
				errs <- err
			}()
		}
		close(start)
		var failed bool
		for range len(services) / 2 {
			if !assert.Nil(t, <-errs) {
				failed = true
			}
		}
		if failed {
			return
		}
		waitUpstreams(t, first.Port, "first")
	})
}

func testNocturneEnvironmentSecretFailure(t *testing.T, h *harness.H) {
	value := h.Name()
	source := h.CreateSecret(t, "", value)
	svc := newManagedHTTPService(t, h,
		[]*corev1.Service_Spec_Config_Upstream_Container_Env{
			{
				Name: "OCTELIUM_E2E_RESPONSE",
				Type: &corev1.Service_Spec_Config_Upstream_Container_Env_FromSecret{FromSecret: source.Metadata.Name},
			},
			{
				Name: "OCTELIUM_E2E_REVISION",
				Type: &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: "original"},
			},
		}, 2)
	h.MustWaitServiceUpstream(t, svc.Metadata.Name)
	h.MustWaitService(t, svc.Metadata.Name)
	upstream := k8sutils.GetSvcK8sUpstreamHostname(svc, "")
	conn := h.Connect(t, harness.ConnectOpts{
		Publish: map[string]int{svc.Metadata.Name: h.Port()},
	})
	c := h.HTTPNoRetry().SetBaseURL(conn.URL(svc.Metadata.Name))
	t.Cleanup(c.GetClient().CloseIdleConnections)
	check := func(ctx context.Context, want string) error {
		res, err := c.R().SetContext(ctx).Get("/")
		if err != nil {
			return err
		}
		if res.StatusCode() != http.StatusOK {
			return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
		}
		if res.String() != want {
			return errors.Errorf("the upstream returned %q, want %q", res.String(), want)
		}
		return nil
	}
	h.Eventually(t, "both initial replicas to serve the Secret value",
		harness.DeploymentBudget, func(ctx context.Context) error {
			dep, err := h.K8sDeployment(ctx, upstream)
			if err != nil {
				return err
			}
			if dep.Status.ObservedGeneration != dep.Generation ||
				dep.Status.UpdatedReplicas != 2 || dep.Status.ReadyReplicas != 2 || dep.Status.Replicas != 2 {
				return errors.Errorf("the initial upstream rollout is not complete")
			}
			return check(ctx, value)
		})
	original := h.MustK8sDeployment(t, upstream)
	mirrors := h.K8sC().CoreV1().Secrets(vutils.K8sNS)
	mirrorName := fmt.Sprintf("svc-env-%s-%s", svc.Metadata.Uid, source.Metadata.Uid)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	mirror, err := mirrors.Get(ctx, mirrorName, k8smetav1.GetOptions{})
	cancel()
	require.Nil(t, err)
	require.Equal(t, value, string(mirror.Data["data"]))
	mirror.Immutable = new(true)
	ctx, cancel = context.WithTimeout(t.Context(), 30*time.Second)
	mirror, err = mirrors.Update(ctx, mirror, k8smetav1.UpdateOptions{})
	cancel()
	require.Nil(t, err)

	updated := h.Name()
	h.UpdateSecret(t, source.Metadata.Name, updated)
	svc = h.GetService(t, svc.Metadata.Name)
	svc.Spec.Config.Upstream.GetContainer().Env[1].Type = &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: "updated"}
	svc = h.UpdateService(t, svc)

	if !t.Run("FailedMirrorUpdate", func(t *testing.T) {
		h.Consistently(t, "a failed Secret update to preserve the working Deployment and responses",
			3*decisionSettle, func(ctx context.Context) error {
				dep, err := h.K8sDeployment(ctx, upstream)
				if err != nil {
					return err
				}
				if dep.UID != original.UID || dep.Generation != original.Generation || dep.Status.ReadyReplicas != 2 {
					return errors.Errorf("the failed Secret update changed the working Deployment")
				}
				current, err := mirrors.Get(ctx, mirrorName, k8smetav1.GetOptions{})
				if err != nil {
					return err
				}
				if current.UID != mirror.UID || string(current.Data["data"]) != value {
					return errors.Errorf("the failed Secret update changed the existing mirror")
				}
				return check(ctx, value)
			})
	}) {
		return
	}

	t.Run("Recovery", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		err := mirrors.Delete(ctx, mirrorName, k8smetav1.DeleteOptions{
			Preconditions: &k8smetav1.Preconditions{UID: new(mirror.UID)},
		})
		cancel()
		require.Nil(t, err)
		svc = h.GetService(t, svc.Metadata.Name)
		svc.Metadata.DisplayName = h.Name()
		svc = h.UpdateService(t, svc)

		h.Eventually(t, "the recovered Secret mirror to allow the replacement replicas to serve requests",
			harness.DeploymentBudget, func(ctx context.Context) error {
				dep, err := h.K8sDeployment(ctx, upstream)
				if err != nil {
					return err
				}
				if dep.UID != original.UID || dep.Generation <= original.Generation ||
					dep.Status.ObservedGeneration != dep.Generation || dep.Status.UpdatedReplicas != 2 ||
					dep.Status.ReadyReplicas != 2 || dep.Status.Replicas != 2 {
					return errors.Errorf("the recovered upstream rollout is not complete")
				}
				current, err := mirrors.Get(ctx, mirrorName, k8smetav1.GetOptions{})
				if err != nil {
					return err
				}
				if current.UID == mirror.UID || string(current.Data["data"]) != updated {
					return errors.Errorf("the Secret mirror has not been replaced with the updated value")
				}
				return check(ctx, updated)
			})
		h.Consistently(t, "every request to use the recovered Secret value", decisionSettle,
			func(ctx context.Context) error { return check(ctx, updated) })
	})
}

func testNocturneRegistryCredentials(t *testing.T, h *harness.H) {
	password := h.Name()
	source := h.CreateSecret(t, "", password)
	response := h.Name()
	svc := newManagedHTTPService(t, h, []*corev1.Service_Spec_Config_Upstream_Container_Env{
		{Name: "OCTELIUM_E2E_RESPONSE", Type: &corev1.Service_Spec_Config_Upstream_Container_Env_Value{Value: response}},
	}, 1)
	svc.Spec.Config.Upstream.GetContainer().Credentials = &corev1.Service_Spec_Config_Upstream_Container_Credentials{
		Type: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_{
			UsernamePassword: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword{
				Username: "first", Server: "first.example.com",
				Password: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_Password{
					Type: &corev1.Service_Spec_Config_Upstream_Container_Credentials_UsernamePassword_Password_FromSecret{FromSecret: source.Metadata.Name},
				},
			},
		},
	}
	same := proto.Clone(svc.Spec.Config).(*corev1.Service_Spec_Config)
	same.Name = "same"
	registry := proto.Clone(same).(*corev1.Service_Spec_Config)
	registry.Name = "registry"
	registry.Upstream.GetContainer().Credentials.GetUsernamePassword().Server = "second.example.com"
	username := proto.Clone(same).(*corev1.Service_Spec_Config)
	username.Name = "username"
	username.Upstream.GetContainer().Credentials.GetUsernamePassword().Username = "second"
	svc = h.UpdateService(t, svc)
	configs := []*corev1.Service_Spec_Config{svc.Spec.Config}
	waitCredentials := func(t *testing.T, previous map[string]*k8scorev1.Secret) map[string]*k8scorev1.Secret {
		t.Helper()
		var ret map[string]*k8scorev1.Secret
		h.Eventually(t, "every upstream to retain its own registry credentials", harness.DeploymentBudget,
			func(ctx context.Context) error {
				secrets := make(map[string]*k8scorev1.Secret)
				contexts := make(map[string]string)
				for _, cfg := range configs {
					dep, err := h.K8sC().AppsV1().Deployments(vutils.K8sNS).Get(ctx,
						k8sutils.GetSvcK8sUpstreamHostname(svc, cfg.Name), k8smetav1.GetOptions{})
					if err != nil {
						return err
					}
					if dep.Status.ObservedGeneration < dep.Generation || dep.Status.ReadyReplicas != 1 ||
						dep.Status.UpdatedReplicas != 1 || dep.Status.Replicas != 1 {
						return errors.Errorf("the upstream %s has not completed its rollout", cfg.Name)
					}
					if len(dep.Spec.Template.Spec.ImagePullSecrets) != 1 {
						return errors.Errorf("the upstream %s does not have one image pull Secret", cfg.Name)
					}
					secret, err := h.K8sC().CoreV1().Secrets(vutils.K8sNS).Get(ctx,
						dep.Spec.Template.Spec.ImagePullSecrets[0].Name, k8smetav1.GetOptions{})
					if err != nil {
						return err
					}
					owner := k8smetav1.GetControllerOf(secret)
					if secret.Type != k8scorev1.SecretTypeDockerConfigJson || owner == nil ||
						owner.APIVersion != "v1" || owner.Kind != "ConfigMap" || owner.Name != h.SvcHostname(svc) {
						return errors.Errorf("the upstream %s has an invalid credential Secret", cfg.Name)
					}
					var config struct {
						Auths map[string]struct{ Auth string } `json:"auths"`
					}
					if err := json.Unmarshal(secret.Data[k8scorev1.DockerConfigJsonKey], &config); err != nil {
						return err
					}
					creds := cfg.Upstream.GetContainer().Credentials.GetUsernamePassword()
					entry, ok := config.Auths[creds.Server]
					if !ok || len(config.Auths) != 1 {
						return errors.Errorf("the upstream %s is missing its registry credentials", cfg.Name)
					}
					auth, err := base64.StdEncoding.DecodeString(entry.Auth)
					if err != nil {
						return err
					}
					if string(auth) != creds.Username+":"+password {
						return errors.Errorf("the upstream %s has incorrect registry credentials", cfg.Name)
					}
					key := fmt.Sprintf("%q:%q", creds.Server, creds.Username)
					if name, ok := contexts[key]; ok && name != secret.Name {
						return errors.Errorf("identical registry credentials do not share one Secret")
					}
					for other, name := range contexts {
						if other != key && name == secret.Name {
							return errors.Errorf("different registry credentials share one Secret")
						}
					}
					contexts[key] = secret.Name
					if original := previous[cfg.Name]; original != nil &&
						(original.Name != secret.Name || original.UID != secret.UID) {
						return errors.Errorf("the upstream %s replaced its credential Secret", cfg.Name)
					}
					secrets[cfg.Name] = secret
				}
				ret = secrets
				return nil
			})
		return ret
	}
	legacy := waitCredentials(t, nil)[svc.Spec.Config.Name]
	assert.Equal(t, fmt.Sprintf("regcred-%s-%s", svc.Metadata.Uid, source.Metadata.Uid), legacy.Name)
	upstream := h.MustK8sDeployment(t, k8sutils.GetSvcK8sUpstreamHostname(svc, svc.Spec.Config.Name))
	svc = h.GetService(t, svc.Metadata.Name)
	svc.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
		Configs: []*corev1.Service_Spec_Config{same, registry, username},
	}
	svc = h.UpdateService(t, svc)
	configs = append(configs, same, registry, username)
	original := waitCredentials(t, nil)
	assert.NotEqual(t, legacy.Name, original[svc.Spec.Config.Name].Name)
	assert.Equal(t, upstream.UID, h.MustK8sDeployment(t, upstream.Name).UID)
	h.MustWaitService(t, svc.Metadata.Name)
	conn := h.Connect(t, harness.ConnectOpts{Publish: map[string]int{svc.Metadata.Name: h.Port()}})
	c := h.HTTPNoRetry()
	t.Cleanup(c.GetClient().CloseIdleConnections)
	check := func(ctx context.Context) error {
		res, err := c.R().SetContext(ctx).Get(conn.URL(svc.Metadata.Name))
		if err != nil {
			return err
		}
		if res.StatusCode() != http.StatusOK {
			return errUnexpectedStatus(res.StatusCode(), http.StatusOK)
		}
		if res.String() != response {
			return errors.Errorf("the Service returned an unexpected response")
		}
		return nil
	}
	h.Eventually(t, "the Service to serve its default upstream", harness.DeploymentBudget, check)
	if !t.Run("Reorder", func(t *testing.T) {
		svc = h.GetService(t, svc.Metadata.Name)
		slices.Reverse(svc.Spec.DynamicConfig.Configs)
		svc.Metadata.DisplayName = h.Name()
		svc = h.UpdateService(t, svc)
		waitCredentials(t, original)
		h.Consistently(t, "requests to survive credential reconciliation", decisionSettle, check)
	}) {
		return
	}
	if !t.Run("RotatePassword", func(t *testing.T) {
		password = h.Name()
		h.UpdateSecret(t, source.Metadata.Name, password)
		svc = h.GetService(t, svc.Metadata.Name)
		svc.Metadata.DisplayName = h.Name()
		svc = h.UpdateService(t, svc)
		waitCredentials(t, original)
		h.Consistently(t, "requests to survive password rotation", decisionSettle, check)
	}) {
		return
	}
	t.Run("RemoveNamed", func(t *testing.T) {
		svc = h.GetService(t, svc.Metadata.Name)
		svc.Spec.DynamicConfig = nil
		svc = h.UpdateService(t, svc)
		for _, cfg := range configs[1:] {
			h.WaitK8sObjectsGone(t, k8sutils.GetSvcK8sUpstreamHostname(svc, cfg.Name))
		}
		configs = configs[:1]
		remaining := waitCredentials(t, nil)[configs[0].Name]
		assert.Equal(t, fmt.Sprintf("regcred-%s-%s", svc.Metadata.Uid, source.Metadata.Uid), remaining.Name)
		h.Eventually(t, "upstream Pods to release the old credential Secrets", harness.K8sGCBudget,
			func(ctx context.Context) error {
				pods, err := h.K8sC().CoreV1().Pods(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{
					LabelSelector: fmt.Sprintf("octelium.com/svc-uid=%s,octelium.com/component=svc-k8s-upstream", svc.Metadata.Uid),
				})
				if err != nil {
					return err
				}
				if len(pods.Items) != 1 {
					return errors.Errorf("the Service still has %d upstream Pods", len(pods.Items))
				}
				for _, ref := range pods.Items[0].Spec.ImagePullSecrets {
					if ref.Name != remaining.Name {
						return errors.Errorf("an upstream Pod still references an old credential Secret")
					}
				}
				return nil
			})
		svc = h.GetService(t, svc.Metadata.Name)
		svc.Metadata.DisplayName = h.Name()
		svc = h.UpdateService(t, svc)
		h.Eventually(t, "the unused registry credential Secrets to be removed", harness.DecisionBudget,
			func(ctx context.Context) error {
				for _, secret := range original {
					_, err := h.K8sC().CoreV1().Secrets(vutils.K8sNS).Get(ctx, secret.Name, k8smetav1.GetOptions{})
					if k8serr.IsNotFound(err) {
						continue
					}
					if err != nil {
						return err
					}
					return errors.Errorf("an unused registry credential Secret still exists")
				}
				return nil
			})
		h.Consistently(t, "requests to survive named upstream removal", decisionSettle, check)
	})
}
