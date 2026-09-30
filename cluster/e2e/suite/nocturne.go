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
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

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
	k8scorev1 "k8s.io/api/core/v1"
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
