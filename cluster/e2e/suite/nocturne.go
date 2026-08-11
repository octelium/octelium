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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
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
