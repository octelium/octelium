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

package k8sutils

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func TestDeploymentReplicasKubernetesE2E(t *testing.T) {
	kubeconfig := os.Getenv("OCTELIUM_GEN016_TEST_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("OCTELIUM_GEN016_TEST_KUBECONFIG is not set")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	require.NoError(t, err)
	client, err := kubernetes.NewForConfig(cfg)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	namespace, err := client.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "gen016-e2e-"}}, metav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := client.CoreV1().Namespaces().Delete(ctx, namespace.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &namespace.UID}})
		if !k8serr.IsNotFound(err) {
			assert.NoError(t, err)
		}
	})
	desired := replicaDeployment(nil, "example.invalid/gen016:original")
	desired.Namespace = namespace.Name
	desired.Spec.Template.Spec.NodeSelector = map[string]string{"octelium.com/gen016-e2e": string(namespace.UID)}
	original := desired.DeepCopy()
	deployment, err := CreateOrUpdateDeployment(ctx, client, desired)
	require.NoError(t, err)
	assert.Equal(t, new(int32(1)), deployment.Spec.Replicas)
	assert.Nil(t, desired.Spec.Replicas)
	assert.Equal(t, original.Spec, desired.Spec)
	hpa, err := client.AutoscalingV2().HorizontalPodAutoscalers(namespace.Name).Create(ctx, &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "workload"},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Name: deployment.Name},
			MinReplicas:    new(int32(1)), MaxReplicas: 10,
			Metrics: []autoscalingv2.MetricSpec{{Type: autoscalingv2.ExternalMetricSourceType, External: &autoscalingv2.ExternalMetricSource{
				Metric: autoscalingv2.MetricIdentifier{Name: namespace.Name},
				Target: autoscalingv2.MetricTarget{Type: autoscalingv2.AverageValueMetricType, AverageValue: new(resource.MustParse("1"))},
			}}},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	uid := deployment.UID
	for _, count := range []int32{3, 0, 7} {
		_, err := client.AppsV1().Deployments(namespace.Name).UpdateScale(ctx, deployment.Name, &autoscalingv1.Scale{
			ObjectMeta: metav1.ObjectMeta{Name: deployment.Name}, Spec: autoscalingv1.ScaleSpec{Replicas: count},
		}, metav1.UpdateOptions{})
		require.NoError(t, err)
		for range 2 {
			desired.Spec.Template.Spec.Containers[0].Image = "example.invalid/gen016:upgraded"
			deployment, err = CreateOrUpdateDeployment(ctx, client, desired)
			require.NoError(t, err)
			assert.Equal(t, new(count), deployment.Spec.Replicas)
			assert.Equal(t, uid, deployment.UID)
			assert.Equal(t, desired.Spec.Template.Spec.Containers[0].Image, deployment.Spec.Template.Spec.Containers[0].Image)
			assert.Nil(t, desired.Spec.Replicas)
		}
	}
	currentHPA, err := client.AutoscalingV2().HorizontalPodAutoscalers(namespace.Name).Get(ctx, hpa.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, hpa.UID, currentHPA.UID)
	assert.Equal(t, hpa.Spec, currentHPA.Spec)
	for _, count := range []int32{2, 0, 1} {
		desired.Spec.Replicas = new(count)
		deployment, err = CreateOrUpdateDeployment(ctx, client, desired)
		require.NoError(t, err)
		assert.Equal(t, new(count), deployment.Spec.Replicas)
	}
	created := desired.DeepCopy()
	created.Name, created.Spec.Replicas = "created-zero", new(int32(0))
	created.Spec.Selector.MatchLabels["app"] = "created-zero"
	created.Spec.Template.Labels["app"] = "created-zero"
	zero, err := CreateOrUpdateDeployment(ctx, client, created)
	require.NoError(t, err)
	assert.Equal(t, new(int32(0)), zero.Spec.Replicas)
}
