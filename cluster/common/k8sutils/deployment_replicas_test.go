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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func replicaDeployment(replicas *int32, image string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "workload", Namespace: "octelium"},
		Spec: appsv1.DeploymentSpec{
			Replicas: replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "workload"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "workload"}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "workload", Image: image}}},
			},
		},
	}
}

func TestDeploymentReplicaOwnership(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		stored, desired, want *int32
	}{
		{name: "legacy-nil"},
		{name: "preserve-zero", stored: new(int32(0)), want: new(int32(0))},
		{name: "preserve-one", stored: new(int32(1)), want: new(int32(1))},
		{name: "preserve-scaled", stored: new(int32(3)), want: new(int32(3))},
		{name: "explicit-from-nil", desired: new(int32(4)), want: new(int32(4))},
		{name: "explicit-zero", stored: new(int32(3)), desired: new(int32(0)), want: new(int32(0))},
		{name: "explicit-one", stored: new(int32(3)), desired: new(int32(1)), want: new(int32(1))},
		{name: "explicit-up", stored: new(int32(2)), desired: new(int32(5)), want: new(int32(5))},
		{name: "explicit-down", stored: new(int32(5)), desired: new(int32(2)), want: new(int32(2))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stored := replicaDeployment(tc.stored, "old-image")
			stored.UID, stored.ResourceVersion = "existing-uid", "1"
			stored.Labels, stored.Annotations = map[string]string{"custom": "preserved"}, map[string]string{"custom": "preserved"}
			c := fake.NewSimpleClientset(stored)
			desired := replicaDeployment(tc.desired, "new-image")
			desired.Spec.MinReadySeconds = 12
			input := desired.DeepCopy()
			for range 3 {
				result, err := CreateOrUpdateDeployment(t.Context(), c, desired)
				require.NoError(t, err)
				assert.Equal(t, tc.want, result.Spec.Replicas)
				assert.Equal(t, stored.UID, result.UID)
				assert.Equal(t, "new-image", result.Spec.Template.Spec.Containers[0].Image)
				assert.Equal(t, int32(12), result.Spec.MinReadySeconds)
				assert.Equal(t, "preserved", result.Annotations["custom"])
				assert.Equal(t, "preserved", result.Labels["custom"])
				assert.Equal(t, input, desired)
			}
			assert.Equal(t, tc.stored, stored.Spec.Replicas)
			assert.Equal(t, "old-image", stored.Spec.Template.Spec.Containers[0].Image)
		})
	}
}

func TestDeploymentReplicaCreation(t *testing.T) {
	for _, replicas := range []*int32{nil, new(int32(0)), new(int32(1)), new(int32(4))} {
		t.Run(fmt.Sprint(replicas), func(t *testing.T) {
			c := fake.NewSimpleClientset()
			desired := replicaDeployment(replicas, "new-image")
			input := desired.DeepCopy()
			result, err := CreateOrUpdateDeployment(t.Context(), c, desired)
			require.NoError(t, err)
			assert.Equal(t, replicas, result.Spec.Replicas)
			assert.Equal(t, input, desired)
			require.Len(t, c.Actions(), 1)
			assert.Equal(t, "create", c.Actions()[0].GetVerb())
			assert.Equal(t, input, c.Actions()[0].(k8stesting.CreateAction).GetObject())
		})
	}
}

func TestDeploymentReplicaRetriesUseLatestScale(t *testing.T) {
	previous := defaultRetryBackoff
	defaultRetryBackoff = wait.Backoff{Steps: 5, Duration: time.Millisecond}
	t.Cleanup(func() { defaultRetryBackoff = previous })
	for _, stage := range []string{"conflict-up", "conflict-zero", "update-before", "update-after", "readback-outage", "create-after"} {
		t.Run(stage, func(t *testing.T) {
			stored := replicaDeployment(new(int32(3)), "old-image")
			stored.UID, stored.ResourceVersion = "existing-uid", "1"
			c := fake.NewSimpleClientset(stored)
			desired := replicaDeployment(nil, "new-image")
			input := desired.DeepCopy()
			writes, reads := 0, 0
			failed := false
			wanted := int32(8)
			if stage == "conflict-zero" {
				wanted = 0
			}
			c.PrependReactor("*", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if action.GetVerb() == "create" && stage == "create-after" {
					current := desired.DeepCopy()
					current.UID, current.ResourceVersion, current.Spec.Replicas = "existing-uid", "2", new(wanted)
					require.NoError(t, c.Tracker().Update(action.GetResource(), current, action.GetNamespace()))
					failed = true
					return true, nil, io.ErrUnexpectedEOF
				}
				if action.GetVerb() == "get" {
					reads++
					if stage == "readback-outage" && reads == 2 {
						return true, nil, k8serr.NewServiceUnavailable("readback unavailable")
					}
				}
				if action.GetVerb() != "update" {
					return false, nil, nil
				}
				writes++
				if failed {
					return false, nil, nil
				}
				failed = true
				if stage == "update-after" || stage == "readback-outage" {
					applied := action.(k8stesting.UpdateAction).GetObject().(*appsv1.Deployment).DeepCopy()
					applied.ResourceVersion, applied.Spec.Replicas = "2", new(wanted)
					require.NoError(t, c.Tracker().Update(action.GetResource(), applied, action.GetNamespace()))
				} else {
					scaled := stored.DeepCopy()
					scaled.Spec.Replicas, scaled.ResourceVersion = new(wanted), "2"
					scaled.Labels = map[string]string{"autoscaler": "preserved"}
					require.NoError(t, c.Tracker().Update(action.GetResource(), scaled, action.GetNamespace()))
				}
				if stage == "conflict-up" || stage == "conflict-zero" {
					return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), stored.Name, io.EOF)
				}
				return true, nil, io.ErrUnexpectedEOF
			})
			result, err := CreateOrUpdateDeployment(t.Context(), c, desired)
			require.NoError(t, err)
			require.True(t, failed)
			assert.Equal(t, new(wanted), result.Spec.Replicas)
			assert.Equal(t, "new-image", result.Spec.Template.Spec.Containers[0].Image)
			assert.Equal(t, input, desired)
			if stage == "update-after" || stage == "readback-outage" {
				assert.Equal(t, 1, writes)
			}
			if stage == "conflict-up" || stage == "conflict-zero" || stage == "update-before" {
				assert.Equal(t, 2, writes)
				assert.Equal(t, "preserved", result.Labels["autoscaler"])
			}
		})
	}
}

func TestDeploymentReplicasDoNotRequireAutoscalerReads(t *testing.T) {
	stored := replicaDeployment(new(int32(7)), "old-image")
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{Name: "autoscaler", Namespace: stored.Namespace, UID: "hpa-uid"},
		Spec:       autoscalingv2.HorizontalPodAutoscalerSpec{ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Name: stored.Name}, MaxReplicas: 10},
	}
	c := fake.NewSimpleClientset(stored, hpa)
	result, err := CreateOrUpdateDeployment(t.Context(), c, replicaDeployment(nil, "new-image"))
	require.NoError(t, err)
	assert.Equal(t, new(int32(7)), result.Spec.Replicas)
	for _, action := range c.Actions() {
		assert.Equal(t, "deployments", action.GetResource().Resource)
	}
	unchanged, err := c.Tracker().Get(autoscalingv2.SchemeGroupVersion.WithResource("horizontalpodautoscalers"), hpa.Namespace, hpa.Name)
	require.NoError(t, err)
	assert.Equal(t, hpa, unchanged)
}

func TestDeploymentReplicaFailureAndCancellation(t *testing.T) {
	previous := defaultRetryBackoff
	defaultRetryBackoff = wait.Backoff{Steps: 3, Duration: time.Millisecond}
	t.Cleanup(func() { defaultRetryBackoff = previous })
	for _, failure := range []string{"forbidden", "conflicts", "canceled"} {
		t.Run(failure, func(t *testing.T) {
			stored := replicaDeployment(new(int32(4)), "old-image")
			c := fake.NewSimpleClientset(stored)
			desired := replicaDeployment(nil, "new-image")
			writes := 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if failure == "canceled" {
				cancel()
			}
			c.PrependReactor("update", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
				writes++
				if failure == "forbidden" {
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), stored.Name, io.EOF)
				}
				return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), stored.Name, io.EOF)
			})
			_, err := CreateOrUpdateDeployment(ctx, c, desired)
			switch failure {
			case "forbidden":
				require.True(t, k8serr.IsForbidden(err))
				assert.Equal(t, 1, writes)
			case "conflicts":
				require.True(t, k8serr.IsConflict(err))
				assert.Equal(t, 3, writes)
			case "canceled":
				require.ErrorIs(t, err, context.Canceled)
				assert.Empty(t, c.Actions())
			}
			current, err := c.Tracker().Get(appsv1.SchemeGroupVersion.WithResource("deployments"), stored.Namespace, stored.Name)
			require.NoError(t, err)
			assert.Equal(t, stored, current)
			assert.Nil(t, desired.Spec.Replicas)
		})
	}
}

func TestDeploymentReplicaExplicitCountWinsAfterConflict(t *testing.T) {
	previous := defaultRetryBackoff
	defaultRetryBackoff = wait.Backoff{Steps: 3, Duration: time.Millisecond}
	t.Cleanup(func() { defaultRetryBackoff = previous })
	stored := replicaDeployment(new(int32(3)), "old-image")
	stored.UID, stored.ResourceVersion = "original", "1"
	c := fake.NewSimpleClientset(stored)
	writes := 0
	c.PrependReactor("update", "deployments", func(action k8stesting.Action) (bool, runtime.Object, error) {
		writes++
		if writes == 1 {
			scaled := stored.DeepCopy()
			scaled.Spec.Replicas, scaled.ResourceVersion = new(int32(9)), "2"
			require.NoError(t, c.Tracker().Update(action.GetResource(), scaled, action.GetNamespace()))
			return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), stored.Name, io.EOF)
		}
		assert.Equal(t, "2", action.(k8stesting.UpdateAction).GetObject().(*appsv1.Deployment).ResourceVersion)
		return false, nil, nil
	})
	result, err := CreateOrUpdateDeployment(t.Context(), c, replicaDeployment(new(int32(2)), "new-image"))
	require.NoError(t, err)
	assert.Equal(t, new(int32(2)), result.Spec.Replicas)
	assert.Equal(t, 2, writes)
}

func TestDeploymentReplicaDefaultingAndScalingHTTP(t *testing.T) {
	for _, state := range []string{"new-default", "new-zero", "scaled", "zero", "explicit-one", "explicit-zero", "get-outage", "scale-conflict", "update-before", "update-after", "readback-outage"} {
		t.Run(state, func(t *testing.T) {
			var mu sync.Mutex
			var stored *appsv1.Deployment
			wanted := int32(7)
			if state != "new-default" && state != "new-zero" {
				stored = replicaDeployment(new(wanted), "old-image")
				stored.UID, stored.ResourceVersion = "server-uid", "1"
				stored.TypeMeta = metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}
			}
			desired := replicaDeployment(nil, "new-image")
			switch state {
			case "new-default":
				wanted = 1
			case "new-zero", "explicit-zero":
				desired.Spec.Replicas, wanted = new(int32(0)), 0
			case "zero":
				stored.Spec.Replicas, wanted = new(int32(0)), 0
			case "explicit-one":
				desired.Spec.Replicas, wanted = new(int32(1)), 1
			case "scale-conflict", "update-before", "update-after", "readback-outage":
				wanted = 9
			}
			input := desired.DeepCopy()
			reads, writes, committed, scaleWrites, unexpected := 0, 0, 0, 0, 0
			failureInjected := false
			version := 1
			status := func(w http.ResponseWriter, code int, reason metav1.StatusReason) {
				w.WriteHeader(code)
				assert.NoError(t, json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: reason, Code: int32(code)}))
			}
			advance := func() {
				version++
				stored.ResourceVersion = strconv.Itoa(version)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				const path = "/apis/apps/v1/namespaces/octelium/deployments/workload"
				if r.Method == http.MethodPut && r.URL.Path == path+"/scale" {
					scale := &autoscalingv1.Scale{}
					if !assert.NoError(t, json.NewDecoder(r.Body).Decode(scale)) {
						status(w, http.StatusBadRequest, metav1.StatusReasonBadRequest)
						return
					}
					if scale.ResourceVersion != stored.ResourceVersion {
						status(w, http.StatusConflict, metav1.StatusReasonConflict)
						return
					}
					scaleWrites++
					stored.Spec.Replicas = new(scale.Spec.Replicas)
					advance()
					scale.ObjectMeta = stored.ObjectMeta
					scale.TypeMeta = metav1.TypeMeta{Kind: "Scale", APIVersion: "autoscaling/v1"}
					assert.NoError(t, json.NewEncoder(w).Encode(scale))
					return
				}
				if r.Method == http.MethodPost && r.URL.Path == "/apis/apps/v1/namespaces/octelium/deployments" {
					if stored != nil {
						status(w, http.StatusConflict, metav1.StatusReasonAlreadyExists)
						return
					}
					current := &appsv1.Deployment{}
					if !assert.NoError(t, json.NewDecoder(r.Body).Decode(current)) {
						status(w, http.StatusBadRequest, metav1.StatusReasonBadRequest)
						return
					}
					assert.Equal(t, input.Spec.Replicas, current.Spec.Replicas)
					if current.Spec.Replicas == nil {
						current.Spec.Replicas = new(int32(1))
					}
					current.UID, current.ResourceVersion = "server-uid", "1"
					current.TypeMeta = metav1.TypeMeta{Kind: "Deployment", APIVersion: "apps/v1"}
					stored = current
					w.WriteHeader(http.StatusCreated)
					assert.NoError(t, json.NewEncoder(w).Encode(stored))
					return
				}
				if r.Method == http.MethodGet && r.URL.Path == path {
					reads++
					if (state == "get-outage" && reads == 1) || (state == "readback-outage" && reads == 2) {
						status(w, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable)
						return
					}
					assert.NoError(t, json.NewEncoder(w).Encode(stored))
					return
				}
				if r.Method == http.MethodPut && r.URL.Path == path {
					writes++
					current := &appsv1.Deployment{}
					if !assert.NoError(t, json.NewDecoder(r.Body).Decode(current)) {
						status(w, http.StatusBadRequest, metav1.StatusReasonBadRequest)
						return
					}
					if !failureInjected && (state == "scale-conflict" || state == "update-before") {
						failureInjected = true
						stored.Spec.Replicas = new(int32(9))
						advance()
						if state == "update-before" {
							status(w, http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable)
							return
						}
					}
					if current.ResourceVersion != stored.ResourceVersion {
						status(w, http.StatusConflict, metav1.StatusReasonConflict)
						return
					}
					if current.Spec.Replicas == nil {
						current.Spec.Replicas = new(int32(1))
					}
					assert.Equal(t, stored.UID, current.UID)
					stored = current
					committed++
					advance()
					if !failureInjected && (state == "update-after" || state == "readback-outage") {
						failureInjected = true
						stored.Spec.Replicas = new(int32(9))
						advance()
						conn, _, err := w.(http.Hijacker).Hijack()
						if assert.NoError(t, err) {
							assert.NoError(t, conn.Close())
						}
						return
					}
					assert.NoError(t, json.NewEncoder(w).Encode(stored))
					return
				}
				unexpected++
				status(w, http.StatusForbidden, metav1.StatusReasonForbidden)
			}))
			defer server.Close()
			client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: -1, ContentConfig: rest.ContentConfig{ContentType: "application/json"}})
			require.NoError(t, err)
			result, err := CreateOrUpdateDeployment(t.Context(), client, desired)
			require.NoError(t, err)
			assert.Equal(t, new(wanted), result.Spec.Replicas)
			assert.Equal(t, "new-image", result.Spec.Template.Spec.Containers[0].Image)
			assert.Equal(t, input.Spec, desired.Spec)
			mu.Lock()
			if state == "scale-conflict" || state == "update-before" {
				assert.Equal(t, 2, writes)
				assert.Equal(t, 1, committed)
			}
			if state == "update-after" || state == "readback-outage" {
				assert.Equal(t, 1, writes)
				assert.Equal(t, 1, committed)
			}
			mu.Unlock()
			scale, err := client.AppsV1().Deployments(desired.Namespace).UpdateScale(t.Context(), desired.Name, &autoscalingv1.Scale{
				ObjectMeta: metav1.ObjectMeta{Name: desired.Name, Namespace: desired.Namespace, ResourceVersion: result.ResourceVersion},
				Spec:       autoscalingv1.ScaleSpec{Replicas: 6},
			}, metav1.UpdateOptions{})
			require.NoError(t, err)
			assert.Equal(t, int32(6), scale.Spec.Replicas)
			for range 2 {
				result, err = CreateOrUpdateDeployment(t.Context(), client, replicaDeployment(nil, "next-image"))
				require.NoError(t, err)
				assert.Equal(t, new(int32(6)), result.Spec.Replicas)
				assert.Equal(t, "next-image", result.Spec.Template.Spec.Containers[0].Image)
			}
			mu.Lock()
			assert.Equal(t, 1, scaleWrites)
			assert.Zero(t, unexpected)
			mu.Unlock()
		})
	}
}
