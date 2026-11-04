package k8sutils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

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
