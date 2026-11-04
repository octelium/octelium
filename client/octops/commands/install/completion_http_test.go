package install

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestInstallationCompletionHTTP(t *testing.T) {
	for _, state := range []string{"legacy", "owned", "temporary-api-failure", "connection-closed", "replaced", "failed-after-publication", "forbidden", "cancelled-request"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			job.TypeMeta = metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}
			var jobGets, tokenGets atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/jobs/"+job.Name) {
					count := jobGets.Add(1)
					switch {
					case state == "cancelled-request":
						<-r.Context().Done()
						return
					case state == "connection-closed" && count == 1:
						conn, _, err := w.(http.Hijacker).Hijack()
						if err == nil {
							conn.Close()
						}
						return
					case state == "temporary-api-failure" && count <= 2:
						w.WriteHeader(http.StatusServiceUnavailable)
						json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: metav1.StatusReasonServiceUnavailable, Code: http.StatusServiceUnavailable})
						return
					case state == "forbidden":
						w.WriteHeader(http.StatusForbidden)
						json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: metav1.StatusReasonForbidden, Code: http.StatusForbidden})
						return
					}
					current := job.DeepCopy()
					if state == "replaced" && count >= 2 {
						current.UID = "replacement"
					}
					if state == "failed-after-publication" {
						current.Status = batchv1.JobStatus{Active: 1}
						if count > 1 {
							current.Status = batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}}
						}
					}
					json.NewEncoder(w).Encode(current)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/pods") {
					json.NewEncoder(w).Encode(&corev1.PodList{TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}})
					return
				}
				if strings.HasSuffix(r.URL.Path, "/secrets/init-token") {
					tokenGets.Add(1)
					token := legacyInitialToken()
					token.TypeMeta = metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}
					if state == "owned" {
						token.Annotations = map[string]string{initializationIDKey: "initialization"}
					}
					json.NewEncoder(w).Encode(token)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/secrets/"+initializationSecretName) && state == "owned" {
					checkpoint := completedInitializationState()
					checkpoint.TypeMeta = metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}
					json.NewEncoder(w).Encode(checkpoint)
					return
				}
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: metav1.StatusReasonNotFound, Code: http.StatusNotFound})
			}))
			t.Cleanup(server.Close)
			c, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: -1})
			require.NoError(t, err)
			timeout := 3 * time.Second
			if state == "cancelled-request" {
				timeout = 40 * time.Millisecond
			}
			secret, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, timeout)
			switch state {
			case "replaced", "failed-after-publication", "forbidden", "cancelled-request":
				require.Error(t, err)
				assert.Nil(t, secret)
				if state != "replaced" {
					assert.Zero(t, tokenGets.Load())
				}
				if state == "cancelled-request" {
					assert.ErrorIs(t, err, context.DeadlineExceeded)
				}
				if state == "failed-after-publication" {
					assert.Contains(t, err.Error(), "BackoffLimitExceeded")
				}
			default:
				require.NoError(t, err)
				assert.Equal(t, "token", string(secret.Data["data"]))
				assert.GreaterOrEqual(t, jobGets.Load(), int32(2))
			}
		})
	}
}

func TestInstallationRecoversFromRequestTimeout(t *testing.T) {
	job := completedInstallationJob()
	job.TypeMeta = metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}
	var requests atomic.Int32
	requestCancelled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/jobs/"+job.Name) {
			if requests.Add(1) == 1 {
				<-r.Context().Done()
				close(requestCancelled)
				return
			}
			json.NewEncoder(w).Encode(job)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/secrets/init-token") {
			token := legacyInitialToken()
			token.TypeMeta = metav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}
			json.NewEncoder(w).Encode(token)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: metav1.StatusReasonNotFound, Code: http.StatusNotFound})
	}))
	t.Cleanup(server.Close)
	c, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: -1})
	require.NoError(t, err)
	secret, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, 20*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "token", string(secret.Data["data"]))
	select {
	case <-requestCancelled:
	default:
		t.Fatal("The stalled API request was not cancelled")
	}
	assert.Equal(t, int32(3), requests.Load())
}
