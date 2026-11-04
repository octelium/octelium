// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package install

import (
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

func TestWaitGenesisJobHTTPRecovery(t *testing.T) {
	job := completedInstallationJob()
	job.Name, job.Namespace = "octelium-genesis-upgrade-abcdef", octeliumNS
	job.TypeMeta = metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}
	var jobRequests, unexpectedRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/jobs/"+job.Name) {
			n := jobRequests.Add(1)
			switch n {
			case 1:
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close()
				}
				return
			case 2:
				w.WriteHeader(http.StatusServiceUnavailable)
				json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: metav1.StatusReasonServiceUnavailable, Code: http.StatusServiceUnavailable})
				return
			}
			current := job.DeepCopy()
			if n == 3 {
				current.Status = batchv1.JobStatus{Active: 1}
			}
			json.NewEncoder(w).Encode(current)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/pods") {
			pod := initializationPod(job)
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "genesis", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}}}}
			json.NewEncoder(w).Encode(&corev1.PodList{TypeMeta: metav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}, Items: []corev1.Pod{*pod}})
			return
		}
		unexpectedRequests.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	c, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: -1})
	require.NoError(t, err)
	require.NoError(t, WaitGenesisJob(t.Context(), c, job, time.Millisecond, 3*time.Second))
	assert.Equal(t, int32(4), jobRequests.Load())
	assert.Zero(t, unexpectedRequests.Load())
}

func TestWaitGenesisJobRecoversFromStalledRequest(t *testing.T) {
	job := completedInstallationJob()
	job.Name, job.Namespace = "octelium-genesis-upgrade-abcdef", octeliumNS
	job.TypeMeta = metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}
	var jobRequests atomic.Int32
	requestCancelled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/jobs/"+job.Name) {
			if jobRequests.Add(1) == 1 {
				<-r.Context().Done()
				close(requestCancelled)
				return
			}
			json.NewEncoder(w).Encode(job)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	c, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: -1})
	require.NoError(t, err)
	require.NoError(t, WaitGenesisJob(t.Context(), c, job, time.Millisecond, 20*time.Second))
	select {
	case <-requestCancelled:
	default:
		t.Fatal("The stalled API request was not cancelled")
	}
	assert.Equal(t, int32(2), jobRequests.Load())
}
