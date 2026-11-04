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
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	pkgerrors "github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func TestCreateGenesis(t *testing.T) {

	ctx := context.Background()

	fakeC := fakek8s.NewSimpleClientset()

	_, err := createGenesis(ctx, &Opts{
		ClusterDomain: "example.com",
		K8sC:          fakeC,
		Region: &corev1.Region{
			Metadata: &metav1.Metadata{
				Name: "default",
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	_, err = createGenesis(ctx, &Opts{
		ClusterDomain: "example.com",
		K8sC:          fakeC,
		Region: &corev1.Region{
			Metadata: &metav1.Metadata{
				Name: "default",
			},
		},
	})
	assert.Nil(t, err)
}

func envOf(c k8scorev1.Container) map[string]string {
	ret := map[string]string{}
	for _, itm := range c.Env {
		ret[itm.Name] = itm.Value
	}
	return ret
}

func TestGetGenesisPodSpecWithoutSPIFFE(t *testing.T) {
	podSpec := GetGenesisPodSpec(&GenesisPodSpecOpts{
		Domain:     "example.com",
		Cmd:        "upgrade",
		SvcAccount: "octelium-nocturne",
	})

	assert.Empty(t, podSpec.Volumes)

	c := podSpec.Containers[0]
	assert.Empty(t, c.VolumeMounts)
	assert.Equal(t, []string{"upgrade"}, c.Args)
	assert.Equal(t, map[string]string{
		"OCTELIUM_DOMAIN":                "example.com",
		"OCTELIUM_REGION_NAME":           "default",
		"OCTELIUM_GENESIS_POD_NAME":      "",
		"OCTELIUM_GENESIS_POD_NAMESPACE": "",
	}, envOf(c))
	for name, field := range map[string]string{
		"OCTELIUM_GENESIS_POD_NAME": "metadata.name", "OCTELIUM_GENESIS_POD_NAMESPACE": "metadata.namespace",
	} {
		assert.Contains(t, c.Env, k8scorev1.EnvVar{Name: name, ValueFrom: &k8scorev1.EnvVarSource{FieldRef: &k8scorev1.ObjectFieldSelector{FieldPath: field}}})
	}
}

func TestGetGenesisPodSpecWithSPIFFE(t *testing.T) {
	t.Run("the default CSI driver is used when none is set", func(t *testing.T) {
		podSpec := GetGenesisPodSpec(&GenesisPodSpecOpts{
			Domain:     "example.com",
			Cmd:        "upgrade",
			SvcAccount: "octelium-nocturne",
			SPIFFE:     &SPIFFEOpts{TrustDomain: "octelium.local"},
		})

		assert.Len(t, podSpec.Volumes, 1)
		assert.NotNil(t, podSpec.Volumes[0].CSI)
		assert.Equal(t, "csi.spiffe.io", podSpec.Volumes[0].CSI.Driver)

		c := podSpec.Containers[0]
		assert.Len(t, c.VolumeMounts, 1)
		assert.Equal(t, "/run/spire/sockets", c.VolumeMounts[0].MountPath)

		env := envOf(c)
		assert.Equal(t, "true", env["OCTELIUM_ENABLE_SPIFFE_CSI"])
		assert.Equal(t, "octelium.local", env["OCTELIUM_SPIFFE_TRUST_DOMAIN"])
		assert.NotContains(t, env, "OCTELIUM_SPIFFE_CSI_DRIVER")
	})

	t.Run("a custom CSI driver reaches both the volume and the env", func(t *testing.T) {
		podSpec := GetGenesisPodSpec(&GenesisPodSpecOpts{
			Domain:     "example.com",
			Cmd:        "init",
			SvcAccount: "octelium-genesis",
			SPIFFE:     &SPIFFEOpts{CSIDriver: "csi.example.com"},
		})

		assert.Equal(t, "csi.example.com", podSpec.Volumes[0].CSI.Driver)
		assert.Equal(t, "csi.example.com",
			envOf(podSpec.Containers[0])["OCTELIUM_SPIFFE_CSI_DRIVER"])
	})
}

func TestGenesisPodImagesAndOptions(t *testing.T) {
	previousTag, previousBranch, previousRegistry, previousPrefix := ldflags.GitTag, ldflags.GitBranch, ldflags.ImageRegistry, ldflags.ImageRegistryPrefix
	t.Cleanup(func() {
		ldflags.GitTag, ldflags.GitBranch, ldflags.ImageRegistry, ldflags.ImageRegistryPrefix = previousTag, previousBranch, previousRegistry, previousPrefix
	})
	ldflags.GitTag, ldflags.GitBranch = "", "test-branch"
	ldflags.ImageRegistry, ldflags.ImageRegistryPrefix = "registry.example", "private"
	for _, tc := range []struct {
		dev, version, pkg, region, want string
	}{
		{"false", "", "", "", "registry.example/private/octelium-genesis:latest"},
		{"true", "", "", "", "registry.example/private/octelium-genesis:test-branch"},
		{"false", "1.2.3", "octeliumee", "west", "registry.example/private/octeliumee-genesis:1.2.3"},
		{"true", "2.0.0-rc.1", "cordium", "east", "registry.example/private/cordium-genesis:2.0.0-rc.1"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			t.Setenv("OCTELIUM_DEV", tc.dev)
			t.Setenv("OCTELIUM_PRODUCTION", "true")
			pod := GetGenesisPodSpec(&GenesisPodSpecOpts{Domain: "example.com", Cmd: "upgrade", SvcAccount: "installer", Version: tc.version, Package: tc.pkg, Region: tc.region})
			assert.Equal(t, "installer", pod.ServiceAccountName)
			assert.Equal(t, k8scorev1.RestartPolicyNever, pod.RestartPolicy)
			require.Len(t, pod.Containers, 1)
			c := pod.Containers[0]
			assert.Equal(t, tc.want, c.Image)
			assert.Equal(t, k8scorev1.PullAlways, c.ImagePullPolicy)
			assert.Equal(t, []string{"upgrade"}, c.Args)
			assert.Equal(t, "example.com", envOf(c)["OCTELIUM_DOMAIN"])
			region := tc.region
			if region == "" {
				region = "default"
			}
			assert.Equal(t, region, envOf(c)["OCTELIUM_REGION_NAME"])
			assert.Empty(t, c.Command)
			assert.Empty(t, c.VolumeMounts)
			assert.Empty(t, pod.Volumes)
		})
	}
	pod := GetGenesisPodSpec(&GenesisPodSpecOpts{SPIFFE: &SPIFFEOpts{}})
	require.Len(t, pod.Volumes, 1)
	assert.Equal(t, "csi.spiffe.io", pod.Volumes[0].CSI.Driver)
	assert.True(t, *pod.Volumes[0].CSI.ReadOnly)
	require.Len(t, pod.Containers[0].VolumeMounts, 1)
	assert.True(t, pod.Containers[0].VolumeMounts[0].ReadOnly)
	assert.Equal(t, pod.Volumes[0].Name, pod.Containers[0].VolumeMounts[0].Name)
	assert.Equal(t, "true", envOf(pod.Containers[0])["OCTELIUM_ENABLE_SPIFFE_CSI"])
	assert.NotContains(t, envOf(pod.Containers[0]), "OCTELIUM_SPIFFE_TRUST_DOMAIN")
	assert.NotContains(t, envOf(pod.Containers[0]), "OCTELIUM_SPIFFE_CSI_DRIVER")
}

func TestGenesisResourcesAndBootstrapSPIFFE(t *testing.T) {
	c := fakek8s.NewSimpleClientset()
	bs := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec:\n  spiffe: {enable: true, trustDomain: cluster.local, csiDriver: {name: custom.csi}}"), bs))
	_, err := createGenesis(context.Background(), &Opts{K8sC: c, Bootstrap: bs, ClusterDomain: "example.com", Version: "1.2.3"})
	require.NoError(t, err)
	ctx := context.Background()
	sa, err := c.CoreV1().ServiceAccounts("default").Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
	require.NoError(t, err)
	role, err := c.RbacV1().ClusterRoles().Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
	require.NoError(t, err)
	require.Len(t, role.Rules, 1)
	assert.Contains(t, role.Rules[0].APIGroups, "*")
	assert.Equal(t, []string{"*"}, role.Rules[0].Verbs)
	assert.Equal(t, []string{"*"}, role.Rules[0].Resources)
	binding, err := c.RbacV1().ClusterRoleBindings().Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, role.Name, binding.RoleRef.Name)
	assert.Equal(t, "ClusterRole", binding.RoleRef.Kind)
	assert.Equal(t, "rbac.authorization.k8s.io", binding.RoleRef.APIGroup)
	require.Len(t, binding.Subjects, 1)
	assert.Equal(t, "ServiceAccount", binding.Subjects[0].Kind)
	assert.Equal(t, sa.Name, binding.Subjects[0].Name)
	assert.Equal(t, sa.Namespace, binding.Subjects[0].Namespace)
	job, err := c.BatchV1().Jobs("default").Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, job.Labels, job.Spec.Template.Labels)
	assert.Equal(t, "genesis", job.Labels["octelium.com/component"])
	assert.Equal(t, sa.Name, job.Spec.Template.Spec.ServiceAccountName)
	container := job.Spec.Template.Spec.Containers[0]
	assert.Equal(t, []string{"init"}, container.Args)
	assert.Contains(t, container.Image, "octelium-genesis:1.2.3")
	assert.Equal(t, "cluster.local", envOf(container)["OCTELIUM_SPIFFE_TRUST_DOMAIN"])
	assert.Equal(t, "custom.csi", job.Spec.Template.Spec.Volumes[0].CSI.Driver)
}

func TestGenesisPreservesSharedResources(t *testing.T) {
	c := fakek8s.NewSimpleClientset(getGenesisRoleBinding(), getGenesisRole(), getGenesisServiceAccount())
	_, err := createGenesis(t.Context(), &Opts{K8sC: c})
	require.NoError(t, err)
	for _, action := range c.Actions() {
		assert.NotEqual(t, "delete", action.GetVerb())
		if action.GetResource().Resource != "jobs" {
			assert.NotEqual(t, "update", action.GetVerb())
		}
	}
}

func TestCreateGenesisFailures(t *testing.T) {
	for _, resource := range []string{"jobs", "serviceaccounts", "clusterroles", "clusterrolebindings"} {
		t.Run(resource, func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
			want := errors.New("creation failed")
			c.PrependReactor("create", resource, func(action k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
			_, err := createGenesis(context.Background(), &Opts{K8sC: c})
			assert.ErrorIs(t, err, want)
		})
	}
	c := fakek8s.NewSimpleClientset()
	c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("cleanup forbidden")
	})
	_, err := createGenesis(context.Background(), &Opts{K8sC: c})
	assert.ErrorContains(t, err, "cleanup forbidden")
}

func TestInstallationCompletionHTTP(t *testing.T) {
	for _, state := range []string{"legacy", "owned", "temporary-api-failure", "connection-closed", "replaced", "failed-after-publication", "forbidden", "cancelled-request"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			job.TypeMeta = k8smetav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}
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
						json.NewEncoder(w).Encode(&k8smetav1.Status{TypeMeta: k8smetav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: k8smetav1.StatusReasonServiceUnavailable, Code: http.StatusServiceUnavailable})
						return
					case state == "forbidden":
						w.WriteHeader(http.StatusForbidden)
						json.NewEncoder(w).Encode(&k8smetav1.Status{TypeMeta: k8smetav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: k8smetav1.StatusReasonForbidden, Code: http.StatusForbidden})
						return
					}
					current := job.DeepCopy()
					if state == "replaced" && count >= 2 {
						current.UID = "replacement"
					}
					if state == "failed-after-publication" {
						current.Status = batchv1.JobStatus{Active: 1}
						if count > 1 {
							current.Status = batchv1.JobStatus{Conditions: []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}}
						}
					}
					json.NewEncoder(w).Encode(current)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/pods") {
					json.NewEncoder(w).Encode(&k8scorev1.PodList{TypeMeta: k8smetav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}})
					return
				}
				if strings.HasSuffix(r.URL.Path, "/secrets/init-token") {
					tokenGets.Add(1)
					token := legacyInitialToken()
					token.TypeMeta = k8smetav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}
					if state == "owned" {
						token.Annotations = map[string]string{initializationIDKey: "initialization"}
					}
					json.NewEncoder(w).Encode(token)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/secrets/"+initializationSecretName) && state == "owned" {
					checkpoint := completedInitializationState()
					checkpoint.TypeMeta = k8smetav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}
					json.NewEncoder(w).Encode(checkpoint)
					return
				}
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(&k8smetav1.Status{TypeMeta: k8smetav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: k8smetav1.StatusReasonNotFound, Code: http.StatusNotFound})
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
	job.TypeMeta = k8smetav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}
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
			token.TypeMeta = k8smetav1.TypeMeta{Kind: "Secret", APIVersion: "v1"}
			json.NewEncoder(w).Encode(token)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(&k8smetav1.Status{TypeMeta: k8smetav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: k8smetav1.StatusReasonNotFound, Code: http.StatusNotFound})
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

func completedInstallationJob() *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: k8smetav1.ObjectMeta{Name: genesisJobName, Namespace: genesisNS, UID: "submitted-job"},
		Status: batchv1.JobStatus{Succeeded: 1, Conditions: []batchv1.JobCondition{{
			Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue,
		}}},
	}
}

func legacyInitialToken() *k8scorev1.Secret {
	return &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "init-token", Namespace: octeliumNS, UID: "initial-token"},
		Data:       map[string][]byte{"data": []byte("token")},
	}
}

func completedInitializationState() *k8scorev1.Secret {
	return &k8scorev1.Secret{
		ObjectMeta: k8smetav1.ObjectMeta{Name: initializationSecretName, Namespace: octeliumNS, Annotations: map[string]string{initializationCompleteKey: "true"}},
		Data:       map[string][]byte{"id": []byte("initialization")},
	}
}

func initializationPod(job *batchv1.Job) *k8scorev1.Pod {
	return &k8scorev1.Pod{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: "genesis-worker", Namespace: job.Namespace, Labels: map[string]string{"job-name": job.Name},
			OwnerReferences: []k8smetav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: new(true)}},
		},
		Status: k8scorev1.PodStatus{Phase: k8scorev1.PodPending},
	}
}

func TestInstallationJobCompletion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*batchv1.Job)
		complete bool
		err      string
	}{
		{"complete", func(*batchv1.Job) {}, true, ""},
		{"pending", func(job *batchv1.Job) { job.Status = batchv1.JobStatus{} }, false, ""},
		{"success-counter-only", func(job *batchv1.Job) { job.Status.Conditions = nil }, false, ""},
		{"active", func(job *batchv1.Job) { job.Status.Active = 1 }, false, ""},
		{"terminating-pods", func(job *batchv1.Job) { job.Status.Terminating = new(int32(1)) }, false, ""},
		{"complete-false", func(job *batchv1.Job) { job.Status.Conditions[0].Status = k8scorev1.ConditionFalse }, false, ""},
		{"complete-unknown", func(job *batchv1.Job) { job.Status.Conditions[0].Status = k8scorev1.ConditionUnknown }, false, ""},
		{"pod-failure-counter", func(job *batchv1.Job) { job.Status = batchv1.JobStatus{Failed: 1} }, false, ""},
		{"failure-target", func(job *batchv1.Job) { job.Status.Conditions[0].Type = batchv1.JobFailureTarget }, false, ""},
		{"success-criteria-met", func(job *batchv1.Job) { job.Status.Conditions[0].Type = batchv1.JobSuccessCriteriaMet }, false, ""},
		{"failed", func(job *batchv1.Job) {
			job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue, Reason: "BackoffLimitExceeded", Message: "All retries failed"}}
		}, false, "BackoffLimitExceeded: All retries failed"},
		{"failed-after-complete", func(job *batchv1.Job) {
			job.Status.Conditions = append(job.Status.Conditions, batchv1.JobCondition{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue})
		}, false, "failed"},
		{"false-failure", func(job *batchv1.Job) {
			job.Status.Conditions = append(job.Status.Conditions, batchv1.JobCondition{Type: batchv1.JobFailed, Status: k8scorev1.ConditionFalse})
		}, true, ""},
		{"replaced", func(job *batchv1.Job) { job.UID = "replacement" }, false, "replaced"},
		{"deleted", func(job *batchv1.Job) { job.DeletionTimestamp = new(k8smetav1.Now()) }, false, "being deleted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := completedInstallationJob()
			tc.mutate(job)
			complete, err := genesisJobComplete(job, completedInstallationJob())
			assert.Equal(t, tc.complete, complete)
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestInstallationResultOwnership(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*k8scorev1.Secret, *k8scorev1.Secret) *k8scorev1.Secret
		err    string
	}{
		{"owned", func(_ *k8scorev1.Secret, state *k8scorev1.Secret) *k8scorev1.Secret { return state }, ""},
		{"legacy", func(token, _ *k8scorev1.Secret) *k8scorev1.Secret { token.Annotations = nil; return nil }, ""},
		{"wrong-initialization", func(token, state *k8scorev1.Secret) *k8scorev1.Secret {
			token.Annotations[initializationIDKey] = "another-installation"
			return state
		}, "completed initialization"},
		{"missing-state", func(_ *k8scorev1.Secret, _ *k8scorev1.Secret) *k8scorev1.Secret { return nil }, "state is missing"},
		{"missing-id", func(_ *k8scorev1.Secret, state *k8scorev1.Secret) *k8scorev1.Secret { state.Data = nil; return state }, "completed initialization"},
		{"incomplete", func(_ *k8scorev1.Secret, state *k8scorev1.Secret) *k8scorev1.Secret {
			state.Annotations = nil
			return state
		}, "completed initialization"},
		{"unmarked-token-with-state", func(token, state *k8scorev1.Secret) *k8scorev1.Secret { token.Annotations = nil; return state }, "completed initialization"},
		{"empty-token", func(token, state *k8scorev1.Secret) *k8scorev1.Secret { token.Data["data"] = nil; return state }, "token is empty"},
		{"missing-token-data", func(token, state *k8scorev1.Secret) *k8scorev1.Secret { token.Data = nil; return state }, "token is empty"},
		{"whitespace-token", func(token, state *k8scorev1.Secret) *k8scorev1.Secret {
			token.Data["data"] = []byte(" \n\t")
			return state
		}, "token is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job, token := completedInstallationJob(), legacyInitialToken()
			token.Annotations = map[string]string{initializationIDKey: "initialization"}
			state := tc.mutate(token, completedInitializationState())
			c := fakek8s.NewSimpleClientset(job, token)
			if state != nil {
				require.NoError(t, c.Tracker().Add(state))
			}
			got, err := getInstallationResult(t.Context(), c, job)
			if tc.err == "" {
				require.NoError(t, err)
				assert.Equal(t, token, got)
			} else {
				require.ErrorContains(t, err, tc.err)
				assert.Nil(t, got)
				assert.NotContains(t, err.Error(), "another-installation")
			}
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
			}
		})
	}
}

func TestInstallationIgnoresTokenBeforeJobCompletion(t *testing.T) {
	for _, state := range []string{"pending", "running", "failed", "replaced", "deleting", "missing"} {
		t.Run(state, func(t *testing.T) {
			expected, job := completedInstallationJob(), completedInstallationJob()
			switch state {
			case "pending":
				job.Status = batchv1.JobStatus{}
			case "running":
				job.Status = batchv1.JobStatus{Active: 1}
			case "failed":
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue}}
			case "replaced":
				job.UID = "replacement"
			case "deleting":
				job.DeletionTimestamp = new(k8smetav1.Now())
			}
			c := fakek8s.NewSimpleClientset(legacyInitialToken())
			if state != "missing" {
				require.NoError(t, c.Tracker().Add(job))
			}
			secret, err := getInstallationResult(t.Context(), c, expected)
			require.Error(t, err)
			assert.Nil(t, secret)
			for _, action := range c.Actions() {
				assert.NotEqual(t, "secrets", action.GetResource().Resource)
			}
		})
	}
}

func TestInstallationFailureAfterTokenPublication(t *testing.T) {
	job := completedInstallationJob()
	c := fakek8s.NewSimpleClientset(legacyInitialToken())
	gets := 0
	c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
		gets++
		current := job.DeepCopy()
		if gets == 1 {
			current.Status = batchv1.JobStatus{Active: 1}
		} else {
			current.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue, Reason: "DeadlineExceeded"}}
		}
		return true, current, nil
	})
	secret, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, time.Second)
	require.ErrorContains(t, err, "DeadlineExceeded")
	assert.Nil(t, secret)
	assert.Equal(t, 2, gets)
	for _, action := range c.Actions() {
		assert.NotEqual(t, "secrets", action.GetResource().Resource)
	}
}

func TestInstallationRechecksJobBeforeAcceptingToken(t *testing.T) {
	for _, state := range []string{"replaced", "deleted", "deleting", "failed", "running", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			c := fakek8s.NewSimpleClientset(job, legacyInitialToken())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			gets := 0
			c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				gets++
				if gets == 1 {
					return false, nil, nil
				}
				current := job.DeepCopy()
				switch state {
				case "replaced":
					current.UID = "replacement"
				case "deleted":
					return true, nil, k8serr.NewNotFound(action.GetResource().GroupResource(), job.Name)
				case "deleting":
					current.DeletionTimestamp = new(k8smetav1.Now())
				case "failed":
					current.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue}}
				case "running":
					current.Status = batchv1.JobStatus{Active: 1}
				case "cancelled":
					cancel()
				}
				return true, current, nil
			})
			secret, err := getInstallationResult(ctx, c, job)
			require.Error(t, err)
			assert.Nil(t, secret)
			assert.Equal(t, 2, gets)
			if state == "cancelled" {
				assert.ErrorIs(t, err, context.Canceled)
			}
		})
	}
}

func TestInstallationRetriesTransientReads(t *testing.T) {
	for _, point := range []string{"job", "token", "checkpoint", "final-job"} {
		for _, failure := range []error{
			io.EOF, io.ErrUnexpectedEOF, context.DeadlineExceeded,
			k8serr.NewServiceUnavailable("API unavailable"), k8serr.NewInternalError(pkgerrors.New("storage outage")),
			k8serr.NewTooManyRequests("throttled", 1), k8serr.NewTimeoutError("timed out", 1),
			&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
		} {
			t.Run(point+"/"+failure.Error(), func(t *testing.T) {
				job, token := completedInstallationJob(), legacyInitialToken()
				token.Annotations = map[string]string{initializationIDKey: "initialization"}
				c := fakek8s.NewSimpleClientset(job, token, completedInitializationState())
				failed, jobGets := false, 0
				c.PrependReactor("get", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
					resource, name := action.GetResource().Resource, action.(k8stesting.GetAction).GetName()
					if resource == "jobs" {
						jobGets++
					}
					match := point == "job" && resource == "jobs" || point == "final-job" && resource == "jobs" && jobGets == 2 ||
						point == "token" && name == "init-token" || point == "checkpoint" && name == initializationSecretName
					if !failed && match {
						failed = true
						return true, nil, failure
					}
					return false, nil, nil
				})
				secret, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, 3*time.Second)
				require.NoError(t, err)
				require.True(t, failed)
				assert.Equal(t, token, secret)
				assert.GreaterOrEqual(t, jobGets, 3)
			})
		}
	}
}

func TestInstallationPermanentReadErrors(t *testing.T) {
	for _, point := range []string{"jobs", "init-token", initializationSecretName} {
		for _, failure := range []error{
			k8serr.NewForbidden(schema.GroupResource{Resource: "secrets"}, "init-token", pkgerrors.New("permission denied")),
			k8serr.NewUnauthorized("credentials expired"), pkgerrors.New("invalid API response"),
		} {
			t.Run(point+"/"+failure.Error(), func(t *testing.T) {
				job := completedInstallationJob()
				c := fakek8s.NewSimpleClientset(job, legacyInitialToken())
				failures := 0
				c.PrependReactor("get", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if action.GetResource().Resource == point || action.(k8stesting.GetAction).GetName() == point {
						failures++
						return true, nil, failure
					}
					return false, nil, nil
				})
				secret, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, time.Second)
				require.ErrorIs(t, err, failure)
				assert.Nil(t, secret)
				assert.Equal(t, 1, failures)
			})
		}
	}
}

func TestInstallationWaitCancellationAndTimeout(t *testing.T) {
	for _, state := range []string{"cancelled-before-read", "cancelled-during-read", "api-outage", "missing-token", "pending-job"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			c := fakek8s.NewSimpleClientset(job)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch state {
			case "cancelled-before-read":
				cancel()
			case "cancelled-during-read":
				c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
					cancel()
					return true, nil, context.Canceled
				})
			case "api-outage":
				c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, k8serr.NewServiceUnavailable("API outage")
				})
			case "pending-job":
				job.Status = batchv1.JobStatus{}
				require.NoError(t, c.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), job, job.Namespace))
			}
			secret, err := waitForInitialToken(ctx, c, job, time.Millisecond, 30*time.Millisecond)
			assert.Nil(t, secret)
			if state == "cancelled-before-read" || state == "cancelled-during-read" {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			if state == "cancelled-before-read" {
				assert.Empty(t, c.Actions())
			}
			if state == "api-outage" {
				assert.Contains(t, err.Error(), "API outage")
			}
			assert.Contains(t, err.Error(), string(job.UID))
		})
	}
}

func TestInstallationPodDiagnosticsAndRecovery(t *testing.T) {
	for _, state := range []string{"Unschedulable", "ImagePullBackOff", "InitContainerError", "ContainerError"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			job.Status = batchv1.JobStatus{Failed: 1}
			pod := initializationPod(job)
			switch state {
			case "Unschedulable":
				pod.Status.Conditions = []k8scorev1.PodCondition{{Type: k8scorev1.PodScheduled, Status: k8scorev1.ConditionFalse, Reason: state, Message: "Insufficient memory"}}
			case "ImagePullBackOff":
				pod.Status.ContainerStatuses = []k8scorev1.ContainerStatus{{Name: "genesis", State: k8scorev1.ContainerState{Waiting: &k8scorev1.ContainerStateWaiting{Reason: state, Message: "Registry unavailable"}}}}
			case "InitContainerError":
				pod.Status.InitContainerStatuses = []k8scorev1.ContainerStatus{{Name: "init", State: k8scorev1.ContainerState{Terminated: &k8scorev1.ContainerStateTerminated{Reason: state, ExitCode: 2}}}}
			case "ContainerError":
				pod.Status.Phase = k8scorev1.PodFailed
				pod.Status.ContainerStatuses = []k8scorev1.ContainerStatus{{Name: "genesis", State: k8scorev1.ContainerState{Terminated: &k8scorev1.ContainerStateTerminated{Reason: state, ExitCode: 1, Message: "Temporary API failure"}}}}
			}
			c := fakek8s.NewSimpleClientset(job, pod, legacyInitialToken())
			secret, err := getInstallationResult(t.Context(), c, job)
			require.ErrorIs(t, err, errGenesisPending)
			assert.Nil(t, secret)
			assert.Contains(t, err.Error(), state)
			assert.Contains(t, err.Error(), pod.Name)
			_, err = waitForInitialToken(t.Context(), c, job, time.Millisecond, 20*time.Millisecond)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Contains(t, err.Error(), state)
			finished := completedInstallationJob()
			require.NoError(t, c.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), finished, job.Namespace))
			secret, err = waitForInitialToken(t.Context(), c, job, time.Millisecond, time.Second)
			require.NoError(t, err)
			assert.Equal(t, "token", string(secret.Data["data"]))
		})
	}
}

func TestInstallationPodDiagnosticsOwnership(t *testing.T) {
	job := completedInstallationJob()
	for _, state := range []string{"different-job", "different-name", "not-controller", "not-job", "unowned"} {
		t.Run(state, func(t *testing.T) {
			pod := initializationPod(job)
			pod.Status.ContainerStatuses = []k8scorev1.ContainerStatus{{Name: "unrelated", State: k8scorev1.ContainerState{Waiting: &k8scorev1.ContainerStateWaiting{Reason: "UnrelatedError"}}}}
			switch state {
			case "different-job":
				pod.OwnerReferences[0].UID = "previous-job"
			case "different-name":
				pod.OwnerReferences[0].Name = "other-job"
			case "not-controller":
				pod.OwnerReferences[0].Controller = new(false)
			case "not-job":
				pod.OwnerReferences[0].Kind = "Deployment"
			case "unowned":
				pod.OwnerReferences = nil
			}
			c := fakek8s.NewSimpleClientset(pod)
			assert.NotContains(t, genesisPodStatus(t.Context(), c, job), "UnrelatedError")
		})
	}
}

func TestInstallationPodReadFailureDoesNotOverrideJobResult(t *testing.T) {
	job := completedInstallationJob()
	job.Status.Conditions[0].Type = batchv1.JobFailed
	job.Status.Conditions[0].Reason = "BackoffLimitExceeded"
	c := fakek8s.NewSimpleClientset(job)
	c.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serr.NewServiceUnavailable("Pod API outage")
	})
	_, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, time.Second)
	require.ErrorContains(t, err, "BackoffLimitExceeded")
	assert.Contains(t, err.Error(), "Pod API outage")
}

func TestInstallationErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		err   error
		retry bool
	}{
		{io.EOF, true}, {io.ErrUnexpectedEOF, true}, {context.DeadlineExceeded, true},
		{&url.Error{Op: "Get", URL: "https://kubernetes", Err: io.EOF}, true},
		{syscall.ECONNRESET, true}, {syscall.ECONNREFUSED, true},
		{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH}, true},
		{&net.DNSError{Err: "temporary DNS failure", Name: "kubernetes"}, true},
		{k8serr.NewServerTimeout(schema.GroupResource{Resource: "jobs"}, "get", 1), true},
		{k8serr.NewForbidden(schema.GroupResource{Resource: "jobs"}, genesisJobName, pkgerrors.New("denied")), false},
		{k8serr.NewUnauthorized("expired"), false}, {k8serr.NewBadRequest("invalid"), false},
		{k8serr.NewNotFound(schema.GroupResource{Resource: "jobs"}, genesisJobName), false},
		{context.Canceled, false}, {x509.UnknownAuthorityError{}, false}, {pkgerrors.New("invalid response"), false},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			assert.Equal(t, tc.retry, isTransientGenesisError(pkgerrors.Wrap(tc.err, "request failed")))
		})
	}
}

func TestInstallationRequiresJobIdentityAndBoundedPolling(t *testing.T) {
	for _, tc := range []struct {
		job               *batchv1.Job
		interval, timeout time.Duration
	}{
		{nil, time.Millisecond, time.Second},
		{&batchv1.Job{}, time.Millisecond, time.Second},
		{&batchv1.Job{ObjectMeta: k8smetav1.ObjectMeta{Name: genesisJobName, Namespace: genesisNS}}, time.Millisecond, time.Second},
		{&batchv1.Job{ObjectMeta: k8smetav1.ObjectMeta{Name: genesisJobName, UID: types.UID("job")}}, time.Millisecond, time.Second},
		{completedInstallationJob(), 0, time.Second},
		{completedInstallationJob(), time.Millisecond, 0},
	} {
		c := fakek8s.NewSimpleClientset()
		secret, err := waitForInitialToken(t.Context(), c, tc.job, tc.interval, tc.timeout)
		require.Error(t, err)
		assert.Nil(t, secret)
		require.Error(t, WaitGenesisJob(t.Context(), c, tc.job, tc.interval, tc.timeout))
		assert.Empty(t, c.Actions())
	}
}

func TestInitialTokenValidationPreservesLocalState(t *testing.T) {
	t.Setenv("OCTELIUM_SKIP_MESSAGES", "true")
	require.NoError(t, cliutils.OpenDB("mem"))
	db := cliutils.GetDB()
	t.Cleanup(func() { db.Close() })
	require.NoError(t, db.SetSessionToken("example.com", &authv1.SessionToken{AccessToken: "existing-session"}))
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("existing-token"), 0600))
	for _, token := range []*k8scorev1.Secret{nil, {}, {Data: map[string][]byte{"data": []byte(" \n\t")}}} {
		require.Error(t, setInitialAuthToken(&Opts{ClusterDomain: "example.com", AuthTokenSavePath: path}, token))
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "existing-token", string(data))
	}
	require.Error(t, setInitialAuthToken(&Opts{ClusterDomain: "example.com", AuthTokenSavePath: t.TempDir()}, legacyInitialToken()))
	session, err := db.GetSessionToken("example.com")
	require.NoError(t, err)
	assert.Equal(t, "existing-session", session.AccessToken)
}

func TestDoInstallFailuresPreserveCredentialsAndOutput(t *testing.T) {
	for _, state := range []string{"cancelled-before-submission", "failed-job", "empty-token", "wrong-initialization", "replaced-job", "cancelled-wait", "save-failed"} {
		t.Run(state, func(t *testing.T) {
			t.Setenv("OCTELIUM_SKIP_MESSAGES", "")
			require.NoError(t, cliutils.OpenDB("mem"))
			db := cliutils.GetDB()
			t.Cleanup(func() { db.Close() })
			require.NoError(t, db.SetSessionToken("example.com", &authv1.SessionToken{AccessToken: "existing-session"}))
			path := filepath.Join(t.TempDir(), "token")
			require.NoError(t, os.WriteFile(path, []byte("existing-token"), 0600))
			output, err := os.Create(filepath.Join(t.TempDir(), "output"))
			require.NoError(t, err)
			stdout, colorOutput := os.Stdout, color.Output
			os.Stdout, color.Output = output, output
			t.Cleanup(func() { os.Stdout, color.Output = stdout, colorOutput; output.Close() })
			c := newGenesisJobClient(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if state == "cancelled-before-submission" {
				cancel()
			}
			started := false
			c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if started && state == "cancelled-wait" {
					cancel()
					return true, nil, context.Canceled
				}
				if started && state == "replaced-job" {
					job := completedInstallationJob()
					job.UID = "replacement"
					return true, job, nil
				}
				return false, nil, nil
			})
			c.PrependReactor("update", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				started = true
				job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job)
				job.Status.Conditions = completedInstallationJob().Status.Conditions
				if state == "failed-job" {
					job.Status.Conditions[0].Type = batchv1.JobFailed
				}
				token := legacyInitialToken()
				if state == "empty-token" {
					token.Data = nil
				}
				if state == "wrong-initialization" {
					token.Annotations = map[string]string{initializationIDKey: "other-initialization"}
					require.NoError(t, c.Tracker().Add(completedInitializationState()))
				}
				require.NoError(t, c.Tracker().Add(token))
				return false, nil, nil
			})
			savePath := path
			if state == "save-failed" {
				savePath = t.TempDir()
			}
			err = DoInstall(ctx, &Opts{K8sC: c, ClusterDomain: "example.com", AuthTokenSavePath: savePath})
			require.Error(t, err)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "existing-token", string(data))
			session, err := db.GetSessionToken("example.com")
			require.NoError(t, err)
			assert.Equal(t, "existing-session", session.AccessToken)
			_, err = output.Seek(0, io.SeekStart)
			require.NoError(t, err)
			data, err = io.ReadAll(output)
			require.NoError(t, err)
			assert.NotContains(t, string(data), "Cluster installation is now complete")
			assert.NotContains(t, string(data), "--auth-token")
			if state == "cancelled-before-submission" {
				assert.Empty(t, c.Actions())
			}
		})
	}
}

func TestWaitGenesisJobHTTPRecovery(t *testing.T) {
	job := completedInstallationJob()
	job.Name, job.Namespace = "octelium-genesis-upgrade-abcdef", octeliumNS
	job.TypeMeta = k8smetav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}
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
				json.NewEncoder(w).Encode(&k8smetav1.Status{TypeMeta: k8smetav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: k8smetav1.StatusReasonServiceUnavailable, Code: http.StatusServiceUnavailable})
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
			pod.Status.ContainerStatuses = []k8scorev1.ContainerStatus{{Name: "genesis", State: k8scorev1.ContainerState{Waiting: &k8scorev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}}}}
			json.NewEncoder(w).Encode(&k8scorev1.PodList{TypeMeta: k8smetav1.TypeMeta{Kind: "PodList", APIVersion: "v1"}, Items: []k8scorev1.Pod{*pod}})
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
	job.TypeMeta = k8smetav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}
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

func TestWaitGenesisJobOutcomes(t *testing.T) {
	for _, state := range []string{"complete", "pending", "failed", "replaced", "deleting", "missing", "counter-only", "active", "terminating", "complete-false", "complete-unknown", "failure-target", "success-criteria", "failure-after-complete"} {
		t.Run(state, func(t *testing.T) {
			expected, job := completedInstallationJob(), completedInstallationJob()
			expected.Namespace, job.Namespace = octeliumNS, octeliumNS
			switch state {
			case "pending":
				job.Status = batchv1.JobStatus{}
			case "failed":
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
			case "replaced":
				job.UID = "replacement"
			case "deleting":
				job.DeletionTimestamp = new(k8smetav1.Now())
			case "counter-only":
				job.Status.Conditions = nil
			case "active":
				job.Status.Active = 1
			case "terminating":
				job.Status.Terminating = new(int32(1))
			case "complete-false":
				job.Status.Conditions[0].Status = k8scorev1.ConditionFalse
			case "complete-unknown":
				job.Status.Conditions[0].Status = k8scorev1.ConditionUnknown
			case "failure-target":
				job.Status.Conditions[0].Type = batchv1.JobFailureTarget
			case "success-criteria":
				job.Status.Conditions[0].Type = batchv1.JobSuccessCriteriaMet
			case "failure-after-complete":
				job.Status.Conditions = append(job.Status.Conditions, batchv1.JobCondition{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue})
			}
			c := fakek8s.NewSimpleClientset(legacyInitialToken())
			if state != "missing" {
				require.NoError(t, c.Tracker().Add(job))
			}
			timeout := time.Second
			switch state {
			case "pending", "counter-only", "active", "terminating", "complete-false", "complete-unknown", "failure-target", "success-criteria":
				timeout = 20 * time.Millisecond
			}
			err := WaitGenesisJob(t.Context(), c, expected, time.Millisecond, timeout)
			switch state {
			case "complete":
				require.NoError(t, err)
			case "failed":
				require.ErrorContains(t, err, "BackoffLimitExceeded")
			case "failure-after-complete":
				require.ErrorContains(t, err, "failed")
			case "replaced":
				require.ErrorContains(t, err, "replaced")
			case "deleting":
				require.ErrorContains(t, err, "being deleted")
			case "missing":
				require.True(t, k8serr.IsNotFound(err), "%v", err)
			default:
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			for _, action := range c.Actions() {
				assert.Contains(t, []string{"get", "list"}, action.GetVerb())
				assert.Contains(t, []string{"jobs", "pods"}, action.GetResource().Resource)
				assert.Equal(t, expected.Namespace, action.GetNamespace())
			}
		})
	}
}

func TestWaitGenesisJobRetriesTemporaryReads(t *testing.T) {
	for _, failure := range []error{
		io.EOF, io.ErrUnexpectedEOF, context.DeadlineExceeded,
		k8serr.NewServiceUnavailable("API unavailable"), k8serr.NewInternalError(pkgerrors.New("temporary storage failure")),
		k8serr.NewTooManyRequests("throttled", 1), k8serr.NewTimeoutError("timed out", 1),
		k8serr.NewServerTimeout(schema.GroupResource{Resource: "jobs"}, "get", 1),
		&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNRESET},
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			job := completedInstallationJob()
			c := fakek8s.NewSimpleClientset(job)
			gets := 0
			c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
				gets++
				if gets <= 2 {
					return true, nil, failure
				}
				return false, nil, nil
			})
			require.NoError(t, WaitGenesisJob(t.Context(), c, job, time.Millisecond, 4*time.Second))
			assert.Equal(t, 3, gets)
		})
	}
}

func TestWaitGenesisJobRejectsPermanentReadErrors(t *testing.T) {
	for _, failure := range []error{
		k8serr.NewForbidden(schema.GroupResource{Resource: "jobs"}, "test", pkgerrors.New("permission denied")),
		k8serr.NewUnauthorized("expired credentials"), k8serr.NewBadRequest("invalid request"), pkgerrors.New("invalid response"),
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			job := completedInstallationJob()
			c := fakek8s.NewSimpleClientset(job)
			gets := 0
			c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
				gets++
				return true, nil, failure
			})
			c.PrependReactor("list", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, failure
			})
			require.ErrorIs(t, WaitGenesisJob(t.Context(), c, job, time.Millisecond, time.Second), failure)
			assert.Equal(t, 1, gets)
		})
	}
}

func TestWaitGenesisJobIgnoresOtherOperations(t *testing.T) {
	job := completedInstallationJob()
	job.Namespace = octeliumNS
	job.Status = batchv1.JobStatus{Active: 1}
	otherNamespace := completedInstallationJob()
	otherJob := completedInstallationJob()
	otherJob.Namespace, otherJob.Name, otherJob.UID = octeliumNS, "another-upgrade", "another-job"
	c := fakek8s.NewSimpleClientset(job, otherNamespace, otherJob, legacyInitialToken())
	err := WaitGenesisJob(t.Context(), c, job, time.Millisecond, 20*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	for _, action := range c.Actions() {
		if action.GetResource().Resource == "jobs" {
			assert.Equal(t, job.Namespace, action.GetNamespace())
			assert.Equal(t, job.Name, action.(k8stesting.GetAction).GetName())
		}
		assert.NotEqual(t, "secrets", action.GetResource().Resource)
	}
}

func TestWaitGenesisJobCancellationAndOutage(t *testing.T) {
	for _, state := range []string{"cancelled-before-read", "cancelled-during-read", "cancelled-after-successful-read", "deadline", "api-outage"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			c := fakek8s.NewSimpleClientset(job)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if state == "cancelled-before-read" {
				cancel()
			}
			c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
				switch state {
				case "cancelled-during-read":
					cancel()
					return true, nil, context.Canceled
				case "cancelled-after-successful-read":
					cancel()
					return true, job, nil
				case "deadline":
					current := job.DeepCopy()
					current.Status = batchv1.JobStatus{Active: 1}
					return true, current, nil
				case "api-outage":
					return true, nil, k8serr.NewServiceUnavailable("API outage")
				}
				return false, nil, nil
			})
			timeout := time.Second
			if state == "deadline" || state == "api-outage" {
				timeout = 20 * time.Millisecond
			}
			err := WaitGenesisJob(ctx, c, job, time.Millisecond, timeout)
			if state == "deadline" || state == "api-outage" {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			} else {
				require.ErrorIs(t, err, context.Canceled)
			}
			if state == "cancelled-before-read" {
				assert.Empty(t, c.Actions())
			}
			if state == "api-outage" {
				assert.Contains(t, err.Error(), "API outage")
			}
			assert.Contains(t, err.Error(), string(job.UID))
		})
	}
}

func TestWaitGenesisJobPodFailuresCanRecover(t *testing.T) {
	for _, state := range []string{"Unschedulable", "ImagePullBackOff", "Failed"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			pod := initializationPod(job)
			switch state {
			case "Unschedulable":
				pod.Status.Conditions = []k8scorev1.PodCondition{{Type: k8scorev1.PodScheduled, Status: k8scorev1.ConditionFalse, Reason: state, Message: "Insufficient memory"}}
			case "ImagePullBackOff":
				pod.Status.ContainerStatuses = []k8scorev1.ContainerStatus{{Name: "genesis", State: k8scorev1.ContainerState{Waiting: &k8scorev1.ContainerStateWaiting{Reason: state}}}}
			case "Failed":
				pod.Status.Phase = k8scorev1.PodFailed
				pod.Status.ContainerStatuses = []k8scorev1.ContainerStatus{{Name: "genesis", State: k8scorev1.ContainerState{Terminated: &k8scorev1.ContainerStateTerminated{Reason: "Error", ExitCode: 1}}}}
			}
			c := fakek8s.NewSimpleClientset(job, pod)
			gets := 0
			c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
				gets++
				if gets == 1 {
					current := job.DeepCopy()
					current.Status = batchv1.JobStatus{Failed: 1}
					return true, current, nil
				}
				return false, nil, nil
			})
			require.NoError(t, WaitGenesisJob(t.Context(), c, job, time.Millisecond, time.Second))
			assert.Equal(t, 2, gets)
			assert.Contains(t, genesisPodStatus(t.Context(), c, job), state)
		})
	}
}

func TestWaitGenesisJobDiagnosticOutage(t *testing.T) {
	for _, failed := range []bool{false, true} {
		job := completedInstallationJob()
		job.Status = batchv1.JobStatus{}
		if failed {
			job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
		}
		c := fakek8s.NewSimpleClientset(job)
		c.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, k8serr.NewServiceUnavailable("Pod API unavailable")
		})
		timeout := 20 * time.Millisecond
		if failed {
			timeout = time.Second
		}
		err := WaitGenesisJob(t.Context(), c, job, time.Millisecond, timeout)
		if failed {
			require.ErrorContains(t, err, "BackoffLimitExceeded")
		} else {
			require.ErrorIs(t, err, context.DeadlineExceeded)
		}
		assert.Contains(t, err.Error(), "Pod API unavailable")
	}
}

func TestWaitGenesisJobWithoutGetPermission(t *testing.T) {
	for _, state := range []string{"complete", "pending", "failed", "replaced", "missing", "wrong-namespace", "transient-list-error", "forbidden-list"} {
		t.Run(state, func(t *testing.T) {
			expected, job := completedInstallationJob(), completedInstallationJob()
			expected.Namespace, job.Namespace = octeliumNS, octeliumNS
			switch state {
			case "pending":
				job.Status = batchv1.JobStatus{Active: 1}
			case "failed":
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
			case "replaced":
				job.UID = "replacement"
			}
			other := completedInstallationJob()
			other.Namespace, other.Name = octeliumNS, "another-job"
			c := fakek8s.NewSimpleClientset(other)
			if state != "missing" {
				require.NoError(t, c.Tracker().Add(job))
			}
			c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), job.Name, pkgerrors.New("get is not permitted"))
			})
			lists := 0
			c.PrependReactor("list", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				lists++
				assert.Equal(t, "metadata.name="+job.Name, action.(k8stesting.ListAction).GetListRestrictions().Fields.String())
				switch state {
				case "wrong-namespace":
					foreign := job.DeepCopy()
					foreign.Namespace = "default"
					return true, &batchv1.JobList{Items: []batchv1.Job{*foreign}}, nil
				case "transient-list-error":
					if lists == 1 {
						return true, nil, k8serr.NewServiceUnavailable("Temporary list outage")
					}
				case "forbidden-list":
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), job.Name, pkgerrors.New("list is not permitted"))
				}
				return false, nil, nil
			})
			timeout := time.Second
			if state == "pending" {
				timeout = 20 * time.Millisecond
			}
			err := WaitGenesisJob(t.Context(), c, expected, time.Millisecond, timeout)
			switch state {
			case "complete", "transient-list-error":
				require.NoError(t, err)
			case "pending":
				require.ErrorIs(t, err, context.DeadlineExceeded)
			case "failed":
				require.ErrorContains(t, err, "BackoffLimitExceeded")
			case "replaced":
				require.ErrorContains(t, err, "replaced")
			case "missing", "wrong-namespace":
				require.True(t, k8serr.IsNotFound(err), "%v", err)
			case "forbidden-list":
				require.True(t, k8serr.IsForbidden(err), "%v", err)
			}
			assert.Positive(t, lists)
		})
	}
}

const submissionJobName = "genesis-submission-test"

func newGenesisJobClient(t *testing.T) *fakek8s.Clientset {
	t.Helper()
	c := fakek8s.NewSimpleClientset()
	c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		secret := action.(k8stesting.CreateAction).GetObject().(*k8scorev1.Secret).DeepCopy()
		secret.UID, secret.ResourceVersion = types.UID(uuid.NewString()), "1"
		err := c.Tracker().Create(action.GetResource(), secret, action.GetNamespace())
		return true, secret, err
	})
	c.PrependReactor("*", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		switch action.GetVerb() {
		case "create":
			job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
			job.UID, job.ResourceVersion = types.UID(uuid.NewString()), "1"
			err := c.Tracker().Create(action.GetResource(), job, action.GetNamespace())
			return true, job, err
		case "update":
			job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job).DeepCopy()
			object, err := c.Tracker().Get(action.GetResource(), action.GetNamespace(), job.Name)
			if err != nil {
				return true, nil, err
			}
			current := object.(*batchv1.Job)
			if job.UID != current.UID || job.ResourceVersion != current.ResourceVersion {
				return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), job.Name, pkgerrors.New("stale Job"))
			}
			version, err := strconv.Atoi(current.ResourceVersion)
			require.NoError(t, err)
			job.ResourceVersion = strconv.Itoa(version + 1)
			err = c.Tracker().Update(action.GetResource(), job, action.GetNamespace())
			return true, job, err
		case "delete":
			a := action.(k8stesting.DeleteAction)
			object, err := c.Tracker().Get(action.GetResource(), action.GetNamespace(), a.GetName())
			if err != nil {
				return true, nil, err
			}
			current := object.(*batchv1.Job)
			pre := a.GetDeleteOptions().Preconditions
			if pre == nil || pre.UID == nil || pre.ResourceVersion == nil || *pre.UID != current.UID || *pre.ResourceVersion != current.ResourceVersion {
				return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), a.GetName(), pkgerrors.New("stale deletion"))
			}
			return true, nil, c.Tracker().Delete(action.GetResource(), action.GetNamespace(), a.GetName())
		}
		return false, nil, nil
	})
	return c
}

func testGenesisPreparation(context.Context) error {
	return nil
}

func testSubmissionJob(version string) *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: k8smetav1.ObjectMeta{Name: submissionJobName, Namespace: "octelium", Labels: map[string]string{"octelium.com/component": "genesis"}},
		Spec: batchv1.JobSpec{Template: k8scorev1.PodTemplateSpec{Spec: k8scorev1.PodSpec{
			RestartPolicy: k8scorev1.RestartPolicyNever, Containers: []k8scorev1.Container{{Name: "genesis", Image: "genesis:" + version, Args: []string{"upgrade"}}},
		}}},
	}
}

func TestGenesisSubmissionWithoutPreparation(t *testing.T) {
	for _, state := range []string{"success", "create-failed", "response-lost", "readback-failed"} {
		t.Run(state, func(t *testing.T) {
			c := newGenesisJobClient(t)
			desired := testSubmissionJob("1.2.3")
			if state != "success" {
				c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if state != "create-failed" {
						require.NoError(t, c.Tracker().Create(action.GetResource(), action.(k8stesting.CreateAction).GetObject(), action.GetNamespace()))
					}
					return true, nil, io.ErrUnexpectedEOF
				})
			}
			if state == "readback-failed" {
				c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, k8serr.NewServiceUnavailable("temporary outage")
				})
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if state == "create-failed" || state == "readback-failed" {
				var timeoutCancel context.CancelFunc
				ctx, timeoutCancel = context.WithTimeout(ctx, 80*time.Millisecond)
				defer timeoutCancel()
			}
			err := SubmitGenesisJob(ctx, c, desired, nil)
			if state == "create-failed" || state == "readback-failed" {
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			} else {
				require.NoError(t, err)
			}
			jobs, err := c.BatchV1().Jobs(desired.Namespace).List(t.Context(), k8smetav1.ListOptions{})
			require.NoError(t, err)
			if state == "create-failed" {
				assert.Empty(t, jobs.Items)
			} else {
				require.Len(t, jobs.Items, 1)
				assert.Nil(t, jobs.Items[0].Spec.Suspend)
			}
			assert.Empty(t, desired.Annotations)
			for _, action := range c.Actions() {
				assert.NotEqual(t, "update", action.GetVerb())
				assert.NotEqual(t, "delete", action.GetVerb())
			}
		})
	}
}

func TestGenesisSubmissionAfterLegacyCompletion(t *testing.T) {
	for _, namespace := range []string{"default", "octelium"} {
		for _, phase := range []k8scorev1.PodPhase{k8scorev1.PodSucceeded, k8scorev1.PodRunning} {
			t.Run(namespace+"/"+string(phase), func(t *testing.T) {
				c := newGenesisJobClient(t)
				previous := &batchv1.Job{
					ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-genesis-upgrade-cordium-abcdef", Namespace: namespace, Labels: map[string]string{"octelium.com/component": "genesis"}},
					Status:     batchv1.JobStatus{Succeeded: 1},
				}
				require.NoError(t, c.Tracker().Add(previous))
				require.NoError(t, c.Tracker().Add(&k8scorev1.Pod{ObjectMeta: k8smetav1.ObjectMeta{Name: previous.Name, Namespace: namespace, Labels: previous.Labels}, Status: k8scorev1.PodStatus{Phase: phase}}))
				err := SubmitGenesisJob(t.Context(), c, testSubmissionJob("1.2.3"), nil)
				if phase == k8scorev1.PodRunning {
					require.ErrorContains(t, err, "may still be running")
				} else {
					require.NoError(t, err)
				}
				current, err := c.BatchV1().Jobs(namespace).Get(t.Context(), previous.Name, k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, previous, current)
			})
		}
	}
}

func TestGenesisSubmissionPreparesBeforeStarting(t *testing.T) {
	c := newGenesisJobClient(t)
	desired := testSubmissionJob("1.2.3")
	prepared := 0
	prepare := func(ctx context.Context) error {
		job, err := c.BatchV1().Jobs(desired.Namespace).Get(ctx, desired.Name, k8smetav1.GetOptions{})
		require.NoError(t, err)
		require.NotNil(t, job.Spec.Suspend)
		if prepared == 0 {
			assert.True(t, *job.Spec.Suspend)
		} else {
			assert.False(t, *job.Spec.Suspend)
		}
		prepared++
		return nil
	}
	require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, prepare))
	first, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.False(t, *first.Spec.Suspend)
	require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, prepare))
	second, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, first.UID, second.UID)
	assert.Equal(t, 2, prepared)
	assert.Nil(t, desired.Spec.Suspend)
	assert.Empty(t, desired.Annotations)
	for _, version := range []string{"2.0.0", "3.0.0"} {
		require.ErrorContains(t, SubmitGenesisJob(t.Context(), c, testSubmissionJob(version), prepare), "different request")
	}
	assert.Equal(t, 2, prepared)
	current, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, first, current)
}

func TestGenesisSubmissionConcurrentRequests(t *testing.T) {
	c := newGenesisJobClient(t)
	var wg sync.WaitGroup
	var started atomic.Int32
	start := make(chan struct{})
	for i := range 8 {
		wg.Go(func() {
			<-start
			if SubmitGenesisJob(t.Context(), c, testSubmissionJob(fmt.Sprint(i)), testGenesisPreparation) == nil {
				started.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()
	assert.Equal(t, int32(1), started.Load())
	jobs, err := c.BatchV1().Jobs("octelium").List(t.Context(), k8smetav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, jobs.Items, 1)
	assert.False(t, *jobs.Items[0].Spec.Suspend)
}

func TestGenesisSubmissionAmbiguousResponses(t *testing.T) {
	for _, verb := range []string{"create", "update"} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/committed=%t", verb, committed), func(t *testing.T) {
				c := newGenesisJobClient(t)
				failed := false
				c.PrependReactor(verb, "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if failed {
						return false, nil, nil
					}
					failed = true
					if committed {
						if verb == "create" {
							job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
							job.UID, job.ResourceVersion = types.UID(uuid.NewString()), "1"
							require.NoError(t, c.Tracker().Create(action.GetResource(), job, action.GetNamespace()))
						} else {
							require.NoError(t, c.Tracker().Update(action.GetResource(), action.(k8stesting.UpdateAction).GetObject(), action.GetNamespace()))
						}
					}
					return true, nil, io.ErrUnexpectedEOF
				})
				desired := testSubmissionJob("1.2.3")
				err := SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation)
				require.NoError(t, err)
				require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation))
				jobs, err := c.BatchV1().Jobs("octelium").List(t.Context(), k8smetav1.ListOptions{})
				require.NoError(t, err)
				require.Len(t, jobs.Items, 1)
				assert.False(t, *jobs.Items[0].Spec.Suspend)
			})
		}
	}
}

func TestGenesisSubmissionLegacyJobsAndPods(t *testing.T) {
	for _, namespace := range []string{"default", "octelium"} {
		for _, state := range []string{"pending-job", "running", "unknown", "terminating", "terminal"} {
			t.Run(namespace+"/"+state, func(t *testing.T) {
				c := newGenesisJobClient(t)
				legacy := testSubmissionJob("legacy")
				legacy.Name, legacy.Namespace = "octelium-genesis-legacy", namespace
				if state != "pending-job" {
					legacy.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue}}
				}
				require.NoError(t, c.Tracker().Add(legacy))
				pod := &k8scorev1.Pod{ObjectMeta: k8smetav1.ObjectMeta{Name: "legacy-worker", Namespace: namespace, Labels: legacy.Labels}, Status: k8scorev1.PodStatus{Phase: k8scorev1.PodRunning}}
				switch state {
				case "unknown":
					pod.Status.Phase = k8scorev1.PodUnknown
				case "terminating":
					pod.DeletionTimestamp = new(k8smetav1.Now())
				case "terminal":
					pod.Status.Phase = k8scorev1.PodFailed
				}
				if state != "pending-job" {
					require.NoError(t, c.Tracker().Add(pod))
				}
				prepared := false
				err := SubmitGenesisJob(t.Context(), c, testSubmissionJob("1.2.3"), func(context.Context) error { prepared = true; return nil })
				if state == "terminal" {
					require.NoError(t, err)
					assert.True(t, prepared)
				} else {
					require.Error(t, err)
					assert.False(t, prepared)
				}
			})
		}
	}
}

func TestGenesisSubmissionCompletedJobReplacement(t *testing.T) {
	c := newGenesisJobClient(t)
	desired := testSubmissionJob("1.2.3")
	require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation))
	first, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, k8smetav1.GetOptions{})
	require.NoError(t, err)
	first.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
	_, err = c.BatchV1().Jobs(first.Namespace).Update(t.Context(), first, k8smetav1.UpdateOptions{})
	require.NoError(t, err)
	require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation))
	second, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.NotEqual(t, first.UID, second.UID)
	assert.False(t, *second.Spec.Suspend)
}

func TestGenesisSubmissionConflictsAndLookupFailures(t *testing.T) {
	for _, resource := range []string{"jobs", "pods"} {
		t.Run(resource, func(t *testing.T) {
			c := newGenesisJobClient(t)
			want := k8serr.NewServiceUnavailable("temporary outage")
			c.PrependReactor("list", resource, func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
			prepared := false
			ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
			defer cancel()
			assert.ErrorIs(t, SubmitGenesisJob(ctx, c, testSubmissionJob("1.2.3"), func(context.Context) error { prepared = true; return nil }), want)
			assert.False(t, prepared)
			for _, action := range c.Actions() {
				assert.False(t, action.Matches("create", "jobs"))
			}
		})
	}
	c := newGenesisJobClient(t)
	conflicted := false
	c.PrependReactor("update", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if conflicted {
			return false, nil, nil
		}
		conflicted = true
		return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), submissionJobName, pkgerrors.New("controller status changed"))
	})
	require.NoError(t, SubmitGenesisJob(t.Context(), c, testSubmissionJob("1.2.3"), testGenesisPreparation))
	assert.True(t, conflicted)
}

func TestGenesisSubmissionChecksAfterRegistration(t *testing.T) {
	c := newGenesisJobClient(t)
	err := SubmitGenesisJob(t.Context(), c, testSubmissionJob("1.2.3"), func(context.Context) error {
		other := testSubmissionJob("2.0.0")
		other.Name, other.Namespace = "octelium-genesis", "default"
		return c.Tracker().Add(other)
	})
	require.ErrorContains(t, err, "still active")
	jobs, err := c.BatchV1().Jobs("octelium").List(t.Context(), k8smetav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, jobs.Items)
}

func TestGenesisSubmissionCleanupPreservesStartedJob(t *testing.T) {
	c := newGenesisJobClient(t)
	desired := testSubmissionJob("1.2.3")
	want := pkgerrors.New("preparer stopped")
	err := SubmitGenesisJob(t.Context(), c, desired, func(ctx context.Context) error {
		job, err := c.BatchV1().Jobs(desired.Namespace).Get(ctx, desired.Name, k8smetav1.GetOptions{})
		require.NoError(t, err)
		job.Spec.Suspend = new(false)
		_, err = c.BatchV1().Jobs(job.Namespace).Update(ctx, job, k8smetav1.UpdateOptions{})
		require.NoError(t, err)
		return want
	})
	require.ErrorIs(t, err, want)
	job, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.False(t, *job.Spec.Suspend)
}

func TestGenesisSubmissionDeletionRace(t *testing.T) {
	c := newGenesisJobClient(t)
	desired := testSubmissionJob("1.2.3")
	require.NoError(t, SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation))
	old, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, k8smetav1.GetOptions{})
	require.NoError(t, err)
	old.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
	_, err = c.BatchV1().Jobs(old.Namespace).Update(t.Context(), old, k8smetav1.UpdateOptions{})
	require.NoError(t, err)
	newUID := types.UID(uuid.NewString())
	c.PrependReactor("delete", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		current := desired.DeepCopy()
		current.UID, current.ResourceVersion = newUID, "1"
		require.NoError(t, c.Tracker().Update(action.GetResource(), current, current.Namespace))
		return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), current.Name, pkgerrors.New("replaced"))
	})
	require.Error(t, SubmitGenesisJob(t.Context(), c, desired, testGenesisPreparation))
	current, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, newUID, current.UID)
}

func TestBootstrapReplacementIsRefused(t *testing.T) {
	c := newGenesisJobClient(t)
	o := &Opts{K8sC: c, ClusterDomain: "original.example"}
	require.NoError(t, setClusterResources(t.Context(), o))
	before, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	o.ClusterDomain = "replacement.example"
	require.ErrorContains(t, setClusterResources(t.Context(), o), "bootstrap differs")
	after, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, before, after)
}

func TestActiveInitializationRejectsDifferentBootstrap(t *testing.T) {
	c := newGenesisJobClient(t)
	bootstrap := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: localhost, password: original}}}"), bootstrap))
	o := &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: bootstrap}
	_, err := createGenesis(t.Context(), o)
	require.NoError(t, err)
	beforeJob, err := c.BatchV1().Jobs("default").Get(t.Context(), genesisJobName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	beforeSecret, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	replacement := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: localhost, password: replacement}}}"), replacement))
	o.Bootstrap = replacement
	_, err = createGenesis(t.Context(), o)
	require.ErrorContains(t, err, "different request")
	afterJob, err := c.BatchV1().Jobs("default").Get(t.Context(), genesisJobName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	afterSecret, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, beforeJob, afterJob)
	assert.Equal(t, beforeSecret, afterSecret)
}

func TestConcurrentMatchingInitializations(t *testing.T) {
	c := newGenesisJobClient(t)
	var wg sync.WaitGroup
	var succeeded atomic.Int32
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			if _, err := createGenesis(t.Context(), &Opts{K8sC: c, ClusterDomain: "example.com"}); err == nil {
				succeeded.Add(1)
			} else {
				t.Errorf("Matching initialization retry failed: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()
	assert.Equal(t, int32(8), succeeded.Load())
	jobs, err := c.BatchV1().Jobs("default").List(t.Context(), k8smetav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, jobs.Items, 1)
	assert.False(t, *jobs.Items[0].Spec.Suspend)
}

func TestGenesisSubmissionReturnsAcceptedJobIdentity(t *testing.T) {
	for _, state := range []string{"created", "create-response-lost", "update-response-lost", "resumed", "replaced-completed"} {
		t.Run(state, func(t *testing.T) {
			c := newGenesisJobClient(t)
			if state == "create-response-lost" || state == "update-response-lost" {
				verb := "create"
				if state == "update-response-lost" {
					verb = "update"
				}
				c.PrependReactor(verb, "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
					var job *batchv1.Job
					var err error
					if verb == "create" {
						job = action.(k8stesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
						job.UID, job.ResourceVersion = types.UID(uuid.NewString()), "1"
						err = c.Tracker().Create(action.GetResource(), job, action.GetNamespace())
					} else {
						job = action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job).DeepCopy()
						err = c.Tracker().Update(action.GetResource(), job, action.GetNamespace())
					}
					require.NoError(t, err)
					return true, nil, io.ErrUnexpectedEOF
				})
			}
			o := &Opts{K8sC: c, ClusterDomain: "example.com"}
			accepted, err := createGenesis(t.Context(), o)
			require.NoError(t, err)
			require.NotEmpty(t, accepted.UID)
			if state == "resumed" || state == "replaced-completed" {
				previousUID := accepted.UID
				if state == "replaced-completed" {
					accepted.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
					_, err = c.BatchV1().Jobs(accepted.Namespace).Update(t.Context(), accepted, k8smetav1.UpdateOptions{})
					require.NoError(t, err)
				}
				accepted, err = createGenesis(t.Context(), o)
				require.NoError(t, err)
				if state == "resumed" {
					assert.Equal(t, previousUID, accepted.UID)
				} else {
					assert.NotEqual(t, previousUID, accepted.UID)
				}
			}
			current, err := c.BatchV1().Jobs(accepted.Namespace).Get(t.Context(), accepted.Name, k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, current, accepted)
			require.NotNil(t, accepted.Spec.Suspend)
			assert.False(t, *accepted.Spec.Suspend)
		})
	}
}

func TestGenesisSubmissionWithResultWithoutPreparation(t *testing.T) {
	for _, state := range []string{"created", "create-response-lost", "not-committed", "different-request", "deleting", "suspended"} {
		t.Run(state, func(t *testing.T) {
			c := newGenesisJobClient(t)
			desired := testSubmissionJob("1.2.3")
			before := desired.DeepCopy()
			if state != "created" {
				c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if state != "not-committed" {
						job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
						job.UID, job.ResourceVersion = types.UID(uuid.NewString()), "1"
						switch state {
						case "different-request":
							job.Annotations[genesisRequestHash] = "another-request"
						case "deleting":
							job.DeletionTimestamp = new(k8smetav1.Now())
						case "suspended":
							job.Spec.Suspend = new(true)
						}
						require.NoError(t, c.Tracker().Create(action.GetResource(), job, job.Namespace))
					}
					return true, nil, io.ErrUnexpectedEOF
				})
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if state == "not-committed" {
				var timeoutCancel context.CancelFunc
				ctx, timeoutCancel = context.WithTimeout(ctx, 80*time.Millisecond)
				defer timeoutCancel()
			}
			accepted, err := SubmitGenesisJobWithResult(ctx, c, desired, nil)
			if state == "created" || state == "create-response-lost" {
				require.NoError(t, err)
				require.NotNil(t, accepted)
				assert.NotEmpty(t, accepted.UID)
				assert.Nil(t, accepted.Spec.Suspend)
				current, err := c.BatchV1().Jobs(desired.Namespace).Get(t.Context(), desired.Name, k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, current, accepted)
			} else if state == "not-committed" {
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			} else {
				require.ErrorContains(t, err, "does not match")
			}
			assert.Equal(t, before, desired)
			for _, action := range c.Actions() {
				assert.NotEqual(t, "update", action.GetVerb())
				assert.NotEqual(t, "delete", action.GetVerb())
			}
		})
	}
}
