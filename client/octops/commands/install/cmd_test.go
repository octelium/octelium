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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestDoInit(t *testing.T) {

	ctx := context.Background()

	fakeC := fakek8s.NewSimpleClientset()

	err := setClusterResources(ctx, &Opts{
		ClusterDomain: "example.com",
		K8sC:          fakeC,
		Region: &corev1.Region{
			Metadata: &metav1.Metadata{
				Name: "default",
			},
		},
	})
	assert.Nil(t, err)

	// initialize twice
	err = setClusterResources(ctx, &Opts{
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

func TestBootstrapSecretRoundTrip(t *testing.T) {
	ctx := context.Background()
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%t", existing), func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
			bootstrap := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.UnmarshalYAML([]byte("spec:\n  primaryStorage:\n    postgresql: {host: postgres, username: installer, passwordFromSecret: {name: postgres-auth, namespace: storage, key: password}}\n  secondaryStorage:\n    redis: {host: redis, password: secret}\n  spiffe: {enable: true, trustDomain: test.local, csiDriver: {name: custom.csi}}\n  cni: {multusConfDir: /opt/multus/conf}\n  ingress: {frontProxy: {enable: true}}\n"), bootstrap))
			region := &corev1.Region{Kind: "Region", Metadata: &metav1.Metadata{Name: "default", SystemLabels: map[string]string{"external-ips": `["203.0.113.10"]`}}}
			if existing {
				_, err := c.CoreV1().Secrets("default").Create(ctx, &k8scorev1.Secret{
					ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Labels: map[string]string{"retained": "yes"}, ResourceVersion: "17"},
					Data:       map[string][]byte{"bootstrap": pbutils.MarshalMust(bootstrap), "region": pbutils.MarshalMust(region), "domain": []byte("example.com")},
				}, k8smetav1.CreateOptions{})
				require.NoError(t, err)
			}
			require.NoError(t, setClusterResources(ctx, &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: bootstrap, Region: region}))
			secret, err := c.CoreV1().Secrets("default").Get(ctx, "octelium-init", k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Len(t, secret.Data, 3)
			assert.Equal(t, "example.com", string(secret.Data["domain"]))
			gotBootstrap, gotRegion := &cbootstrapv1.Config{}, &corev1.Region{}
			require.NoError(t, pbutils.Unmarshal(secret.Data["bootstrap"], gotBootstrap))
			require.NoError(t, pbutils.Unmarshal(secret.Data["region"], gotRegion))
			assert.True(t, pbutils.IsEqual(bootstrap, gotBootstrap))
			assert.True(t, pbutils.IsEqual(region, gotRegion))
			if existing {
				assert.Equal(t, "yes", secret.Labels["retained"])
				assert.Equal(t, "17", secret.ResourceVersion)
			}
		})
	}
}

func TestSetClusterResourcesErrors(t *testing.T) {
	for _, verb := range []string{"get", "create"} {
		t.Run(verb, func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
			want := errors.New("storage failure")
			c.PrependReactor(verb, "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
			err := setClusterResources(context.Background(), &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: &cbootstrapv1.Config{}})
			assert.ErrorIs(t, err, want)
		})
	}
}

func TestDoInstallLifecycle(t *testing.T) {
	t.Setenv("OCTELIUM_SKIP_MESSAGES", "true")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	require.NoError(t, cliutils.OpenDB("mem"))
	d := cliutils.GetDB()
	t.Cleanup(func() { d.Close() })
	require.NoError(t, d.SetSessionToken("example.com", &authv1.SessionToken{AccessToken: "stale"}))
	require.NoError(t, d.SetSessionToken("other.example", &authv1.SessionToken{AccessToken: "keep"}))
	c := newGenesisJobClient(t)
	c.PrependReactor("update", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job)
		assert.Equal(t, "default", action.GetNamespace())
		assert.Equal(t, "octelium-genesis", job.Name)
		assert.Equal(t, []string{"init"}, job.Spec.Template.Spec.Containers[0].Args)
		secret, err := c.Tracker().Get(k8scorev1.SchemeGroupVersion.WithResource("secrets"), "default", "octelium-init")
		assert.NoError(t, err)
		assert.Equal(t, "example.com", string(secret.(*k8scorev1.Secret).Data["domain"]))
		assert.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "init-token", Namespace: "octelium"}, Data: map[string][]byte{"data": []byte("new-token")}}))
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
		return false, nil, nil
	})
	path := filepath.Join(t.TempDir(), "credentials", "token")
	require.NoError(t, DoInstall(context.Background(), &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: &cbootstrapv1.Config{}, Version: "1.2.3", AuthTokenSavePath: path}))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new-token", string(data))
	_, err = d.Get("example.com")
	assert.True(t, d.ErrorIsNotFound(err))
	other, err := d.GetSessionToken("other.example")
	require.NoError(t, err)
	assert.Equal(t, "keep", other.AccessToken)
}

func TestDoInstallStopsBeforeGenesisOnStorageError(t *testing.T) {
	c := fakek8s.NewSimpleClientset()
	want := errors.New("write failed")
	c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
	assert.ErrorIs(t, DoInstall(context.Background(), &Opts{K8sC: c}), want)
	jobs, err := c.BatchV1().Jobs("default").List(t.Context(), k8smetav1.ListOptions{})
	require.NoError(t, err)
	assert.Empty(t, jobs.Items)
}

func TestDoInstallLaterStageErrors(t *testing.T) {
	t.Setenv("OCTELIUM_SKIP_MESSAGES", "true")
	c := fakek8s.NewSimpleClientset()
	want := errors.New("service account unavailable")
	c.PrependReactor("create", "serviceaccounts", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
	assert.ErrorIs(t, DoInstall(context.Background(), &Opts{K8sC: c}), want)
	for _, action := range c.Actions() {
		if action.GetResource().Resource == "secrets" && action.GetVerb() != "get" {
			assert.Equal(t, "default", action.GetNamespace())
		}
	}
	require.NoError(t, cliutils.OpenDB("mem"))
	d := cliutils.GetDB()
	t.Cleanup(func() { d.Close() })
	assert.Error(t, setInitialAuthToken(&Opts{AuthTokenSavePath: t.TempDir()}, legacyInitialToken()))
}

func TestInitialTokenWithUnreadableLocalState(t *testing.T) {
	t.Setenv("OCTELIUM_SKIP_MESSAGES", "true")
	dir := t.TempDir()
	require.NoError(t, cliutils.OpenDB(dir))
	d := cliutils.GetDB()
	t.Cleanup(func() { d.Close() })
	require.NoError(t, os.WriteFile(filepath.Join(dir, "octelium.db"), []byte("corrupt"), 0600))
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, setInitialAuthToken(&Opts{ClusterDomain: "example.com", AuthTokenSavePath: path}, legacyInitialToken()))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "token", string(data))
}

func TestInitialTokenSaveAndOutput(t *testing.T) {
	t.Setenv("OCTELIUM_SKIP_MESSAGES", "")
	require.NoError(t, cliutils.OpenDB("mem"))
	d := cliutils.GetDB()
	t.Cleanup(func() { d.Close() })
	for _, path := range []string{"", filepath.Join(t.TempDir(), "token")} {
		require.NoError(t, setInitialAuthToken(&Opts{ClusterDomain: "example.com", AuthTokenSavePath: path}, legacyInitialToken()))
	}
	blocked := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocked, []byte("file"), 0600))
	assert.Error(t, setInitialAuthToken(&Opts{ClusterDomain: "example.com", AuthTokenSavePath: filepath.Join(blocked, "token")}, legacyInitialToken()))
	assert.Error(t, setInitialAuthToken(&Opts{ClusterDomain: "example.com", AuthTokenSavePath: t.TempDir()}, legacyInitialToken()))
}

func TestInitialTokenRetry(t *testing.T) {
	job := completedInstallationJob()
	c := fakek8s.NewSimpleClientset(job)
	calls := 0
	c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.GetAction).GetName() != "init-token" {
			return false, nil, nil
		}
		calls++
		if calls == 1 {
			return true, nil, k8serr.NewNotFound(schema.GroupResource{Resource: "secrets"}, "init-token")
		}
		return true, legacyInitialToken(), nil
	})
	secret, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, time.Second)
	require.NoError(t, err)
	assert.Equal(t, "token", string(secret.Data["data"]))
	assert.Equal(t, 2, calls)
}

func TestInitialTokenReadError(t *testing.T) {
	job := completedInstallationJob()
	c := fakek8s.NewSimpleClientset(job)
	want := errors.New("token read failed")
	c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
	_, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, time.Second)
	require.ErrorIs(t, err, want)
}

func TestDoInstallPreservesExistingInstallation(t *testing.T) {
	for _, name := range []string{"init-token", "octelium-init", installationConfigMapName, "octelium-genesis-init"} {
		t.Run(name, func(t *testing.T) {
			var object runtime.Object = &k8scorev1.Secret{
				ObjectMeta: k8smetav1.ObjectMeta{Name: name, Namespace: octeliumNS, Annotations: map[string]string{"octelium.com/genesis-init-complete": "true"}},
				Data:       map[string][]byte{"data": []byte("existing-token")},
			}
			if name == installationConfigMapName {
				object = &k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: name, Namespace: octeliumNS}}
			}
			source := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "default"}, Data: map[string][]byte{"domain": []byte("original.example")}}
			c := fakek8s.NewSimpleClientset(object, source)
			require.ErrorContains(t, DoInstall(t.Context(), &Opts{K8sC: c, ClusterDomain: "replacement.example"}), "octops upgrade")
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
			}
			stored, err := c.CoreV1().Secrets("default").Get(t.Context(), source.Name, k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, source.Data, stored.Data)
		})
	}
}

func TestInstallationAdmissionAllowsFreshAndIncomplete(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		t.Run(fmt.Sprint(incomplete), func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
			if incomplete {
				require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-genesis-init", Namespace: octeliumNS}}))
				require.NoError(t, c.Tracker().Add(&k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: installationConfigMapName, Namespace: octeliumNS}}))
			}
			require.NoError(t, checkExistingInstallation(t.Context(), c))
		})
	}
}

func TestInstallationAdmissionReadFailures(t *testing.T) {
	for _, resource := range []string{"secrets", "configmaps"} {
		t.Run(resource, func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
			want := k8serr.NewServiceUnavailable("temporary outage")
			c.PrependReactor("get", resource, func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
			ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
			defer cancel()
			assert.ErrorIs(t, DoInstall(ctx, &Opts{K8sC: c}), want)
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
			}
		})
	}
}

func TestRepairBootstrapAfterFailedJob(t *testing.T) {
	c, opts, _ := newRepairBootstrap(t)
	_, err := createGenesis(t.Context(), opts)
	require.NoError(t, err)
	secret, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	actual := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.Unmarshal(secret.Data["bootstrap"], actual))
	assert.Equal(t, "corrected.example", actual.Spec.PrimaryStorage.GetPostgresql().Host)
}

func newRepairBootstrap(t *testing.T) (*fakek8s.Clientset, *Opts, *k8scorev1.Secret) {
	t.Helper()
	c := newGenesisJobClient(t)
	bootstrap := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: wrong.example, password: original}}, secondaryStorage: {redis: {host: localhost}}}"), bootstrap))
	opts := &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: bootstrap, Version: "1.2.3"}
	_, err := createGenesis(t.Context(), opts)
	require.NoError(t, err)
	source, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	source.UID, source.ResourceVersion = "input-uid", "1"
	source.Labels, source.Annotations = map[string]string{"customer": "preserved"}, map[string]string{"customer": "preserved"}
	source.Data["custom"] = []byte("preserved")
	_, err = c.CoreV1().Secrets("default").Update(t.Context(), source, k8smetav1.UpdateOptions{})
	require.NoError(t, err)
	job, err := c.BatchV1().Jobs("default").Get(t.Context(), genesisJobName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: "True"}}
	_, err = c.BatchV1().Jobs(job.Namespace).Update(t.Context(), job, k8smetav1.UpdateOptions{})
	require.NoError(t, err)
	bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "corrected.example"
	c.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updated := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Secret).DeepCopy()
		object, err := c.Tracker().Get(action.GetResource(), action.GetNamespace(), updated.Name)
		if err != nil {
			return true, nil, err
		}
		current := object.(*k8scorev1.Secret)
		if updated.UID != current.UID || updated.ResourceVersion != current.ResourceVersion {
			return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), updated.Name, fmt.Errorf("Secret changed"))
		}
		version, err := strconv.Atoi(current.ResourceVersion)
		require.NoError(t, err)
		updated.ResourceVersion = strconv.Itoa(version + 1)
		err = c.Tracker().Update(action.GetResource(), updated, action.GetNamespace())
		return true, updated, err
	})
	return c, opts, source.DeepCopy()
}

func TestRepairBootstrapRefusesStorageAndInstalledState(t *testing.T) {
	for _, state := range []string{"octelium-postgres", "octelium-redis", "octelium-init", "init-token", "configuration", "complete", "unknown-checkpoint", "invalid-hash"} {
		t.Run(state, func(t *testing.T) {
			c, opts, original := newRepairBootstrap(t)
			switch state {
			case "configuration":
				require.NoError(t, c.Tracker().Add(&k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: installationConfigMapName, Namespace: octeliumNS}}))
			case "complete", "unknown-checkpoint", "invalid-hash":
				hash, err := initializationInputHash(original.Data)
				require.NoError(t, err)
				checkpoint := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-genesis-init", Namespace: octeliumNS}, Data: map[string][]byte{"version": []byte("1"), "id": []byte("previous-initialization"), "input-hash": []byte(hash)}}
				if state == "complete" {
					checkpoint.Annotations = map[string]string{"octelium.com/genesis-init-complete": "true"}
				} else if state == "unknown-checkpoint" {
					checkpoint.Data["version"] = []byte("99")
				} else {
					checkpoint.Data["input-hash"] = []byte("invalid")
				}
				require.NoError(t, c.Tracker().Add(checkpoint))
			default:
				require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: state, Namespace: octeliumNS}, Data: map[string][]byte{"key": []byte("preserved")}}))
			}
			_, err := createGenesis(t.Context(), opts)
			require.ErrorContains(t, err, "bootstrap differs")
			current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, original, current)
		})
	}
}

func TestRepairBootstrapRepeatedCorrections(t *testing.T) {
	c, opts, original := newRepairBootstrap(t)
	hash, err := initializationInputHash(original.Data)
	require.NoError(t, err)
	checkpoint := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-genesis-init", Namespace: octeliumNS}, Data: map[string][]byte{"version": []byte("1"), "id": []byte("previous-initialization"), "input-hash": []byte(hash)}}
	require.NoError(t, c.Tracker().Add(checkpoint))
	for _, host := range []string{"corrected.example", "corrected-again.example", "final.example"} {
		opts.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = host
		job, err := createGenesis(t.Context(), opts)
		require.NoError(t, err)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: "True"}}
		_, err = c.BatchV1().Jobs(genesisNS).Update(t.Context(), job, k8smetav1.UpdateOptions{})
		require.NoError(t, err)
		current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, k8smetav1.GetOptions{})
		require.NoError(t, err)
		bootstrap := &cbootstrapv1.Config{}
		require.NoError(t, pbutils.Unmarshal(current.Data["bootstrap"], bootstrap))
		assert.Equal(t, host, bootstrap.Spec.PrimaryStorage.GetPostgresql().Host)
		assert.Equal(t, original.UID, current.UID)
		assert.Equal(t, original.Labels, current.Labels)
		assert.Equal(t, original.Annotations, current.Annotations)
		assert.Equal(t, original.Data["custom"], current.Data["custom"])
		retained, err := c.CoreV1().Secrets(octeliumNS).Get(t.Context(), checkpoint.Name, k8smetav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, checkpoint, retained)
	}
}

func TestRepairBootstrapRetriesAndConcurrentChanges(t *testing.T) {
	for _, point := range []string{"before", "after", "conflict", "changed-input", "replaced", "forbidden", "cancelled"} {
		t.Run(point, func(t *testing.T) {
			c, opts, original := newRepairBootstrap(t)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			writes := 0
			c.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				writes++
				if writes > 1 {
					return false, nil, nil
				}
				updated := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Secret).DeepCopy()
				assert.Equal(t, original.UID, updated.UID)
				assert.Equal(t, original.ResourceVersion, updated.ResourceVersion)
				switch point {
				case "after":
					updated.ResourceVersion = "2"
					require.NoError(t, c.Tracker().Update(action.GetResource(), updated, action.GetNamespace()))
				case "conflict", "changed-input", "replaced":
					changed := original.DeepCopy()
					changed.Annotations["concurrent"] = "preserved"
					changed.ResourceVersion = "2"
					if point == "changed-input" {
						bootstrap := proto.Clone(opts.Bootstrap).(*cbootstrapv1.Config)
						bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "another-client.example"
						changed.Data["bootstrap"] = pbutils.MarshalMust(bootstrap)
					}
					if point == "replaced" {
						changed.UID = "replacement-uid"
					}
					require.NoError(t, c.Tracker().Update(action.GetResource(), changed, action.GetNamespace()))
					return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), updated.Name, io.EOF)
				case "forbidden":
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), updated.Name, io.EOF)
				case "cancelled":
					cancel()
					return true, nil, context.Canceled
				}
				return true, nil, io.ErrUnexpectedEOF
			})
			_, err := createGenesis(ctx, opts)
			if point == "before" || point == "after" || point == "conflict" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, k8smetav1.GetOptions{})
			require.NoError(t, err)
			if point == "after" {
				assert.Equal(t, 1, writes)
			} else if point == "before" || point == "conflict" {
				assert.Equal(t, 2, writes)
			} else {
				assert.Equal(t, 1, writes)
			}
			if point == "conflict" {
				assert.Equal(t, "preserved", current.Annotations["concurrent"])
			}
			if point == "replaced" {
				assert.Equal(t, "replacement-uid", string(current.UID))
			}
			if point == "changed-input" {
				bootstrap := &cbootstrapv1.Config{}
				require.NoError(t, pbutils.Unmarshal(current.Data["bootstrap"], bootstrap))
				assert.Equal(t, "another-client.example", bootstrap.Spec.PrimaryStorage.GetPostgresql().Host)
			}
		})
	}
}

func TestRepairBootstrapRefusesActiveOwnedPod(t *testing.T) {
	c, opts, original := newRepairBootstrap(t)
	inserted := false
	c.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		object, err := c.Tracker().Get(batchv1.SchemeGroupVersion.WithResource("jobs"), genesisNS, genesisJobName)
		if err != nil {
			return false, nil, nil
		}
		job := object.(*batchv1.Job)
		if !inserted && job.Spec.Suspend != nil && *job.Spec.Suspend {
			inserted = true
			require.NoError(t, c.Tracker().Add(&k8scorev1.Pod{
				ObjectMeta: k8smetav1.ObjectMeta{Name: "custom-labels", Namespace: genesisNS, UID: "active-pod", OwnerReferences: []k8smetav1.OwnerReference{{Kind: "Job", Name: job.Name, UID: job.UID, Controller: new(true)}}},
				Status:     k8scorev1.PodStatus{Phase: k8scorev1.PodRunning},
			}))
		}
		return false, nil, nil
	})
	_, err := createGenesis(t.Context(), opts)
	require.ErrorContains(t, err, "bootstrap differs")
	assert.True(t, inserted)
	current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, original, current)
}

func TestRepairLegacyInitializationJobCompatibility(t *testing.T) {
	for _, state := range []string{"active", "suspended", "missing-input", "changed-input", "failed"} {
		t.Run(state, func(t *testing.T) {
			c := newGenesisJobClient(t)
			bootstrap := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: postgres.example}}, secondaryStorage: {redis: {host: redis.example}}}"), bootstrap))
			opts := &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: bootstrap, Version: "1.2.3"}
			legacy, err := submitGenesisJob(t.Context(), c, getGenesisJob(opts, nil), func(ctx context.Context) error { return setClusterResources(ctx, opts) })
			require.NoError(t, err)
			if state == "suspended" || state == "missing-input" {
				legacy.Spec.Suspend = new(true)
				legacy, err = c.BatchV1().Jobs(genesisNS).Update(t.Context(), legacy, k8smetav1.UpdateOptions{})
				require.NoError(t, err)
			}
			if state == "missing-input" {
				require.NoError(t, c.CoreV1().Secrets(genesisNS).Delete(t.Context(), "octelium-init", k8smetav1.DeleteOptions{}))
			}
			if state == "failed" {
				legacy.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue}}
				_, err = c.BatchV1().Jobs(genesisNS).Update(t.Context(), legacy, k8smetav1.UpdateOptions{})
				require.NoError(t, err)
			}
			if state == "changed-input" {
				opts.Bootstrap = proto.Clone(bootstrap).(*cbootstrapv1.Config)
				opts.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "changed.example"
			}
			accepted, err := createGenesis(t.Context(), opts)
			if state == "changed-input" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if state == "failed" {
				assert.NotEqual(t, legacy.UID, accepted.UID)
				assert.NotEmpty(t, accepted.Spec.Template.Annotations[initializationInputHashKey])
			} else {
				assert.Equal(t, legacy.UID, accepted.UID)
				assert.Empty(t, accepted.Spec.Template.Annotations[initializationInputHashKey])
			}
		})
	}
}

func TestRepairBootstrapStopsOnJobChange(t *testing.T) {
	for _, change := range []string{"started", "replaced"} {
		t.Run(change, func(t *testing.T) {
			c, opts, original := newRepairBootstrap(t)
			changed := false
			c.PrependReactor("get", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if changed || action.GetNamespace() != octeliumNS {
					return false, nil, nil
				}
				object, err := c.Tracker().Get(batchv1.SchemeGroupVersion.WithResource("jobs"), genesisNS, genesisJobName)
				require.NoError(t, err)
				job := object.(*batchv1.Job).DeepCopy()
				if job.Spec.Suspend != nil && *job.Spec.Suspend {
					changed = true
					if change == "started" {
						job.Spec.Suspend = new(false)
					} else {
						job.UID = "replacement-job"
					}
					job.ResourceVersion = "2"
					require.NoError(t, c.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), job, genesisNS))
				}
				return false, nil, nil
			})
			_, err := createGenesis(t.Context(), opts)
			require.Error(t, err)
			assert.True(t, changed)
			current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, original, current)
			job, err := c.BatchV1().Jobs(genesisNS).Get(t.Context(), genesisJobName, k8smetav1.GetOptions{})
			require.NoError(t, err)
			if change == "started" {
				assert.False(t, *job.Spec.Suspend)
			} else {
				assert.Equal(t, "replacement-job", string(job.UID))
			}
		})
	}
}

func TestRepairInputHashCompatibility(t *testing.T) {
	for _, tc := range []struct{ name, hash, binding string }{
		{"region", "44642b94e6da0fa7b5e5e944c5449349ae595f3980853843c35f62812964161c", "c02a415829ae7399191ecc015fed96410e70696d2529ad2a5e7f1ee249614d97"},
		{"nil-region", "06ff4e8bba40f04f913a4f55d7b50d0a44162095cc334f17f68f34fece97c0a9", "b6fb5dbd76337d2b30299063fc3991835dfe25f151cb708446006d6e59aa04e2"},
		{"unknown", "16ec771cc69f6f92bf580c017c28f942763fbafdfa4bae41705f356f484f18cc", "2d65e18f02d1112d75ea0ee7761dbbb09623fc502cff52aeb124baa2101e0245"},
		{"empty", "3babbfe6662c6fd5437cef3d4c7e5a590ce20ab4fba62412dd3c4d2cb9f5ae50", "5920145142603dd5c2de668f49e7780a254965c718c0d2a0ec4d40621593e5f2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bootstrap := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: localhost, username: postgres, password: ' p@ss:/?& ' }}, secondaryStorage: {redis: {host: localhost, database: 7}}}"), bootstrap))
			region := &corev1.Region{Metadata: &metav1.Metadata{Name: "default", Labels: map[string]string{"z": "2", "a": "1"}}, Spec: &corev1.Region_Spec{}, Status: &corev1.Region_Status{}}
			if tc.name == "nil-region" {
				region = nil
			}
			if tc.name == "unknown" {
				bootstrap.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01})
			}
			if tc.name == "empty" {
				bootstrap, region = &cbootstrapv1.Config{}, nil
			}
			hash, err := initializationInputHash(map[string][]byte{"bootstrap": pbutils.MarshalMust(bootstrap), "region": pbutils.MarshalMust(region), "domain": []byte("example.com")})
			require.NoError(t, err)
			assert.Equal(t, tc.hash, hash)
			assert.Equal(t, tc.binding, initializationInputBinding(hash, []byte("input-secret-uid")))
			assert.NotEqual(t, tc.binding, initializationInputBinding(hash, []byte("other-secret-uid")))
		})
	}
}

func TestRepairBindingDoesNotExposeInputHash(t *testing.T) {
	c, opts, _ := newRepairBootstrap(t)
	job, err := createGenesis(t.Context(), opts)
	require.NoError(t, err)
	source, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	hash, err := initializationInputHash(source.Data)
	require.NoError(t, err)
	assert.Len(t, source.Data[initializationInputKey], 32)
	assert.Equal(t, initializationInputBinding(hash, source.Data[initializationInputKey]), job.Spec.Template.Annotations[initializationInputHashKey])
	data, err := json.Marshal(job)
	require.NoError(t, err)
	assert.NotContains(t, string(data), hash)
	assert.NotContains(t, string(data), string(source.UID))
	assert.NotContains(t, string(data), "original")
}

func TestRepairConcurrentMatchingInstallations(t *testing.T) {
	c := newGenesisJobClient(t)
	bootstrap := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: postgres.example}}, secondaryStorage: {redis: {host: redis.example}}}"), bootstrap))
	opts := &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: bootstrap, Version: "1.2.3"}
	var wg sync.WaitGroup
	results := make(chan *batchv1.Job, 6)
	errors := make(chan error, 6)
	start := make(chan struct{})
	for range 6 {
		wg.Go(func() {
			<-start
			job, err := createGenesis(t.Context(), opts)
			results <- job
			errors <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	job, err := c.BatchV1().Jobs(genesisNS).Get(t.Context(), genesisJobName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	for result := range results {
		require.NotNil(t, result)
		assert.Equal(t, job.UID, result.UID)
	}
}

func TestRepairLegacyInputBindingIsOptional(t *testing.T) {
	for _, policy := range []string{"allow", "forbidden", "invalid", "immutable", "read-forbidden"} {
		t.Run(policy, func(t *testing.T) {
			c := newGenesisJobClient(t)
			bootstrap := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: postgres.example}}, secondaryStorage: {redis: {host: redis.example}}}"), bootstrap))
			opts := &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: bootstrap, Version: "1.2.3"}
			require.NoError(t, setClusterResources(t.Context(), opts))
			original, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
			require.NoError(t, err)
			if policy == "immutable" {
				original.Immutable = new(true)
				require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), original, genesisNS))
			}
			c.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if policy == "forbidden" {
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), original.Name, io.EOF)
				}
				if policy == "invalid" {
					return true, nil, k8serr.NewInvalid(k8scorev1.SchemeGroupVersion.WithKind("Secret").GroupKind(), original.Name, field.ErrorList{field.Forbidden(field.NewPath("data", initializationInputKey), "unsupported extension")})
				}
				return false, nil, nil
			})
			if policy == "read-forbidden" {
				c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if action.(k8stesting.GetAction).GetName() == "octelium-postgres" {
						return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "octelium-postgres", io.EOF)
					}
					return false, nil, nil
				})
			}
			job, err := createGenesis(t.Context(), opts)
			require.NoError(t, err)
			current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, k8smetav1.GetOptions{})
			require.NoError(t, err)
			for _, key := range []string{"bootstrap", "region", "domain"} {
				assert.Equal(t, original.Data[key], current.Data[key], key)
			}
			if policy == "allow" {
				assert.Len(t, current.Data[initializationInputKey], 32)
				assert.NotEmpty(t, job.Spec.Template.Annotations[initializationInputHashKey])
			} else {
				assert.Equal(t, original, current)
				assert.Empty(t, job.Spec.Template.Annotations[initializationInputHashKey])
			}
		})
	}
}

func TestRepairInputCreationSupportsLegacyAdmission(t *testing.T) {
	c := newGenesisJobClient(t)
	rejected := 0
	c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		secret := action.(k8stesting.CreateAction).GetObject().(*k8scorev1.Secret)
		if len(secret.Data[initializationInputKey]) != 0 {
			rejected++
			return true, nil, k8serr.NewInvalid(k8scorev1.SchemeGroupVersion.WithKind("Secret").GroupKind(), secret.Name, field.ErrorList{field.Forbidden(field.NewPath("data", initializationInputKey), "unsupported extension")})
		}
		return false, nil, nil
	})
	job, err := createGenesis(t.Context(), &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: &cbootstrapv1.Config{}, Version: "1.2.3"})
	require.NoError(t, err)
	assert.Equal(t, 1, rejected)
	assert.Empty(t, job.Spec.Template.Annotations[initializationInputHashKey])
	current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Len(t, current.Data, 3)
}

func TestRepairJobCreationSupportsLegacyAdmission(t *testing.T) {
	c := newGenesisJobClient(t)
	rejected := 0
	c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		if job.Spec.Template.Annotations[initializationInputHashKey] != "" {
			rejected++
			return true, nil, k8serr.NewInvalid(batchv1.SchemeGroupVersion.WithKind("Job").GroupKind(), job.Name, field.ErrorList{field.Forbidden(field.NewPath("spec", "template", "metadata", "annotations"), "unsupported extension")})
		}
		return false, nil, nil
	})
	job, err := createGenesis(t.Context(), &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: &cbootstrapv1.Config{}, Version: "1.2.3"})
	require.NoError(t, err)
	assert.Equal(t, 1, rejected)
	assert.Empty(t, job.Spec.Template.Annotations[initializationInputHashKey])
	assert.False(t, *job.Spec.Suspend)
}

func TestPreflightReadRecoveryPreservesInstalledGuard(t *testing.T) {
	for _, name := range []string{"init-token", initializationSecretName, "octelium-init", installationConfigMapName} {
		t.Run(name, func(t *testing.T) {
			var existing runtime.Object = &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: name, Namespace: octeliumNS, Annotations: map[string]string{initializationCompleteKey: "true"}}}
			if name == installationConfigMapName {
				existing = &k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: name, Namespace: octeliumNS}}
			}
			c := fakek8s.NewSimpleClientset(existing)
			failed := false
			c.PrependReactor("get", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if action.(k8stesting.GetAction).GetName() == name && !failed {
					failed = true
					return true, nil, io.ErrUnexpectedEOF
				}
				return false, nil, nil
			})
			require.ErrorContains(t, DoInstall(t.Context(), &Opts{K8sC: c}), "octops upgrade")
			require.True(t, failed)
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
			}
		})
	}
}

func TestBootstrapCreateReadbackRecovery(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		c := fakek8s.NewSimpleClientset()
		created, readFailed := false, false
		creates := 0
		c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			creates++
			created = true
			secret := action.(k8stesting.CreateAction).GetObject().(*k8scorev1.Secret).DeepCopy()
			if foreign {
				secret.Data["domain"] = []byte("another.example")
			}
			require.NoError(t, c.Tracker().Create(action.GetResource(), secret, action.GetNamespace()))
			return true, nil, io.ErrUnexpectedEOF
		})
		c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
			if created && !readFailed {
				readFailed = true
				return true, nil, k8serr.NewServiceUnavailable("readback is temporarily unavailable")
			}
			return false, nil, nil
		})
		err := setClusterResources(t.Context(), &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: &cbootstrapv1.Config{}})
		if foreign {
			require.ErrorContains(t, err, "bootstrap differs")
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, 1, creates)
		assert.True(t, readFailed)
		for _, action := range c.Actions() {
			assert.NotEqual(t, "update", action.GetVerb())
			assert.NotEqual(t, "delete", action.GetVerb())
		}
	}
}

func TestJobSubmissionRecoversEachKubernetesBoundary(t *testing.T) {
	for _, stage := range []string{"lookup", "list-jobs", "list-pods", "create-readback", "start-read", "start-write", "start-ack", "delete-before", "delete-ack", "delete-readback", "deletion-wait"} {
		t.Run(stage, func(t *testing.T) {
			c := newGenesisJobClient(t)
			desired := testSubmissionJob("1.2.3")
			if stage == "delete-before" || stage == "delete-ack" || stage == "delete-readback" || stage == "deletion-wait" {
				previous, err := SubmitGenesisJobWithResult(t.Context(), c, desired, testGenesisPreparation)
				require.NoError(t, err)
				previous.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
				require.NoError(t, c.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), previous, previous.Namespace))
			}
			failed, prepared, created, deleted := false, false, false, false
			readFailed := false
			updates, removes := 0, 0
			c.PrependReactor("*", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
				resource := action.GetResource().Resource
				switch action.GetVerb() {
				case "list":
					if !failed && (stage == "list-jobs" && resource == "jobs" || stage == "list-pods" && resource == "pods") {
						failed = true
						return true, nil, k8serr.NewServiceUnavailable("list outage")
					}
				case "get":
					if resource != "jobs" {
						break
					}
					if !failed && (stage == "lookup" || stage == "start-read" && prepared || stage == "deletion-wait" && deleted) {
						failed = true
						return true, nil, io.ErrUnexpectedEOF
					}
					if !readFailed && (stage == "create-readback" && created || stage == "delete-readback" && deleted) {
						readFailed = true
						return true, nil, k8serr.NewServiceUnavailable("readback outage")
					}
				case "create":
					if resource == "jobs" && stage == "create-readback" && !failed {
						failed, created = true, true
						job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
						job.UID, job.ResourceVersion = types.UID("committed-job"), "1"
						require.NoError(t, c.Tracker().Create(action.GetResource(), job, action.GetNamespace()))
						return true, nil, io.ErrUnexpectedEOF
					}
				case "update":
					if resource == "jobs" {
						updates++
						if !failed && (stage == "start-write" || stage == "start-ack") {
							failed = true
							if stage == "start-ack" {
								job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job).DeepCopy()
								job.ResourceVersion = "2"
								require.NoError(t, c.Tracker().Update(action.GetResource(), job, job.Namespace))
							}
							return true, nil, io.ErrUnexpectedEOF
						}
					}
				case "delete":
					if resource == "jobs" {
						removes++
						if !failed && (stage == "delete-before" || stage == "delete-ack" || stage == "delete-readback") {
							failed = true
							if stage != "delete-before" {
								deleted = true
								require.NoError(t, c.Tracker().Delete(action.GetResource(), action.GetNamespace(), action.(k8stesting.DeleteAction).GetName()))
							}
							return true, nil, io.ErrUnexpectedEOF
						}
						if stage == "deletion-wait" {
							deleted = true
						}
					}
				}
				return false, nil, nil
			})
			accepted, err := SubmitGenesisJobWithResult(t.Context(), c, desired, func(context.Context) error { prepared = true; return nil })
			require.NoError(t, err)
			require.True(t, failed)
			assert.NotEmpty(t, accepted.UID)
			require.NotNil(t, accepted.Spec.Suspend)
			assert.False(t, *accepted.Spec.Suspend)
			if stage == "start-ack" {
				assert.Equal(t, 1, updates)
			}
			if stage == "delete-ack" || stage == "delete-readback" {
				assert.Equal(t, 1, removes)
			}
		})
	}
}

func TestGeneratedJobCreationIsNotReplayed(t *testing.T) {
	c := fakek8s.NewSimpleClientset()
	job := testSubmissionJob("1.2.3")
	job.Name, job.GenerateName = "", "genesis-generated-"
	creates := 0
	c.PrependReactor("create", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
		creates++
		return true, nil, io.ErrUnexpectedEOF
	})
	_, err := SubmitGenesisJobWithResult(t.Context(), c, job, nil)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Equal(t, 1, creates)
}
