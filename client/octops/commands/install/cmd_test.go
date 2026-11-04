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
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
