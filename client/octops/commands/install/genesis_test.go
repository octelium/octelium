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
	"testing"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestCreateGenesis(t *testing.T) {

	ctx := context.Background()

	fakeC := fakek8s.NewSimpleClientset()

	err := createGenesis(ctx, &Opts{
		ClusterDomain: "example.com",
		K8sC:          fakeC,
		Region: &corev1.Region{
			Metadata: &metav1.Metadata{
				Name: "default",
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	err = createGenesis(ctx, &Opts{
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
		"OCTELIUM_DOMAIN":      "example.com",
		"OCTELIUM_REGION_NAME": "default",
	}, envOf(c))
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
	require.NoError(t, createGenesis(context.Background(), &Opts{K8sC: c, Bootstrap: bs, ClusterDomain: "example.com", Version: "1.2.3"}))
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

func TestCleanupResourcesFailures(t *testing.T) {
	for _, resource := range []string{"jobs", "clusterrolebindings", "clusterroles", "serviceaccounts"} {
		for _, verb := range []string{"get", "delete"} {
			t.Run(fmt.Sprintf("%s/%s", resource, verb), func(t *testing.T) {
				c := fakek8s.NewSimpleClientset(getGenesisJob(&Opts{}, nil), getGenesisRoleBinding(), getGenesisRole(), getGenesisServiceAccount())
				want := errors.New("cleanup failed")
				c.PrependReactor(verb, resource, func(action k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
				assert.ErrorIs(t, cleanupResources(context.Background(), c), want)
				actions := c.Actions()
				require.NotEmpty(t, actions)
				assert.Equal(t, verb, actions[len(actions)-1].GetVerb())
				assert.Equal(t, resource, actions[len(actions)-1].GetResource().Resource)
			})
		}
	}
}

func TestCreateGenesisFailures(t *testing.T) {
	for _, resource := range []string{"jobs", "serviceaccounts", "clusterroles", "clusterrolebindings"} {
		t.Run(resource, func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
			want := errors.New("creation failed")
			c.PrependReactor("create", resource, func(action k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
			assert.ErrorIs(t, createGenesis(context.Background(), &Opts{K8sC: c}), want)
			actions := c.Actions()
			assert.Equal(t, resource, actions[len(actions)-1].GetResource().Resource)
		})
	}
	c := fakek8s.NewSimpleClientset()
	c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("cleanup forbidden")
	})
	assert.ErrorContains(t, createGenesis(context.Background(), &Opts{K8sC: c}), "Could not clean up components")
	assert.Len(t, c.Actions(), 1)
}
