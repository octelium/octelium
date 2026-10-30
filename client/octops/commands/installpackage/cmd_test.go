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

package installpackage

import (
	"context"
	"fmt"
	"testing"

	"github.com/octelium/octelium/client/octops/commands/install"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestGenesisPackageJobs(t *testing.T) {
	t.Setenv("OCTELIUM_PRODUCTION", "true")
	t.Setenv("OCTELIUM_DEV", "false")
	for _, tc := range []struct{ cmd, pkg, wantCmd, wantPkg string }{
		{"", "", "init", "octelium"}, {"init", "octeliumee", "init", "octeliumee"}, {"upgrade", "cordium", "upgrade", "cordium"},
	} {
		t.Run(tc.wantCmd+"/"+tc.wantPkg, func(t *testing.T) {
			first := getGenesisJob("example.com", tc.cmd, "1.2.3", tc.pkg, nil)
			second := getGenesisJob("example.com", tc.cmd, "1.2.3", tc.pkg, nil)
			assert.NotEqual(t, first.Name, second.Name)
			assert.Regexp(t, "^octelium-genesis-"+tc.wantCmd+"-"+tc.wantPkg+"-[a-z0-9]{6}$", first.Name)
			assert.Equal(t, "octelium", first.Namespace)
			assert.Equal(t, first.Labels, first.Spec.Template.Labels)
			assert.Equal(t, "octelium-nocturne", first.Spec.Template.Spec.ServiceAccountName)
			assert.Equal(t, k8scorev1.RestartPolicyNever, first.Spec.Template.Spec.RestartPolicy)
			require.Len(t, first.Spec.Template.Spec.Containers, 1)
			container := first.Spec.Template.Spec.Containers[0]
			assert.Equal(t, tc.wantPkg+"-genesis", container.Name)
			assert.Contains(t, container.Image, tc.wantPkg+"-genesis:1.2.3")
			assert.Equal(t, []string{tc.wantCmd}, container.Args)
			assert.Equal(t, k8scorev1.PullAlways, container.ImagePullPolicy)
			assert.Empty(t, first.Spec.Template.Spec.Volumes)
		})
	}
	job := getGenesisJob("example.com", "upgrade", "1.2.3", "cordium", &install.SPIFFEOpts{CSIDriver: "custom.csi", TrustDomain: "test.local"})
	assert.Equal(t, "custom.csi", job.Spec.Template.Spec.Volumes[0].CSI.Driver)
	assert.Contains(t, job.Spec.Template.Spec.Containers[0].Env, k8scorev1.EnvVar{Name: "OCTELIUM_SPIFFE_TRUST_DOMAIN", Value: "test.local"})
}

func TestCreateGenesisPackage(t *testing.T) {
	ctx := context.Background()
	c := fakek8s.NewSimpleClientset(&k8scorev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "octelium-installation", Namespace: "octelium"}, Data: map[string]string{"installation.json": `{"spiffe":{"enable":true}}`}})
	for range 2 {
		require.NoError(t, createGenesis(ctx, c, "example.com", "init", "1.2.3", "octeliumee"))
	}
	jobs, err := c.BatchV1().Jobs("octelium").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, jobs.Items, 2)
	assert.NotEqual(t, jobs.Items[0].Name, jobs.Items[1].Name)
	for _, job := range jobs.Items {
		assert.Equal(t, "csi.spiffe.io", job.Spec.Template.Spec.Volumes[0].CSI.Driver)
	}
	want := k8serr.NewForbidden(schema.GroupResource{Group: "batch", Resource: "jobs"}, "test", fmt.Errorf("not permitted"))
	c.PrependReactor("create", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
	assert.ErrorIs(t, createGenesis(ctx, c, "example.com", "upgrade", "1.2.3", "cordium"), want)
}
