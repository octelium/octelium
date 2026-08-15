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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
	k8scorev1 "k8s.io/api/core/v1"
)

func TestCreateGenesis(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	err = createGenesis(ctx, &Opts{
		ClusterDomain: "example.com",
		K8sC:          fakeC.K8sC,
		Region: &corev1.Region{
			Metadata: &metav1.Metadata{
				Name: "default",
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	err = createGenesis(ctx, &Opts{
		ClusterDomain: "example.com",
		K8sC:          fakeC.K8sC,
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
