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

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/stretchr/testify/assert"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	fakek8s "k8s.io/client-go/kubernetes/fake"
)

func newInstallationConfigMap(val string) *k8scorev1.ConfigMap {
	return &k8scorev1.ConfigMap{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name:      installationConfigMapName,
			Namespace: octeliumNS,
		},
		Data: map[string]string{
			installationConfigMapKey: val,
		},
	}
}

func TestGetSPIFFEWithoutConfigMap(t *testing.T) {
	ctx := context.Background()

	assert.Nil(t, GetSPIFFE(ctx, fakek8s.NewSimpleClientset()))
}

func TestGetSPIFFEWithoutSPIFFE(t *testing.T) {
	ctx := context.Background()

	for _, val := range []string{
		"",
		"{}",
		`{"cni":{"confDir":"/etc/cni"}}`,
		`{"spiffe":{"enable":false,"trustDomain":"octelium.local"}}`,
		`not json at all`,
	} {
		c := fakek8s.NewSimpleClientset()
		_, err := c.CoreV1().ConfigMaps(octeliumNS).
			Create(ctx, newInstallationConfigMap(val), k8smetav1.CreateOptions{})
		assert.Nil(t, err)

		assert.Nil(t, GetSPIFFE(ctx, c), "value %q must yield no SPIFFE", val)
	}
}

func TestGetSPIFFE(t *testing.T) {
	ctx := context.Background()

	c := fakek8s.NewSimpleClientset()
	_, err := c.CoreV1().ConfigMaps(octeliumNS).Create(ctx,
		newInstallationConfigMap(
			`{"spiffe":{"enable":true,"trustDomain":"octelium.local","csiDriver":{"name":"csi.example.com"}}}`),
		k8smetav1.CreateOptions{})
	assert.Nil(t, err)

	ret := GetSPIFFE(ctx, c)
	assert.NotNil(t, ret)
	assert.Equal(t, "octelium.local", ret.TrustDomain)
	assert.Equal(t, "csi.example.com", ret.CSIDriver)
	assert.Equal(t, "csi.example.com", ret.getCSIDriver())
}

func TestSpiffeFromBootstrap(t *testing.T) {
	for _, bs := range []*cbootstrapv1.Config{
		nil,
		{},
		{Spec: &cbootstrapv1.Config_Spec{}},
		{Spec: &cbootstrapv1.Config_Spec{Spiffe: &cbootstrapv1.Config_Spec_SPIFFE{}}},
		{Spec: &cbootstrapv1.Config_Spec{Spiffe: &cbootstrapv1.Config_Spec_SPIFFE{
			Enable: false, TrustDomain: "octelium.local"}}},
	} {
		assert.Nil(t, spiffeFromBootstrap(bs))
	}

	ret := spiffeFromBootstrap(&cbootstrapv1.Config{
		Spec: &cbootstrapv1.Config_Spec{
			Spiffe: &cbootstrapv1.Config_Spec_SPIFFE{
				Enable:      true,
				TrustDomain: "octelium.local",
			},
		},
	})
	assert.NotNil(t, ret)
	assert.Equal(t, "octelium.local", ret.TrustDomain)
	assert.Empty(t, ret.CSIDriver)
	assert.Equal(t, "csi.spiffe.io", ret.getCSIDriver())
}
