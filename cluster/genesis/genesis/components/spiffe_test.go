/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package components

import (
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
)

func optsWithInstallation(inst *corev1.ClusterConfig_Status_Installation) *CommonOpts {
	return &CommonOpts{
		ClusterConfig: &corev1.ClusterConfig{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.ClusterConfig_Spec{},
			Status: &corev1.ClusterConfig_Status{
				Installation: inst,
			},
		},
	}
}

func spiffeInstallation(enable bool, csiDriver, trustDomain string) *corev1.ClusterConfig_Status_Installation {
	ret := &corev1.ClusterConfig_Status_Installation{
		Spiffe: &corev1.ClusterConfig_Status_Installation_SPIFFE{
			Enable:      enable,
			TrustDomain: trustDomain,
		},
	}
	if csiDriver != "" {
		ret.Spiffe.CsiDriver = &corev1.ClusterConfig_Status_Installation_SPIFFE_CSIDriver{
			Name: csiDriver,
		}
	}
	return ret
}

func envOf(c k8scorev1.Container) map[string]string {
	ret := map[string]string{}
	for _, itm := range c.Env {
		ret[itm.Name] = itm.Value
	}
	return ret
}

func newDeployment(env ...k8scorev1.EnvVar) *appsv1.Deployment {
	return &appsv1.Deployment{
		Spec: appsv1.DeploymentSpec{
			Template: k8scorev1.PodTemplateSpec{
				Spec: k8scorev1.PodSpec{
					Containers: []k8scorev1.Container{{Name: "main", Env: env}},
				},
			},
		},
	}
}

func TestSetDeploymentSPIFFE(t *testing.T) {
	t.Run("a Cluster without SPIFFE is left alone", func(t *testing.T) {
		dep := newDeployment()
		SetDeploymentSPIFFE(dep, optsWithInstallation(
			spiffeInstallation(false, "", "octelium.local")))

		assert.Empty(t, dep.Spec.Template.Spec.Volumes)
		assert.Empty(t, dep.Spec.Template.Spec.Containers[0].VolumeMounts)
		assert.Empty(t, dep.Spec.Template.Spec.Containers[0].Env)
	})

	t.Run("a Cluster with no installation options at all is left alone", func(t *testing.T) {
		for _, o := range []*CommonOpts{
			nil,
			{},
			{ClusterConfig: &corev1.ClusterConfig{}},
			optsWithInstallation(nil),
			optsWithInstallation(&corev1.ClusterConfig_Status_Installation{}),
		} {
			dep := newDeployment()
			SetDeploymentSPIFFE(dep, o)

			assert.Empty(t, dep.Spec.Template.Spec.Volumes)
			assert.Empty(t, dep.Spec.Template.Spec.Containers[0].VolumeMounts)
			assert.Empty(t, dep.Spec.Template.Spec.Containers[0].Env)
		}
	})

	t.Run("a component that mounts the SPIFFE volume is told SPIFFE is on",
		func(t *testing.T) {
			dep := newDeployment()
			SetDeploymentSPIFFE(dep, optsWithInstallation(
				spiffeInstallation(true, "", "octelium.local")))

			c := dep.Spec.Template.Spec.Containers[0]

			assert.Len(t, dep.Spec.Template.Spec.Volumes, 1)
			assert.NotNil(t, dep.Spec.Template.Spec.Volumes[0].CSI)
			assert.Equal(t, "csi.spiffe.io", dep.Spec.Template.Spec.Volumes[0].CSI.Driver)
			assert.Len(t, c.VolumeMounts, 1)
			assert.Equal(t, "/run/spire/sockets", c.VolumeMounts[0].MountPath)

			assert.Equal(t, map[string]string{
				"OCTELIUM_ENABLE_SPIFFE_CSI":   "true",
				"OCTELIUM_SPIFFE_TRUST_DOMAIN": "octelium.local",
			}, envOf(c))
		})

	t.Run("a custom CSI driver reaches both the volume and the component",
		func(t *testing.T) {
			dep := newDeployment()
			SetDeploymentSPIFFE(dep, optsWithInstallation(
				spiffeInstallation(true, "csi.example.com", "octelium.local")))

			assert.Equal(t, "csi.example.com",
				dep.Spec.Template.Spec.Volumes[0].CSI.Driver)
			assert.Equal(t, "csi.example.com",
				envOf(dep.Spec.Template.Spec.Containers[0])["OCTELIUM_SPIFFE_CSI_DRIVER"])
		})

	t.Run("a component that already set the env keeps its own value", func(t *testing.T) {
		dep := newDeployment(k8scorev1.EnvVar{
			Name: "OCTELIUM_ENABLE_SPIFFE_CSI", Value: "true"})

		SetDeploymentSPIFFE(dep, optsWithInstallation(
			spiffeInstallation(true, "", "octelium.local")))

		c := dep.Spec.Template.Spec.Containers[0]

		var count int
		for _, itm := range c.Env {
			if itm.Name == "OCTELIUM_ENABLE_SPIFFE_CSI" {
				count++
			}
		}
		assert.Equal(t, 1, count, "the env var must not be set twice")
		assert.Equal(t, "octelium.local", envOf(c)["OCTELIUM_SPIFFE_TRUST_DOMAIN"])
	})
}
