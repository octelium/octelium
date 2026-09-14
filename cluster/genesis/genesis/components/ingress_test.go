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
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/stretchr/testify/assert"
	k8scorev1 "k8s.io/api/core/v1"
)

func ingressOpts(o *CommonOpts) *CommonOpts {
	o.Region = &corev1.Region{}
	return o
}

func volumeNames(volumes []k8scorev1.Volume) []string {
	var ret []string
	for _, itm := range volumes {
		ret = append(ret, itm.Name)
	}
	return ret
}

func volumeMountPaths(mounts []k8scorev1.VolumeMount) []string {
	var ret []string
	for _, itm := range mounts {
		ret = append(ret, itm.MountPath)
	}
	return ret
}

func TestGetEnvoyIngressDataPlaneConfig(t *testing.T) {
	t.Run("a Cluster without SPIFFE keeps the config it already has", func(t *testing.T) {
		for _, o := range []*CommonOpts{
			nil,
			{},
			{ClusterConfig: &corev1.ClusterConfig{}},
			optsWithInstallation(nil),
			optsWithInstallation(&corev1.ClusterConfig_Status_Installation{}),
			optsWithInstallation(spiffeInstallation(false, "", "octelium.local")),
		} {
			assert.Equal(t, envoyGatewayConfigTemplate, getEnvoyIngressDataPlaneConfig(o))
		}
	})

	t.Run("a Cluster with SPIFFE reaches the control plane over the SPIRE Agent",
		func(t *testing.T) {
			config := getEnvoyIngressDataPlaneConfig(optsWithInstallation(
				spiffeInstallation(true, "", "octelium.local")))

			assert.Equal(t, envoyGatewayConfigTemplateSPIFFE, config)

			assert.Contains(t, config, "cluster_name: spire_agent")
			assert.Contains(t, config, "path: /run/spire/sockets/spire-agent.sock")
			assert.Contains(t, config,
				"type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext")
			assert.Contains(t, config, "tls_certificate_sds_secret_configs")
			assert.Contains(t, config, "validation_context_sds_secret_config")
			assert.Contains(t, config, "name: default")
			assert.Contains(t, config, "name: ROOTCA")
			assert.Contains(t, config, "- h2")
		})

	t.Run("both configs point the xds cluster at the ingress control plane",
		func(t *testing.T) {
			for _, config := range []string{
				envoyGatewayConfigTemplate,
				envoyGatewayConfigTemplateSPIFFE,
			} {
				assert.Contains(t, config, "address: octelium-ingress.octelium.svc")
				assert.Contains(t, config, "port_value: 8080")
				assert.Contains(t, config, "id: octelium-ingress")
			}
		})
}

func TestGetEnvoyIngressDataPlaneConfigMap(t *testing.T) {

	cm := getEnvoyIngressDataPlaneConfigMap(optsWithInstallation(
		spiffeInstallation(false, "", "")))

	assert.Equal(t, "ingress-dataplane-envoy-config", cm.Name)
	assert.Equal(t, vutils.K8sNS, cm.Namespace)
	assert.Equal(t, envoyGatewayConfigTemplate, cm.Data["config"])

	cm = getEnvoyIngressDataPlaneConfigMap(optsWithInstallation(
		spiffeInstallation(true, "", "")))

	assert.Equal(t, envoyGatewayConfigTemplateSPIFFE, cm.Data["config"])
}

func TestGetIngressDataPlaneDeployment(t *testing.T) {
	t.Run("a Cluster without SPIFFE mounts nothing but its own config", func(t *testing.T) {
		dep := getIngressDataPlaneDeployment(ingressOpts(optsWithInstallation(
			spiffeInstallation(false, "", ""))))

		spec := dep.Spec.Template.Spec

		assert.Equal(t, []string{"envoy-config"}, volumeNames(spec.Volumes))
		assert.Equal(t, []string{"/etc/envoy/envoy.yaml"},
			volumeMountPaths(spec.Containers[0].VolumeMounts))

		assert.Equal(t,
			vutils.Sha256SumHex([]byte(envoyGatewayConfigTemplate)),
			dep.Spec.Template.Annotations["octelium.com/envoy-config-hash"])
	})

	t.Run("a Cluster with SPIFFE mounts the Workload API socket", func(t *testing.T) {
		dep := getIngressDataPlaneDeployment(ingressOpts(optsWithInstallation(
			spiffeInstallation(true, "csi.example.com", ""))))

		spec := dep.Spec.Template.Spec

		assert.Equal(t, []string{"envoy-config", "spiffe-agent"}, volumeNames(spec.Volumes))
		assert.NotNil(t, spec.Volumes[1].CSI)
		assert.Equal(t, "csi.example.com", spec.Volumes[1].CSI.Driver)

		assert.Equal(t, []string{"/etc/envoy/envoy.yaml", "/run/spire/sockets"},
			volumeMountPaths(spec.Containers[0].VolumeMounts))

		assert.Equal(t,
			vutils.Sha256SumHex([]byte(envoyGatewayConfigTemplateSPIFFE)),
			dep.Spec.Template.Annotations["octelium.com/envoy-config-hash"])
	})

	t.Run("the Envoy container is restarted whenever its config changes", func(t *testing.T) {
		without := getIngressDataPlaneDeployment(ingressOpts(optsWithInstallation(
			spiffeInstallation(false, "", ""))))
		with := getIngressDataPlaneDeployment(ingressOpts(optsWithInstallation(
			spiffeInstallation(true, "", ""))))

		assert.NotEqual(t,
			without.Spec.Template.Annotations["octelium.com/envoy-config-hash"],
			with.Spec.Template.Annotations["octelium.com/envoy-config-hash"])
	})
}
