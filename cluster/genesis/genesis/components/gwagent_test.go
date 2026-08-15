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
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/stretchr/testify/assert"
	k8scorev1 "k8s.io/api/core/v1"
)

func cniInstallation(confDir, multusConfDir string) *corev1.ClusterConfig_Status_Installation {
	cni := &corev1.ClusterConfig_Status_Installation_CNI{}
	switch {
	case multusConfDir != "":
		cni.ConfDirType = &corev1.ClusterConfig_Status_Installation_CNI_MultusConfDir{
			MultusConfDir: multusConfDir,
		}
	case confDir != "":
		cni.ConfDirType = &corev1.ClusterConfig_Status_Installation_CNI_ConfDir{
			ConfDir: confDir,
		}
	}

	return &corev1.ClusterConfig_Status_Installation{Cni: cni}
}

func TestGetMultusConfDir(t *testing.T) {

	for _, o := range []*CommonOpts{
		nil,
		{},
		{ClusterConfig: &corev1.ClusterConfig{}},
		optsWithInstallation(nil),
		optsWithInstallation(&corev1.ClusterConfig_Status_Installation{}),
		optsWithInstallation(&corev1.ClusterConfig_Status_Installation{
			Cni: &corev1.ClusterConfig_Status_Installation_CNI{},
		}),
		optsWithInstallation(cniInstallation("", "")),
	} {
		assert.Equal(t, vutils.MultusConfDirDefault, GetMultusConfDir(o))
	}

	assert.Equal(t, "/etc/cni/multus/net.d", GetMultusConfDir(
		optsWithInstallation(cniInstallation("/etc/cni", ""))))

	assert.Equal(t, "/var/lib/rancher/k3s/agent/etc/cni/multus/net.d", GetMultusConfDir(
		optsWithInstallation(cniInstallation("/var/lib/rancher/k3s/agent/etc/cni", ""))))

	assert.Equal(t, "/opt/multus/conf", GetMultusConfDir(
		optsWithInstallation(cniInstallation("", "/opt/multus/conf"))))
}

func TestGatewayAgentDaemonSetSecurityContext(t *testing.T) {

	ds := getGatewayAgentDaemonSet(&CommonOpts{
		ClusterConfig: &corev1.ClusterConfig{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.ClusterConfig_Spec{},
			Status:   &corev1.ClusterConfig_Status{},
		},
		Region: &corev1.Region{
			Metadata: &metav1.Metadata{Name: "default"},
			Spec:     &corev1.Region_Spec{},
			Status:   &corev1.Region_Status{},
		},
	})

	podSpec := ds.Spec.Template.Spec

	{
		sc := podSpec.Containers[0].SecurityContext

		assert.NotNil(t, sc.Capabilities)
		assert.Equal(t, []k8scorev1.Capability{"ALL"}, sc.Capabilities.Drop)

		assert.Equal(t, []k8scorev1.Capability{
			"NET_ADMIN",
			"NET_RAW",
			"MKNOD",
			"NET_BIND_SERVICE",
			// "DAC_OVERRIDE",
		}, sc.Capabilities.Add)

		assert.False(t, *sc.AllowPrivilegeEscalation)

		assert.Equal(t, int64(0), *sc.RunAsUser)
		assert.False(t, *sc.ReadOnlyRootFilesystem)

		assert.Nil(t, sc.Privileged)
	}

	{
		initContainer := podSpec.InitContainers[0]
		assert.Equal(t, "/lib/modules", initContainer.VolumeMounts[0].MountPath)
		assert.True(t, initContainer.VolumeMounts[0].ReadOnly)
	}
}

func TestGatewayAgentDaemonSetMultusConf(t *testing.T) {

	genOpts := func(inst *corev1.ClusterConfig_Status_Installation) *CommonOpts {
		o := optsWithInstallation(inst)
		o.Region = &corev1.Region{
			Metadata: &metav1.Metadata{Name: "default"},
			Spec:     &corev1.Region_Spec{},
			Status:   &corev1.Region_Status{},
		}
		return o
	}

	getVolume := func(ds *k8scorev1.PodSpec, name string) *k8scorev1.Volume {
		for _, vol := range ds.Volumes {
			if vol.Name == name {
				return &vol
			}
		}
		return nil
	}

	getMountPaths := func(c k8scorev1.Container, name string) []string {
		var ret []string
		for _, vm := range c.VolumeMounts {
			if vm.Name == name {
				ret = append(ret, vm.MountPath)
			}
		}
		return ret
	}

	getEnv := func(c k8scorev1.Container, name string) string {
		for _, env := range c.Env {
			if env.Name == name {
				return env.Value
			}
		}
		return ""
	}

	{
		ds := getGatewayAgentDaemonSet(genOpts(nil))
		podSpec := ds.Spec.Template.Spec

		vol := getVolume(&podSpec, "multus-conf")
		assert.NotNil(t, vol)
		assert.Equal(t, vutils.MultusConfDirDefault, vol.HostPath.Path)

		container := podSpec.Containers[0]

		mountPaths := getMountPaths(container, "multus-conf")
		assert.Contains(t, mountPaths, multusConfMountPath)
		assert.Contains(t, mountPaths, vutils.MultusConfDirDefault)

		assert.Equal(t, multusConfMountPath, getEnv(container, vutils.MultusConfDirEnv))

		assert.Nil(t, getVolume(&podSpec, "etc-cni"))
	}

	{
		ds := getGatewayAgentDaemonSet(genOpts(cniInstallation("", "/opt/multus/conf")))
		podSpec := ds.Spec.Template.Spec

		vol := getVolume(&podSpec, "multus-conf")
		assert.NotNil(t, vol)
		assert.Equal(t, "/opt/multus/conf", vol.HostPath.Path)

		container := podSpec.Containers[0]

		mountPaths := getMountPaths(container, "multus-conf")
		assert.Contains(t, mountPaths, multusConfMountPath)
		assert.Contains(t, mountPaths, vutils.MultusConfDirDefault)

		assert.Equal(t, multusConfMountPath, getEnv(container, vutils.MultusConfDirEnv))
	}
}
