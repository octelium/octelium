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

func TestGetMultusConfDir(t *testing.T) {

	assert.Equal(t, vutils.MultusConfDirDefault, GetMultusConfDir(&CommonOpts{}))

	assert.Equal(t, "/etc/cni/multus/net.d", GetMultusConfDir(&CommonOpts{
		CNIConfDir: "/etc/cni",
	}))
	assert.Equal(t, "/var/lib/rancher/k3s/agent/etc/cni/multus/net.d", GetMultusConfDir(&CommonOpts{
		CNIConfDir: "/var/lib/rancher/k3s/agent/etc/cni",
	}))

	assert.Equal(t, "/opt/multus/conf", GetMultusConfDir(&CommonOpts{
		MultusConfDir: "/opt/multus/conf",
	}))

	assert.Equal(t, "/opt/multus/conf", GetMultusConfDir(&CommonOpts{
		CNIConfDir:    "/etc/cni",
		MultusConfDir: "/opt/multus/conf",
	}))
}

func TestGatewayAgentDaemonSetMultusConf(t *testing.T) {

	genOpts := func(o *CommonOpts) *CommonOpts {
		o.ClusterConfig = &corev1.ClusterConfig{
			Metadata: &metav1.Metadata{},
			Spec:     &corev1.ClusterConfig_Spec{},
			Status:   &corev1.ClusterConfig_Status{},
		}
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
		ds := getGatewayAgentDaemonSet(genOpts(&CommonOpts{}))
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
		ds := getGatewayAgentDaemonSet(genOpts(&CommonOpts{
			MultusConfDir: "/opt/multus/conf",
		}))
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
