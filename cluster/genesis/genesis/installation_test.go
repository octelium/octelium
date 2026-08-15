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

package genesis

import (
	"testing"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func TestGetInstallationFromBootstrapWithoutOptions(t *testing.T) {
	for _, bs := range []*cbootstrapv1.Config{
		nil,
		{},
		{Spec: &cbootstrapv1.Config_Spec{}},
		{Spec: &cbootstrapv1.Config_Spec{
			PrimaryStorage: &cbootstrapv1.Config_Spec_PrimaryStorage{},
		}},
	} {
		ret, err := getInstallationFromBootstrap(bs)
		assert.Nil(t, err)
		assert.Nil(t, ret)
	}
}

func TestGetInstallationFromBootstrap(t *testing.T) {
	ret, err := getInstallationFromBootstrap(&cbootstrapv1.Config{
		Spec: &cbootstrapv1.Config_Spec{
			Spiffe: &cbootstrapv1.Config_Spec_SPIFFE{
				Enable:      true,
				TrustDomain: "octelium.local",
				CsiDriver: &cbootstrapv1.Config_Spec_SPIFFE_CSIDriver{
					Name: "csi.example.com",
				},
			},
			Cni: &cbootstrapv1.Config_Spec_CNI{
				ConfDirType: &cbootstrapv1.Config_Spec_CNI_MultusConfDir{
					MultusConfDir: "/opt/multus/conf",
				},
			},
			Ingress: &cbootstrapv1.Config_Spec_Ingress{
				FrontProxy: &cbootstrapv1.Config_Spec_Ingress_FrontProxy{
					Enable: true,
				},
			},
		},
	})
	assert.Nil(t, err)

	assert.True(t, ret.GetSpiffe().GetEnable())
	assert.Equal(t, "octelium.local", ret.GetSpiffe().GetTrustDomain())
	assert.Equal(t, "csi.example.com", ret.GetSpiffe().GetCsiDriver().GetName())

	assert.Empty(t, ret.GetCni().GetConfDir())
	assert.Equal(t, "/opt/multus/conf", ret.GetCni().GetMultusConfDir())

	assert.True(t, ret.GetIngress().GetFrontProxy().GetEnable())
}

func TestGetInstallationFromBootstrapPartial(t *testing.T) {
	ret, err := getInstallationFromBootstrap(&cbootstrapv1.Config{
		Spec: &cbootstrapv1.Config_Spec{
			Spiffe: &cbootstrapv1.Config_Spec_SPIFFE{Enable: true},
		},
	})
	assert.Nil(t, err)

	assert.True(t, ret.GetSpiffe().GetEnable())
	assert.Empty(t, ret.GetSpiffe().GetCsiDriver().GetName())
	assert.Nil(t, ret.GetCni())
	assert.Nil(t, ret.GetIngress())
}

func TestGetInstallationFromBootstrapYAML(t *testing.T) {
	y := `
spec:
  primaryStorage:
    postgresql:
      username: postgres
      password: "pass"
      host: localhost
      port: 5432
  secondaryStorage:
    redis:
      password: "pass"
      host: localhost
      port: 6379
  spiffe:
    enable: true
    trustDomain: octelium.local
    csiDriver:
      name: csi.example.com
  cni:
    confDir: /var/lib/rancher/k3s/agent/etc/cni
  ingress:
    frontProxy:
      enable: true
`
	bs := &cbootstrapv1.Config{}
	assert.Nil(t, pbutils.UnmarshalYAML([]byte(y), bs))

	ret, err := getInstallationFromBootstrap(bs)
	assert.Nil(t, err)

	assert.True(t, ret.GetSpiffe().GetEnable())
	assert.Equal(t, "octelium.local", ret.GetSpiffe().GetTrustDomain())
	assert.Equal(t, "csi.example.com", ret.GetSpiffe().GetCsiDriver().GetName())
	assert.Equal(t, "/var/lib/rancher/k3s/agent/etc/cni", ret.GetCni().GetConfDir())
	assert.Empty(t, ret.GetCni().GetMultusConfDir())
	assert.True(t, ret.GetIngress().GetFrontProxy().GetEnable())
}

func TestGetInstallationFromBootstrapYAMLBothConfDirs(t *testing.T) {
	y := `
spec:
  cni:
    confDir: /var/lib/rancher/k3s/agent/etc/cni
    multusConfDir: /opt/multus/conf
`
	assert.NotNil(t, pbutils.UnmarshalYAML([]byte(y), &cbootstrapv1.Config{}))
}

func TestGetInstallationFromBootstrapYAMLMultusConfDir(t *testing.T) {
	y := `
spec:
  cni:
    multusConfDir: /opt/multus/conf
`
	bs := &cbootstrapv1.Config{}
	assert.Nil(t, pbutils.UnmarshalYAML([]byte(y), bs))

	ret, err := getInstallationFromBootstrap(bs)
	assert.Nil(t, err)

	assert.Equal(t, "/opt/multus/conf", ret.GetCni().GetMultusConfDir())
	assert.Empty(t, ret.GetCni().GetConfDir())
}
