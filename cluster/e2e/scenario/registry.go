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

package scenario

import (
	"os"
	"time"

	"github.com/octelium/octelium/cluster/common/vutils"
)

func init() {
	register("k3s-flannel", k3sFlannel)
}

func k3sFlannel() *Scenario {
	return &Scenario{
		Description: "Single-node k3s on the host with flannel. The baseline environment.",
		Domain:      "localhost",

		CNI: CNIFlannel,

		Provisioner: &K3s{
			Kubeconfig: "/etc/rancher/k3s/k3s.yaml",

			ServerArgs:  []string{"--disable traefik", "--docker"},
			InstallExec: []string{"--disable", "traefik"},
			Packages: []string{
				"iputils-ping", "postgresql", "jq", "curl",
				"ssh", "postgresql-client", "mysql-client",
			},
			DBHostPath: "/mnt/octelium/db",
			Paths: CNIPaths{
				BinDir: "/var/lib/rancher/k3s/data/cni/",
				NetDir: "/var/lib/rancher/k3s/agent/etc/cni/net.d",
			},
		},

		Topology: Topology{
			Nodes: 1,
			Labels: []string{
				"octelium.com/node",
				vutils.NodeLabelControlPlane,
				vutils.NodeLabelDataPlane,
			},
		},

		Multus: MultusOpts{
			Enabled:      true,
			Chart:        "oci://registry-1.docker.io/bitnamicharts/multus-cni",
			ChartVersion: "2.2.7",

			ImageRepository: "bitnamilegacy/multus-cni",
			AllowInsecure:   true,
		},

		Storage: StorageOpts{
			Postgres: PostgresOpts{
				Chart:           "oci://registry-1.docker.io/bitnamicharts/postgresql",
				ChartVersion:    "16.4.14",
				ImageRepository: "bitnamilegacy/postgresql",
				AllowInsecure:   true,
				ReleaseName:     "octelium-pg",
				SecretName:      "octelium-pg",
				Host:            "octelium-pg-postgresql.default.svc",
				Port:            5432,
				Database:        "octelium",
				Username:        "octelium",
				PVCName:         "octelium-db-pvc",
				PVCSize:         "5Gi",
			},
			Redis: RedisOpts{
				Chart:           "oci://registry-1.docker.io/bitnamicharts/redis",
				ChartVersion:    "20.8.0",
				ImageRepository: "bitnamilegacy/redis",
				AllowInsecure:   true,
				ReleaseName:     "octelium-redis",
				SecretName:      "octelium-redis",
				Host:            "octelium-redis-master.default.svc",
				Port:            6379,
			},
		},

		Install: InstallOpts{
			Version:       os.Getenv("GITHUB_REF_NAME"),
			EnableQUICv0:  true,
			OTelCollector: true,
			ClusterCert:   true,
			WaitTimeout:   10 * time.Minute,
			WaitDeployments: []string{
				"octelium-ingress-dataplane",
				"octelium-ingress",
				"svc-default-octelium-api",
				"svc-auth-octelium-api",
				"svc-dns-octelium",
				"svc-demo-nginx-default",
				"svc-portal-default",
				"svc-default-default",
			},
		},

		Caps: Capabilities{
			CapQUICv0,
			CapIPv6,
			CapHostPortIngress,
			CapHeavyUpstreams,
			CapRootTUN,
		},

		Budget: 45 * time.Minute,
	}
}
