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
	"fmt"
	"os"
	"time"

	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/pkg/errors"
)

func Build(spec Spec) (*Scenario, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}

	ret := baseScenario()
	ret.ID = spec.ID()
	ret.CNI = spec.CNI

	switch spec.Distro {
	case DistroK3s:
		p := k3sProvisioner(spec.CNI)
		if spec.IsMultiNode() {
			p.withAgents(spec.Nodes - 1)
		}
		if spec.Chaos {
			p.tune()
		}
		ret.Provisioner = p
	default:
		return nil, errors.Errorf(
			"The distro %q is not implemented yet. Currently supported: %s",
			spec.Distro, DistroK3s)
	}

	ret.Description = fmt.Sprintf("Single-node %s with %s", spec.Distro, spec.CNI)

	if spec.IsMultiNode() {
		ret.Description = fmt.Sprintf("%d-node %s with %s, one Gateway per node",
			spec.Nodes, spec.Distro, spec.CNI)
		ret.Topology.Nodes = spec.Nodes
		ret.Topology.AgentLabels = []string{
			"octelium.com/node",
			vutils.NodeLabelDataPlane,
		}
		ret.Caps = append(ret.Caps, CapMultiNode)
		ret.Budget += time.Duration(spec.Nodes) * 2 * time.Minute
		ret.Install.WaitTimeout += time.Duration(spec.Nodes) * 30 * time.Second
		ret.Hooks.PostInstall = append(ret.Hooks.PostInstall,
			Step{Name: "octelium/gateway-hosts", Run: stepGatewayHosts})
	}

	if spec.SPIFFE {
		ret.Description += " and SPIRE"
		ret.Install.EnableSPIFFECSI = true
		ret.Install.SPIFFETrustDomain = spec.trustDomain()
		ret.Caps = append(ret.Caps, CapSPIFFE)
		ret.Hooks.PostPrepare = append(ret.Hooks.PostPrepare,
			Step{Name: "spiffe/spire", Run: stepSPIRE})
	}

	if spec.Chaos {
		ret.Description += ", tuned for the chaos suite"
		ret.Caps = append(ret.Caps, CapChaos)
		ret.Budget += 90 * time.Minute
		ret.Storage.Redis.Resources = &StorageResources{
			CPURequest:    "500m",
			MemoryRequest: "512Mi",
			MemoryLimit:   "4Gi",
		}
		ret.Storage.Postgres.Resources = &StorageResources{
			CPURequest:    "1",
			MemoryRequest: "512Mi",
			MemoryLimit:   "2Gi",
		}
	}

	if err := applyCustomizers(ret); err != nil {
		return nil, err
	}

	return ret, nil
}

func (s Spec) trustDomain() string {
	if val := os.Getenv("OCTELIUM_SPIFFE_TRUST_DOMAIN"); val != "" {
		return val
	}
	return SPIFFETrustDomainDefault
}

func baseScenario() *Scenario {
	return &Scenario{
		Domain: "localhost",

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

func k3sProvisioner(cni CNI) *K3s {
	ret := &K3s{
		Kubeconfig: "/etc/rancher/k3s/k3s.yaml",
		CNI:        cni,

		ServerArgs:  []string{"--disable traefik", "--docker"},
		InstallExec: []string{"--disable", "traefik"},
		Packages: []string{
			"iputils-ping", "postgresql", "jq", "curl",
			"ssh", "postgresql-client", "mysql-client",
		},
		DBHostPath: "/mnt/octelium/db",
		Paths:      k3sCNIPaths(cni),
	}

	if cni != CNIFlannel {
		disable := []string{"--flannel-backend=none", "--disable-network-policy"}
		ret.ServerArgs = append(ret.ServerArgs, disable...)
		ret.InstallExec = append(ret.InstallExec, disable...)
	}

	return ret
}
