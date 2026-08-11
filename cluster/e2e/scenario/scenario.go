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
	"slices"
	"time"

	"github.com/pkg/errors"
)

const TestNamespace = "e2e"

type Capability string

const (
	CapMultiNode       Capability = "multi-node"
	CapRootTUN         Capability = "root-tun"
	CapQUICv0          Capability = "quicv0"
	CapIPv6            Capability = "ipv6"
	CapSPIFFE          Capability = "spiffe"
	CapHostPortIngress Capability = "host-port-ingress"
	CapHeavyUpstreams  Capability = "heavy-upstreams"
	CapUpgrade         Capability = "upgrade"
)

type Capabilities []Capability

func (c Capabilities) Has(arg Capability) bool {
	for _, itm := range c {
		if itm == arg {
			return true
		}
	}
	return false
}

type CNI string

const (
	CNIFlannel CNI = "flannel"
	CNICilium  CNI = "cilium"
	CNICalico  CNI = "calico"
	CNICanal   CNI = "canal"
	CNIKindnet CNI = "kindnet"
)

type CNIPaths struct {
	BinDir string
	NetDir string

	OcteliumCNIConfDir string
}

type Topology struct {
	Nodes  int
	Labels []string
}

type MultusOpts struct {
	Enabled      bool
	ChartVersion string

	Chart           string
	ImageRepository string
	AllowInsecure   bool
}

type PostgresOpts struct {
	Chart           string
	ChartVersion    string
	ImageRepository string
	AllowInsecure   bool

	ReleaseName string
	SecretName  string
	Host        string
	Port        int32
	Database    string
	Username    string

	PVCName string
	PVCSize string
}

type RedisOpts struct {
	Chart           string
	ChartVersion    string
	ImageRepository string
	AllowInsecure   bool

	ReleaseName string
	SecretName  string
	Host        string
	Port        int32
}

type StorageOpts struct {
	Postgres PostgresOpts
	Redis    RedisOpts
}

type InstallOpts struct {
	Version      string
	EnableQUICv0 bool
	NetworkMode  string

	Env map[string]string

	EnableSPIFFECSI   bool
	SPIFFECSIDriver   string
	SPIFFETrustDomain string

	IngressFrontProxy bool
	OTelCollector     bool
	ClusterCert       bool

	WaitDeployments []string
	WaitTimeout     time.Duration
}

type Hooks struct {
	PostProvision []Step
	PostPrepare   []Step
	PostInstall   []Step
}

var DefaultComponents = []string{
	"ingress",
	"ingress-dataplane",
	"nocturne",
	"rscserver",
	"octovigil",
	"gwagent",
}

type Scenario struct {
	ID          string
	Description string
	Domain      string

	Provisioner Provisioner
	CNI         CNI
	Topology    Topology
	Multus      MultusOpts
	Storage     StorageOpts
	Install     InstallOpts
	Hooks       Hooks
	Caps        Capabilities
	Components  []string

	Budget time.Duration
}

func (s *Scenario) ComponentList() []string {
	if len(s.Components) == 0 {
		return DefaultComponents
	}
	return s.Components
}

var registry = map[string]func() *Scenario{}

func Register(id string, fn func() *Scenario) {
	if _, ok := registry[id]; ok {
		panic("scenario already registered: " + id)
	}
	registry[id] = fn
}

func Get(id string) (*Scenario, error) {
	fn, ok := registry[id]
	if !ok {
		return nil, errors.Errorf("Unknown scenario %q. Known scenarios: %s", id, IDs())
	}
	ret := fn()
	ret.ID = id
	return ret, nil
}

func MustGet(id string) *Scenario {
	ret, err := Get(id)
	if err != nil {
		panic(err)
	}
	return ret
}

func IDs() []string {
	ret := make([]string, 0, len(registry))
	for id := range registry {
		ret = append(ret, id)
	}
	slices.Sort(ret)
	return ret
}
