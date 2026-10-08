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
	"slices"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type Distro string

const (
	DistroK3s  Distro = "k3s"
	DistroRKE2 Distro = "rke2"
	DistroK8s  Distro = "k8s"
)

const (
	DefaultDistro = DistroK3s
	DefaultCNI    = CNIFlannel
)

const (
	spiffeSuffix = "spiffe"
	chaosSuffix  = "chaos"
	nodesPrefix  = "nodes"
)

const MaxNodes = 32

var multiNodeSizes = []int{2, 4, 8, 16, 32}

type Spec struct {
	Distro Distro
	CNI    CNI
	Nodes  int
	SPIFFE bool
	Chaos  bool
}

func (s Spec) ID() string {
	parts := []string{string(s.Distro), string(s.CNI)}
	if s.IsMultiNode() {
		parts = append(parts, fmt.Sprintf("%s%d", nodesPrefix, s.Nodes))
	}
	if s.SPIFFE {
		parts = append(parts, spiffeSuffix)
	}
	if s.Chaos {
		parts = append(parts, chaosSuffix)
	}
	return strings.Join(parts, "-")
}

func (s Spec) IsMultiNode() bool {
	return s.Nodes > 1
}

var distros = []Distro{DistroK3s, DistroRKE2, DistroK8s}

var cnisByDistro = map[Distro][]CNI{
	DistroK3s:  {CNIFlannel, CNICilium, CNICalico},
	DistroRKE2: {CNICanal, CNICilium, CNICalico},
	DistroK8s:  {CNICilium, CNICalico},
}

func Distros() []Distro { return slices.Clone(distros) }

func CNIsFor(d Distro) []CNI { return slices.Clone(cnisByDistro[d]) }

func Specs() []Spec {
	var ret []Spec
	for _, d := range distros {
		for _, c := range cnisByDistro[d] {
			for _, spiffe := range []bool{false, true} {
				for _, chaos := range []bool{false, true} {
					ret = append(ret, Spec{Distro: d, CNI: c, SPIFFE: spiffe, Chaos: chaos})
				}
			}
		}
	}

	for _, nodes := range multiNodeSizes {
		for _, chaos := range []bool{false, true} {
			ret = append(ret, Spec{Distro: DistroK3s, CNI: CNIFlannel, Nodes: nodes, Chaos: chaos})
		}
	}

	return ret
}

func errMalformedSpec(id string) error {
	return errors.Errorf(
		"Malformed scenario %q. Expected <distro>-<cni>[-nodes<N>][-spiffe][-chaos], "+
			"for example k3s-flannel or k3s-flannel-nodes4-chaos", id)
}

func ParseSpec(id string) (Spec, error) {
	ret := Spec{}

	parts := strings.Split(id, "-")
	if len(parts) < 2 {
		return ret, errMalformedSpec(id)
	}

	ret.Distro = Distro(parts[0])
	ret.CNI = CNI(parts[1])

	var hasNodes bool
	for _, mod := range parts[2:] {
		switch {
		case mod == spiffeSuffix && !ret.SPIFFE:
			ret.SPIFFE = true
		case mod == chaosSuffix && !ret.Chaos:
			ret.Chaos = true
		case strings.HasPrefix(mod, nodesPrefix) && !hasNodes:
			nodes, err := strconv.Atoi(strings.TrimPrefix(mod, nodesPrefix))
			if err != nil {
				return ret, errMalformedSpec(id)
			}
			hasNodes = true
			ret.Nodes = nodes
		default:
			return ret, errMalformedSpec(id)
		}
	}

	if err := ret.Validate(); err != nil {
		return ret, err
	}

	return ret, nil
}

func (s Spec) Validate() error {
	if !slices.Contains(distros, s.Distro) {
		return errors.Errorf("Unknown distro %q. One of: %s",
			s.Distro, joinAny(distros))
	}

	supported, ok := cnisByDistro[s.Distro]
	if !ok || len(supported) == 0 {
		return errors.Errorf("The distro %q supports no CNI yet", s.Distro)
	}

	if !slices.Contains(supported, s.CNI) {
		return errors.Errorf("The distro %q does not support the CNI %q. One of: %s",
			s.Distro, s.CNI, joinAny(supported))
	}

	if s.Nodes < 0 || s.Nodes > MaxNodes {
		return errors.Errorf("Invalid node count %d. A scenario runs between 1 and %d nodes",
			s.Nodes, MaxNodes)
	}

	if s.IsMultiNode() && (s.Distro != DistroK3s || s.CNI != CNIFlannel) {
		return errors.Errorf(
			"Multi-node scenarios currently run on %s with %s only, not %s with %s",
			DistroK3s, CNIFlannel, s.Distro, s.CNI)
	}

	return nil
}

func joinAny[T ~string](vals []T) string {
	ret := make([]string, 0, len(vals))
	for _, v := range vals {
		ret = append(ret, string(v))
	}
	return strings.Join(ret, ", ")
}
