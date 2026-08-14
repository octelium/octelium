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

const spiffeSuffix = "spiffe"

type Spec struct {
	Distro Distro
	CNI    CNI
	SPIFFE bool
}

func (s Spec) ID() string {
	parts := []string{string(s.Distro), string(s.CNI)}
	if s.SPIFFE {
		parts = append(parts, spiffeSuffix)
	}
	return strings.Join(parts, "-")
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
				ret = append(ret, Spec{Distro: d, CNI: c, SPIFFE: spiffe})
			}
		}
	}
	return ret
}

func ParseSpec(id string) (Spec, error) {
	ret := Spec{}

	parts := strings.Split(id, "-")
	if len(parts) < 2 {
		return ret, errors.Errorf(
			"Malformed scenario %q. Expected <distro>-<cni>[-spiffe], for example k3s-flannel", id)
	}

	if last := parts[len(parts)-1]; last == spiffeSuffix {
		ret.SPIFFE = true
		parts = parts[:len(parts)-1]
	}

	if len(parts) != 2 {
		return ret, errors.Errorf(
			"Malformed scenario %q. Expected <distro>-<cni>[-spiffe], for example k3s-flannel", id)
	}

	ret.Distro = Distro(parts[0])
	ret.CNI = CNI(parts[1])

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

	return nil
}

func joinAny[T ~string](vals []T) string {
	ret := make([]string, 0, len(vals))
	for _, v := range vals {
		ret = append(ret, string(v))
	}
	return strings.Join(ret, ", ")
}
