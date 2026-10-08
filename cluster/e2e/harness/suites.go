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

package harness

import (
	"os"
	"slices"
	"strings"

	"github.com/pkg/errors"
)

const (
	SuiteEnv        = "OCTELIUM_E2E_SUITE"
	ChaosScaleEnv   = "OCTELIUM_E2E_CHAOS_SCALE"
	ChaosClientsEnv = "OCTELIUM_E2E_CHAOS_CLIENTS"
)

const (
	SuiteBase  = "base"
	SuiteChaos = "chaos"
	SuiteAll   = "all"
)

var ChaosScales = []string{"small", "medium", "large", "xlarge"}

const ChaosScaleDefault = "medium"

func ParseSuites(val string) ([]string, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return []string{SuiteBase}, nil
	}

	var ret []string
	for _, itm := range strings.Split(val, ",") {
		itm = strings.TrimSpace(itm)
		switch itm {
		case SuiteBase, SuiteChaos:
			if !slices.Contains(ret, itm) {
				ret = append(ret, itm)
			}
		case SuiteAll:
			return []string{SuiteBase, SuiteChaos}, nil
		default:
			return nil, errors.Errorf("Unknown suite %q. One of: %s, %s, %s",
				itm, SuiteBase, SuiteChaos, SuiteAll)
		}
	}

	return ret, nil
}

func SuiteSelected(name string) bool {
	suites, err := ParseSuites(os.Getenv(SuiteEnv))
	if err != nil {
		return false
	}
	return slices.Contains(suites, name)
}

func ValidateChaosScale(val string) error {
	if val == "" || slices.Contains(ChaosScales, val) {
		return nil
	}
	return errors.Errorf("Unknown chaos scale %q. One of: %s", val, strings.Join(ChaosScales, ", "))
}

func ChaosScale() string {
	if val := strings.TrimSpace(os.Getenv(ChaosScaleEnv)); val != "" {
		return val
	}
	return ChaosScaleDefault
}

func (h *H) ArtifactDir() string {
	return h.artifacts.dir
}
