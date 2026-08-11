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

package suite

import (
	"os"
	"sort"
	"strings"
	"time"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
)

const (
	capMultiNode       = scenario.CapMultiNode
	capRootTUN         = scenario.CapRootTUN
	capQUICv0          = scenario.CapQUICv0
	capIPv6            = scenario.CapIPv6
	capSPIFFE          = scenario.CapSPIFFE
	capHostPortIngress = scenario.CapHostPortIngress
	capHeavyUpstreams  = scenario.CapHeavyUpstreams
	capUpgrade         = scenario.CapUpgrade
)

const propagationBudget = 10 * time.Second

const decisionSettle = 2 * time.Second

var errStillAllowed = errors.New("the request is still allowed")

func errUnexpectedStatus(got, want int) error {
	return errors.Errorf("got status %d, want %d", got, want)
}

func routeDevice(route string) string {
	fields := strings.Fields(route)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func hasRouteVia(routes, dev string) bool {
	for _, line := range strings.Split(routes, "\n") {
		if routeDevice(line) == dev {
			return true
		}
	}
	return false
}

func newMetadata() *metav1.Metadata {
	return &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)}
}

func envForLog() []string {
	var ret []string
	for _, itm := range os.Environ() {
		k, v, ok := strings.Cut(itm, "=")
		if !ok {
			continue
		}
		if isSecretEnvKey(k) {
			v = "[redacted]"
		}
		ret = append(ret, k+"="+v)
	}

	sort.Strings(ret)
	return ret
}

func isSecretEnvKey(k string) bool {
	k = strings.ToUpper(k)
	for _, needle := range []string{"TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL"} {
		if strings.Contains(k, needle) {
			return true
		}
	}
	return false
}
