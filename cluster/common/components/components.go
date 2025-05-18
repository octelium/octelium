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
	"fmt"
	"time"

	"github.com/octelium/octelium/pkg/utils/ldflags"
)

type ComponentType = string
type ComponentNamespace = string

const ComponentNamespaceOctelium ComponentNamespace = "octelium"

const APIServer ComponentType = "apiserver"
const DNSServer ComponentType = "dnsserver"
const GWAgent ComponentType = "gwagent"
const Ingress ComponentType = "ingress"
const IngressDataPlane ComponentType = "ingress-dataplane"
const Nocturne ComponentType = "nocturne"
const AuthServer ComponentType = "authserver"
const RscServer ComponentType = "rscserver"
const Vigil ComponentType = "vigil"
const NodeInit ComponentType = "nodeinit"
const Genesis ComponentType = "genesis"
const Octovigil ComponentType = "octovigil"
const Portal ComponentType = "portal"

var myComponentType ComponentType
var myComponentNS ComponentNamespace

func MyComponentType() ComponentType {
	return myComponentType
}

func OcteliumComponent(arg string) string {
	return fmt.Sprintf("octelium-%s", arg)
}

func GetImage(component, version string) string {
	return ldflags.GetImage(fmt.Sprintf("octelium-%s", component), version)
}

var startedAt time.Time

func RuntimeStartedAt() time.Time {
	return startedAt
}

var runtimeID string

func RuntimeID() string {
	return runtimeID
}

func MyComponentUID() string {
	return fmt.Sprintf("%s-%s-%s", myComponentNS, myComponentType, runtimeID)
}

func SetComponentNamespace(arg ComponentNamespace) {
	myComponentNS = arg
}

func SetComponentType(arg ComponentNamespace) {
	myComponentType = arg
}

func MyComponentNamespace() string {
	return myComponentNS
}
