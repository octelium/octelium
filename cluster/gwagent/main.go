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

package main

import (
	"github.com/octelium/octelium/cluster/common/components"
	gwagent "github.com/octelium/octelium/cluster/gwagent/gwagent"
)

func init() {
	components.SetComponentNamespace(components.ComponentNamespaceOctelium)
	components.SetComponentType(components.GWAgent)
}

func main() {
	components.RunComponent(gwagent.Run, nil)
}
