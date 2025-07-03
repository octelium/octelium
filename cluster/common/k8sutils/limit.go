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

package k8sutils

import (
	"fmt"

	k8scorev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

const DefaultLimitMemoryMegabytes = 700
const DefaultLimitCPUMillicores = 1200

func GetDefaultLimits() k8scorev1.ResourceList {
	return k8scorev1.ResourceList{
		k8scorev1.ResourceMemory: resource.MustParse(fmt.Sprintf("%dMi", DefaultLimitMemoryMegabytes)),
		k8scorev1.ResourceCPU:    resource.MustParse(fmt.Sprintf("%dm", DefaultLimitCPUMillicores)),
	}
}
