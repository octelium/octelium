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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStorageResourcesArgs(t *testing.T) {
	t.Run("no resources keep the chart preset", func(t *testing.T) {
		assert.Empty(t, storageResourcesArgs("master", nil))
		assert.Empty(t, storageResourcesArgs("master", &StorageResources{}))
	})

	t.Run("only the set values are passed", func(t *testing.T) {
		assert.Equal(t, []string{
			"--set primary.resources.requests.cpu=1",
			"--set primary.resources.requests.memory=512Mi",
			"--set primary.resources.limits.memory=2Gi",
		}, storageResourcesArgs("primary", &StorageResources{
			CPURequest:    "1",
			MemoryRequest: "512Mi",
			MemoryLimit:   "2Gi",
		}))

		assert.Equal(t, []string{
			"--set master.resources.limits.memory=4Gi",
		}, storageResourcesArgs("master", &StorageResources{
			MemoryLimit: "4Gi",
		}))
	})
}
