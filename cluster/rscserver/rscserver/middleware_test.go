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

package rscserver

import (
	"testing"

	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestGetRequestInfo(t *testing.T) {
	type validEntry struct {
		arg      string
		expected *regexResult
	}

	valids := []validEntry{
		{
			arg: "/octelium.api.rsc.core.v1.ResourceService/GetService",
			expected: &regexResult{
				api:     "core",
				version: "v1",
				verb:    "Get",
				kind:    "Service",
			},
		},
		{
			arg: "/octelium.api.rsc.core.v1.ResourceService/UpdateService",
			expected: &regexResult{
				api:     "core",
				version: "v1",
				verb:    "Update",
				kind:    "Service",
			},
		},
		{
			arg: "/octelium.api.rsc.core.v1.ResourceService/DeleteService",
			expected: &regexResult{
				api:     "core",
				version: "v1",
				verb:    "Delete",
				kind:    "Service",
			},
		},
		{
			arg: "/octelium.api.rsc.core.v1.ResourceService/WatchClusterConfig",
			expected: &regexResult{
				api:     "core",
				version: "v1",
				verb:    "Watch",
				kind:    "ClusterConfig",
			},
		},
	}

	for _, valid := range valids {
		res, err := getRequestInfo(valid.arg)
		assert.Nil(t, err)
		assert.Equal(t, res, valid.expected)
	}

	invalids := []string{
		"",
		utilrand.GetRandomString(6),
		utilrand.GetRandomString(60),
		"/octelium.api.rsc.cluster2.v1.ResourceService/WatchClusterConfig",
		"/octelium.api.rsc.core.v1.ResourceService/InvokeService",
		"/octelium.api.rsc.core.v1.ResourceService/UpdateService/",
		"/octelium.internal.core.v1.ResourceService/UpdateService",
		"/octelium.api.rsc.v1.ResourceService/UpdateService",
	}

	for _, invalid := range invalids {
		_, err := getRequestInfo(invalid)
		assert.NotNil(t, err)
	}
}
