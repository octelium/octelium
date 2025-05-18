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

package httputils

import (
	"testing"

	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
)

func TestGetGRPCInfo(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	type tstCase struct {
		path            string
		service         string
		fullServiceName string
		pkg             string
		method          string
	}

	cases := []tstCase{
		{
			path:            "/octelium.api.main.core.v1.MainService/GetUser",
			service:         "MainService",
			fullServiceName: "octelium.api.main.core.v1.MainService",
			pkg:             "octelium.api.main.core.v1",
			method:          "GetUser",
		},
		{
			path:            "/a.b/c",
			service:         "b",
			fullServiceName: "a.b",
			pkg:             "a",
			method:          "c",
		},
	}

	for _, tstCase := range cases {
		res, err := GetGRPCInfo(tstCase.path)
		assert.Nil(t, err)
		assert.Equal(t, tstCase.service, res.Service)
		assert.Equal(t, tstCase.pkg, res.Package)
		assert.Equal(t, tstCase.fullServiceName, res.FullServiceName)
		assert.Equal(t, tstCase.method, res.Method)
	}

	invalids := []string{
		"",
		"/",
		".",
		"/.",
		"/a/b",
		"a/b/c",
		"/a/b/c/",
		"//",
	}
	for _, invalid := range invalids {
		_, err := GetGRPCInfo(invalid)
		assert.NotNil(t, err)
	}
}
