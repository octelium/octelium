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

package vutils

import (
	"fmt"
	"testing"

	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestGetServiceFullNameFromName(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		assert.Equal(t, "nginx.default", vutils.GetServiceFullNameFromName("nginx"))
		assert.Equal(t, "nginx.test", vutils.GetServiceFullNameFromName("nginx.test"))

		assert.Equal(t, "", vutils.GetServiceFullNameFromName(""))
	}
	{
		svc := utilrand.GetRandomStringCanonical(8)
		ns := utilrand.GetRandomStringCanonical(8)

		assert.Equal(t, fmt.Sprintf("%s.default", svc), vutils.GetServiceFullNameFromName(svc))
		assert.Equal(t, fmt.Sprintf("%s.%s", svc, ns), vutils.GetServiceFullNameFromName(fmt.Sprintf("%s.%s", svc, ns)))
	}
}
