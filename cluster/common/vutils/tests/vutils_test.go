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
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
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

func TestSetRegionPublicHostName(t *testing.T) {
	{
		r := &corev1.Region{
			Metadata: &metav1.Metadata{Name: "default"},
			Status:   &corev1.Region_Status{PublicHostname: "_r-default"},
		}
		vutils.SetRegionPublicHostName(r)
		assert.Equal(t, "octelium-region-default", r.Status.PublicHostname)
	}
	{
		name := utilrand.GetRandomStringCanonical(40)
		r := &corev1.Region{
			Metadata: &metav1.Metadata{Name: name},
			Status:   &corev1.Region_Status{},
		}
		vutils.SetRegionPublicHostName(r)
		assert.Equal(t, fmt.Sprintf("octelium-region-%s", name), r.Status.PublicHostname)
		assert.False(t, strings.Contains(r.Status.PublicHostname, "_"))
		assert.LessOrEqual(t, len(r.Status.PublicHostname), 63)
	}
}
