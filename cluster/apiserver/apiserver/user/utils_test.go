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

package user

import (
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
)

func TestServiceTo(t *testing.T) {

	newSvc := func(addrs []*corev1.Service_Status_Address) *corev1.Service {
		return &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1.default",
			},
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				PrimaryHostname: "svc1",
				Port:            8080,
				NamespaceRef: &metav1.ObjectReference{
					Name: "default",
				},
				Addresses: addrs,
			},
		}
	}

	{
		ret := ServiceTo(newSvc(nil))
		assert.Equal(t, 0, len(ret.Status.Addresses))
	}

	{
		ret := ServiceTo(newSvc([]*corev1.Service_Status_Address{
			nil,
			{},
			{
				DualStackIP: &metav1.DualStackIP{},
			},
		}))
		assert.Equal(t, 0, len(ret.Status.Addresses))
	}

	{
		ret := ServiceTo(newSvc([]*corev1.Service_Status_Address{
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv4: "1.2.3.4",
					Ipv6: "::1",
				},
			},
			{
				DualStackIP: nil,
			},
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv4: "1.2.3.5",
				},
			},
		}))

		assert.Equal(t, []string{"1.2.3.4", "::1", "1.2.3.5"}, ret.Status.Addresses)
		assert.Equal(t, "svc1", ret.Status.PrimaryHostname)
		assert.Equal(t, uint32(8080), ret.Spec.Port)
	}
}
