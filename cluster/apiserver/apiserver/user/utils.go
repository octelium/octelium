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
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
)

func ServiceTo(p *corev1.Service) *userv1.Service {
	ret := &userv1.Service{
		Metadata: &metav1.Metadata{
			Uid:         p.Metadata.Uid,
			Name:        p.Metadata.Name,
			DisplayName: p.Metadata.DisplayName,
			Description: p.Metadata.Description,
		},

		Spec: &userv1.Service_Spec{
			Port:     uint32(ucorev1.ToService(p).RealPort()),
			Type:     userv1.Service_Spec_Type(ucorev1.ToService(p).GetMode()),
			IsTLS:    p.Spec.IsTLS,
			IsPublic: p.Spec.IsPublic,
		},
		Status: &userv1.Service_Status{
			Namespace:       p.Status.NamespaceRef.Name,
			PrimaryHostname: p.Status.PrimaryHostname,
			Addresses: func() []string {
				ret := []string{}

				for _, svcIP := range p.Status.Addresses {
					if svcIP.DualStackIP.Ipv4 != "" {
						ret = append(ret, svcIP.DualStackIP.Ipv4)
					}

					if svcIP.DualStackIP.Ipv6 != "" {
						ret = append(ret, svcIP.DualStackIP.Ipv6)
					}

				}

				return ret
			}(),
		},
	}

	return ret
}
