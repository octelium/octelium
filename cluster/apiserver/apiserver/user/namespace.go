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
	"context"

	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/urscsrv"
)

func (s *Server) ListNamespace(ctx context.Context, req *userv1.ListNamespaceOptions) (*userv1.NamespaceList, error) {

	nsList, err := s.octeliumC.CoreC().ListNamespace(ctx, urscsrv.GetUserPublicListOptions(req))
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	ret := &userv1.NamespaceList{
		ApiVersion:       "user/v1",
		Kind:             "NamespaceList",
		ListResponseMeta: nsList.ListResponseMeta,
	}

	for _, net := range nsList.Items {

		ns := &userv1.Namespace{
			Metadata: &metav1.Metadata{
				Uid:         net.Metadata.Uid,
				Name:        net.Metadata.Name,
				DisplayName: net.Metadata.DisplayName,
				Description: net.Metadata.Description,
			},

			Spec: &userv1.Namespace_Spec{},

			Status: &userv1.Namespace_Status{},
		}
		ret.Items = append(ret.Items, ns)
	}

	return ret, nil
}
