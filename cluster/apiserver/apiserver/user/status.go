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
	"github.com/octelium/octelium/cluster/common/userctx"
)

func (s *Server) GetStatus(ctx context.Context, req *userv1.GetStatusRequest) (*userv1.GetStatusResponse, error) {
	i, err := userctx.GetUserCtx(ctx)
	if err != nil {
		return nil, err
	}

	user := i.User
	sess := i.Session

	clusterCfg, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	ret := &userv1.GetStatusResponse{
		Domain: clusterCfg.Status.Domain,
		Cluster: &userv1.GetStatusResponse_Cluster{
			Metadata: &metav1.Metadata{
				DisplayName: clusterCfg.Metadata.DisplayName,
				Description: clusterCfg.Metadata.Description,
			},
		},

		User: &userv1.GetStatusResponse_User{
			Metadata: &metav1.Metadata{
				Name:        user.Metadata.Name,
				DisplayName: user.Metadata.DisplayName,
				Uid:         user.Metadata.Uid,
				PicURL:      user.Metadata.PicURL,
			},
			Spec: &userv1.GetStatusResponse_User_Spec{
				Email: user.Spec.Email,
			},
			Status: &userv1.GetStatusResponse_User_Status{},
		},
	}

	ret.Session = &userv1.GetStatusResponse_Session{
		Metadata: &metav1.Metadata{
			Name:   sess.Metadata.Name,
			Uid:    sess.Metadata.Uid,
			PicURL: sess.Metadata.PicURL,
		},
		Spec: &userv1.GetStatusResponse_Session_Spec{},
		Status: &userv1.GetStatusResponse_Session_Status{
			Type: userv1.GetStatusResponse_Session_Status_Type(sess.Status.Type),
		},
	}

	if ret.Session.Metadata.PicURL == "" {
		if sess.Status.Authentication != nil && sess.Status.Authentication.Info != nil &&
			sess.Status.Authentication.Info.GetIdentityProvider() != nil &&
			sess.Status.Authentication.Info.GetIdentityProvider().PicURL != "" {
			ret.Session.Metadata.PicURL = sess.Status.Authentication.Info.GetIdentityProvider().PicURL
		}
	}

	return ret, nil
}
