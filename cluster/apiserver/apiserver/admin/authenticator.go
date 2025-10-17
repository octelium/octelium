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

package admin

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/urscsrv"
)

func (s *Server) ListAuthenticator(ctx context.Context, req *corev1.ListAuthenticatorOptions) (*corev1.AuthenticatorList, error) {

	var listOpts []*rmetav1.ListOptions_Filter

	if req.UserRef != nil {
		if err := apivalidation.CheckObjectRef(req.UserRef, &apivalidation.CheckGetOptionsOpts{}); err != nil {
			return nil, err
		}
		usr, err := s.octeliumC.CoreC().GetUser(ctx, &rmetav1.GetOptions{
			Uid:  req.UserRef.Uid,
			Name: req.UserRef.Name,
		})
		if err != nil {
			return nil, err
		}
		listOpts = append(listOpts, urscsrv.FilterStatusUserUID(usr.Metadata.Uid))
	}

	vAuthenticators, err := s.octeliumC.CoreC().ListAuthenticator(ctx, urscsrv.GetPublicListOptions(req, listOpts...))
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return vAuthenticators, nil
}

func (s *Server) DeleteAuthenticator(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, nil); err != nil {
		return nil, err
	}

	dev, err := s.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
		Name: req.Name,
		Uid:  req.Uid,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if _, err := s.octeliumC.CoreC().DeleteAuthenticator(ctx, &rmetav1.DeleteOptions{Uid: dev.Metadata.Uid}); err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) GetAuthenticator(ctx context.Context, req *metav1.GetOptions) (*corev1.Authenticator, error) {
	if err := apivalidation.CheckGetOptions(req, nil); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetAuthenticator(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	return ret, nil
}
