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
	"github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/grpcerr"
)

func (s *Server) CreateSecret(ctx context.Context, req *corev1.Secret) (*corev1.Secret, error) {
	if err := s.validateSecret(ctx, req); err != nil {
		return nil, grpcutils.InvalidArgWithErr(err)
	}

	{
		_, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
		if err == nil {
			return nil, grpcutils.AlreadyExists("The Secret %s already exists", req.Metadata.Name)
		}
		if !grpcerr.IsNotFound(err) {
			return nil, grpcutils.InternalWithErr(err)
		}
	}

	item := &corev1.Secret{
		Metadata: common.MetadataFrom(req.Metadata),
		Spec:     req.Spec,
		Status:   &corev1.Secret_Status{},
		Data:     req.Data,
	}

	item, err := s.octeliumC.CoreC().CreateSecret(ctx, item)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return item, nil
}

func (s *Server) ListSecret(ctx context.Context, req *corev1.ListSecretOptions) (*corev1.SecretList, error) {

	vSecrets, err := s.octeliumC.CoreC().ListSecret(ctx, urscsrv.GetPublicListOptions(req))
	if err != nil {
		return nil, err
	}

	for _, secret := range vSecrets.Items {
		secret.Data = nil
	}

	return vSecrets, nil
}

func (s *Server) DeleteSecret(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, nil); err != nil {
		return nil, err
	}

	sec, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: req.Name, Uid: req.Uid})
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(sec); err != nil {
		return nil, err
	}

	_, err = s.octeliumC.CoreC().DeleteSecret(ctx, &rmetav1.DeleteOptions{Uid: sec.Metadata.Uid})
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) GetSecret(ctx context.Context, req *metav1.GetOptions) (*corev1.Secret, error) {
	if err := apivalidation.CheckGetOptions(req, nil); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystemHidden(ret); err != nil {
		return nil, err
	}

	ret.Data = nil

	return ret, nil
}

func (s *Server) UpdateSecret(ctx context.Context, req *corev1.Secret) (*corev1.Secret, error) {
	if err := s.validateSecret(ctx, req); err != nil {
		return nil, grpcutils.InvalidArgWithErr(err)
	}

	sec, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{
		Name: req.Metadata.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(sec); err != nil {
		return nil, err
	}

	sec.Spec = req.Spec
	sec.Data = req.Data

	item, err := s.octeliumC.CoreC().UpdateSecret(ctx, sec)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return item, nil
}

func (s *Server) validateSecret(ctx context.Context, itm *corev1.Secret) error {

	if err := apivalidation.ValidateCommon(itm, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
		},
	}); err != nil {
		return err
	}

	if itm.Spec == nil {
		return grpcutils.InvalidArg("Nil spec")
	}

	if itm.Data == nil || itm.Data.Type == nil {
		return grpcutils.InvalidArg("Empty Secret data")
	}

	if itm.Spec.Data != nil {
		switch itm.Spec.Data.Type.(type) {
		case *corev1.Secret_Spec_Data_Value:
			lenVal := len(itm.Spec.Data.GetValue())
			if lenVal == 0 || lenVal > 512*1024 {
				return grpcutils.InvalidArg("Invalid Secret size")
			}
		case *corev1.Secret_Spec_Data_ValueBytes:
			lenVal := len(itm.Spec.Data.GetValueBytes())
			if lenVal == 0 || lenVal > 512*1024 {
				return grpcutils.InvalidArg("Invalid Secret size")
			}
		default:
			return grpcutils.InvalidArg("Invalid Secret data type")
		}

	}

	switch itm.Data.Type.(type) {
	case *corev1.Secret_Data_Value:
		lenVal := len(itm.Data.GetValue())
		if lenVal == 0 || lenVal > 512*1024 {
			return grpcutils.InvalidArg("Invalid Secret size")
		}
	case *corev1.Secret_Data_ValueBytes:
		lenVal := len(itm.Data.GetValueBytes())
		if lenVal == 0 || lenVal > 512*1024 {
			return grpcutils.InvalidArg("Invalid Secret size")
		}
	default:
		return grpcutils.InvalidArg("Invalid Secret data type")
		/*
			case *corev1.Secret_Data_DataMap_:
				lenMap := len(itm.Data.GetDataMap().Map)
				if lenMap == 0 || lenMap > 1000 {
					return grpcutils.InvalidArg("Invalid data map length")
				}
				for key, val := range itm.Data.GetDataMap().Map {
					if !rgx.NameMain.MatchString(key) {
						return grpcutils.InvalidArg("Invalid Secret data map key: %s", key)
					}

					lenVal := len(val)

					if lenVal == 0 || lenVal > 512*1024 {
						return grpcutils.InvalidArg("Invalid Secret size")
					}
				}
		*/
	}

	return nil
}
