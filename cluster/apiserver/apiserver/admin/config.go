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

func (s *Server) CreateConfig(ctx context.Context, req *corev1.Config) (*corev1.Config, error) {
	if err := s.validateConfig(ctx, req); err != nil {
		return nil, grpcutils.InvalidArgWithErr(err)
	}

	{
		_, err := s.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
		if err == nil {
			return nil, grpcutils.AlreadyExists("The Config %s already exists", req.Metadata.Name)
		}
		if !grpcerr.IsNotFound(err) {
			return nil, grpcutils.InternalWithErr(err)
		}
	}

	item := &corev1.Config{
		Metadata: common.MetadataFrom(req.Metadata),
		Spec:     req.Spec,
		Status:   &corev1.Config_Status{},
		Data:     req.Data,
	}

	item, err := s.octeliumC.CoreC().CreateConfig(ctx, item)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	item.Data = nil

	return item, nil
}

func (s *Server) ListConfig(ctx context.Context, req *corev1.ListConfigOptions) (*corev1.ConfigList, error) {

	vConfigs, err := s.octeliumC.CoreC().ListConfig(ctx, urscsrv.GetPublicListOptions(req))
	if err != nil {
		return nil, err
	}

	for _, secret := range vConfigs.Items {
		secret.Data = nil
	}

	return vConfigs, nil
}

func (s *Server) DeleteConfig(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, nil); err != nil {
		return nil, err
	}

	sec, err := s.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: req.Name, Uid: req.Uid})
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(sec); err != nil {
		return nil, err
	}

	_, err = s.octeliumC.CoreC().DeleteConfig(ctx, &rmetav1.DeleteOptions{Uid: sec.Metadata.Uid})
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) GetConfig(ctx context.Context, req *metav1.GetOptions) (*corev1.Config, error) {
	if err := apivalidation.CheckGetOptions(req, nil); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{
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

func (s *Server) UpdateConfig(ctx context.Context, req *corev1.Config) (*corev1.Config, error) {
	if err := s.validateConfig(ctx, req); err != nil {
		return nil, grpcutils.InvalidArgWithErr(err)
	}

	sec, err := s.octeliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{
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

	item, err := s.octeliumC.CoreC().UpdateConfig(ctx, sec)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return item, nil
}

func (s *Server) validateConfig(ctx context.Context, itm *corev1.Config) error {

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
		return grpcutils.InvalidArg("Empty Config data")
	}

	switch itm.Data.Type.(type) {
	case *corev1.Config_Data_Value:
		lenVal := len(itm.Data.GetValue())
		if lenVal == 0 || lenVal > 3*1024*1024 {
			return grpcutils.InvalidArg("Invalid Config size: %d", lenVal)
		}
	case *corev1.Config_Data_ValueBytes:
		lenVal := len(itm.Data.GetValueBytes())
		if lenVal == 0 || lenVal > 3*1024*1024 {
			return grpcutils.InvalidArg("Invalid Config size: %d", lenVal)
		}
	default:
		return grpcutils.InvalidArg("Invalid Config data type")
		/*
			case *corev1.Config_Data_DataMap_:
				lenMap := len(itm.Data.GetDataMap().Map)
				if lenMap == 0 || lenMap > 1000 {
					return grpcutils.InvalidArg("Invalid data map length")
				}
				for key, val := range itm.Data.GetDataMap().Map {
					if !rgx.NameMain.MatchString(key) {
						return grpcutils.InvalidArg("Invalid Config data map key: %s", key)
					}

					lenVal := len(val)

					if lenVal == 0 || lenVal > 512*1024 {
						return grpcutils.InvalidArg("Invalid Config size")
					}
				}
		*/
	}

	return nil
}
