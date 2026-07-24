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
	"unicode/utf8"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/pkg/grpcerr"
)

const (
	cfgMaxDataSize    = 3 * 1024 * 1024
	cfgMaxDataMapKeys = 256
	cfgMaxDataMapKey  = 256
)

func (s *Server) CreateConfig(ctx context.Context, req *corev1.Config) (*corev1.Config, error) {
	if err := s.validateConfig(ctx, req); err != nil {
		return nil, err
	}

	{
		_, err := s.octeliumC.CoreC().GetConfig(ctx, apivalidation.ObjectToRGetOptions(req))
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

	if req == nil {
		return nil, grpcutils.InvalidArg("Nil request")
	}

	vConfigs, err := s.octeliumC.CoreC().ListConfig(ctx, urscsrv.GetPublicListOptions(req))
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	for _, itm := range vConfigs.Items {
		itm.Data = nil
	}

	return vConfigs, nil
}

func (s *Server) DeleteConfig(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, nil); err != nil {
		return nil, err
	}

	itm, err := s.octeliumC.CoreC().GetConfig(ctx, apivalidation.DeleteOptionsToRGetOptions(req))
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(itm); err != nil {
		return nil, err
	}

	_, err = s.octeliumC.CoreC().DeleteConfig(ctx, apivalidation.ObjectToRDeleteOptions(itm))
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) GetConfig(ctx context.Context, req *metav1.GetOptions) (*corev1.Config, error) {
	if err := apivalidation.CheckGetOptions(req, nil); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetConfig(ctx, apivalidation.GetOptionsToRGetOptions(req))
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
		return nil, err
	}

	itm, err := s.octeliumC.CoreC().GetConfig(ctx, apivalidation.ObjectToRGetOptions(req))
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	if err := apivalidation.CheckIsSystem(itm); err != nil {
		return nil, err
	}

	common.MetadataUpdate(itm.Metadata, req.Metadata)
	itm.Spec = req.Spec
	itm.Data = req.Data

	item, err := s.octeliumC.CoreC().UpdateConfig(ctx, itm)
	if err != nil {
		return nil, serr.InternalWithErr(err)
	}

	item.Data = nil

	return item, nil
}

func (s *Server) validateConfig(_ context.Context, itm *corev1.Config) error {

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
		if lenVal == 0 || lenVal > cfgMaxDataSize {
			return grpcutils.InvalidArg("Invalid Config size: %d", lenVal)
		}
	case *corev1.Config_Data_ValueBytes:
		lenVal := len(itm.Data.GetValueBytes())
		if lenVal == 0 || lenVal > cfgMaxDataSize {
			return grpcutils.InvalidArg("Invalid Config size: %d", lenVal)
		}
	case *corev1.Config_Data_DataMap_:
		dataMap := itm.Data.GetDataMap()
		if dataMap == nil || len(dataMap.Map) == 0 {
			return grpcutils.InvalidArg("Empty Config dataMap")
		}

		if len(dataMap.Map) > cfgMaxDataMapKeys {
			return grpcutils.InvalidArg("Too many Config dataMap keys: %d", len(dataMap.Map))
		}

		totalLen := 0
		for k, v := range dataMap.Map {
			if k == "" {
				return grpcutils.InvalidArg("Empty Config dataMap key")
			}
			if len(k) > cfgMaxDataMapKey {
				return grpcutils.InvalidArg("Config dataMap key is too long")
			}
			if !utf8.ValidString(k) {
				return grpcutils.InvalidArg("Config dataMap key must be valid UTF-8")
			}
			if len(v) == 0 {
				return grpcutils.InvalidArg("Empty Config dataMap value for the key: %s", k)
			}

			totalLen = totalLen + len(k) + len(v)
		}

		if totalLen > cfgMaxDataSize {
			return grpcutils.InvalidArg("Invalid Config size: %d", totalLen)
		}
	case *corev1.Config_Data_Attrs:
		attrs := itm.Data.GetAttrs()
		if attrs == nil || len(attrs.GetFields()) == 0 {
			return grpcutils.InvalidArg("Empty Config attrs")
		}

		if err := apivalidation.ValidateAttrs(attrs); err != nil {
			return err
		}
	default:
		return grpcutils.InvalidArg("Invalid Config data type")
	}

	return nil
}
