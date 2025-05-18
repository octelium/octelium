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

package rscserver

import (
	"context"
	"encoding/json"

	"github.com/octelium/octelium/apis/cluster/csecretmanv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func (s *Server) handleSecretManagerSet(ctx context.Context,
	req umetav1.ResourceObjectI, api, version, kind string) (umetav1.ResourceObjectI, error) {
	if !s.hasSecretManager {
		return req, nil
	}

	if !s.isTypeSecret(req.GetKind()) {
		return req, nil
	}

	if !hasFieldData(req) {
		return req, nil
	}

	reqMap, err := pbutils.ConvertToMap(req)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	jsonBytes, err := json.Marshal(reqMap["data"])
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	reqMap["data"] = nil

	ret, err := s.opts.NewResourceObject(api, version, kind)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}
	if err := pbutils.UnmarshalFromMap(reqMap, ret); err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	if _, err := s.secretmanC.SetSecret(ctx, &csecretmanv1.SetSecretRequest{
		SecretRef: umetav1.GetObjectReference(req),
		Data:      jsonBytes,
	}); err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *Server) handleSecretManagerGet(ctx context.Context, req umetav1.ResourceObjectI, api, version, kind string) (umetav1.ResourceObjectI, error) {
	if !s.hasSecretManager {
		return req, nil
	}

	if !s.isTypeSecret(req.GetKind()) {
		return req, nil
	}

	resp, err := s.secretmanC.GetSecret(ctx, &csecretmanv1.GetSecretRequest{
		SecretRef: umetav1.GetObjectReference(req),
	})
	if err != nil {
		return nil, err
	}

	reqMap, err := pbutils.ConvertToMap(req)
	if err != nil {
		return nil, err
	}

	var dataMap map[string]any
	if err := json.Unmarshal(resp.Data, &dataMap); err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	reqMap["data"] = dataMap

	ret, err := s.opts.NewResourceObject(api, version, kind)
	if err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}
	if err := pbutils.UnmarshalFromMap(reqMap, ret); err != nil {
		return nil, grpcutils.InternalWithErr(err)
	}

	return ret, nil
}

func (s *Server) handleSecretManagerDelete(ctx context.Context,
	req umetav1.ResourceObjectI, api, version, kind string) error {
	if !s.hasSecretManager {
		return nil
	}

	if !s.isTypeSecret(req.GetKind()) {
		return nil
	}

	if !hasFieldData(req) {
		return nil
	}

	_, err := s.secretmanC.DeleteSecret(ctx, &csecretmanv1.DeleteSecretRequest{
		SecretRef: umetav1.GetObjectReference(req),
	})

	return err
}

func (s *Server) handleSecretManagerList(ctx context.Context, req []umetav1.ResourceObjectI, api, version, kind string) ([]umetav1.ResourceObjectI, error) {
	if !s.hasSecretManager {
		return req, nil
	}

	if len(req) < 1 {
		return req, nil
	}

	if !s.isTypeSecret(req[0].GetKind()) {
		return req, nil
	}

	var ret []umetav1.ResourceObjectI

	uids := func() []*metav1.ObjectReference {
		var ret []*metav1.ObjectReference
		for _, itm := range req {
			ret = append(ret, umetav1.GetObjectReference(itm))
		}
		return ret
	}()

	getReqItem := func(uid string) umetav1.ResourceObjectI {
		for _, itm := range req {
			if itm.GetMetadata().Uid == uid {
				return itm
			}
		}
		return nil
	}

	resp, err := s.secretmanC.ListSecret(ctx, &csecretmanv1.ListSecretRequest{
		SecretRefs: uids,
	})
	if err != nil {
		return nil, err
	}

	for _, itmResp := range resp.Items {
		itmReq := getReqItem(itmResp.SecretRef.Uid)
		if itmReq == nil {
			continue
		}

		reqMap, err := pbutils.ConvertToMap(itmReq)
		if err != nil {
			return nil, grpcutils.InternalWithErr(err)
		}

		var dataMap map[string]any
		if err := json.Unmarshal(itmResp.Data, &dataMap); err != nil {
			return nil, grpcutils.InternalWithErr(err)
		}

		reqMap["data"] = dataMap

		itmReturn, err := s.opts.NewResourceObject(api, version, kind)
		if err != nil {
			return nil, grpcutils.InternalWithErr(err)
		}
		if err := pbutils.UnmarshalFromMap(reqMap, itmReturn); err != nil {
			return nil, grpcutils.InternalWithErr(err)
		}

		ret = append(ret, itmReturn)
	}

	return ret, nil
}

func hasFieldData(item umetav1.ResourceObjectI) bool {
	var ret bool

	item.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Name() == "data" {
			ret = true
		}
		return true
	})

	return ret
}
