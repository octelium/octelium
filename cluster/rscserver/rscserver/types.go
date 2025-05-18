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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/doug-martin/goqu/v9"
	"github.com/doug-martin/goqu/v9/exp"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func (s *Server) toResourceList(lst []umetav1.ResourceObjectI, listMeta *metav1.ListResponseMeta, api, version, kind string) (proto.Message, error) {
	retMap := map[string]any{
		"apiVersion": vutils.GetApiVersion(api, version),
		"kind":       fmt.Sprintf("%sList", kind),
		"items":      []map[string]any{},
	}

	if listMeta != nil {
		retMap["listResponseMeta"] = map[string]any{
			"page":         listMeta.Page,
			"hasMore":      listMeta.HasMore,
			"totalCount":   listMeta.TotalCount,
			"itemsPerPage": listMeta.ItemsPerPage,
		}
	}

	itemsMap := []map[string]any{}
	for _, itm := range lst {
		objMap, err := pbutils.ConvertToMap(itm)
		if err != nil {
			return nil, err
		}
		itemsMap = append(itemsMap, objMap)
	}

	retMap["items"] = itemsMap
	jsonBytes, err := json.Marshal(retMap)
	if err != nil {
		return nil, err
	}

	objList, err := s.opts.NewResourceObjectList(api, version, kind)
	if err != nil {
		return nil, err
	}

	if err := pbutils.UnmarshalJSON(jsonBytes, objList); err != nil {
		return nil, err
	}

	return objList, nil
}

func getListFilters(req *rmetav1.ListOptions) []exp.Expression {
	var ret []exp.Expression

	for _, filter := range req.Filters {
		retFilter := "resource"

		args := strings.Split(filter.Field, ".")

		for idx := 0; idx < len(args)-1; idx++ {
			retFilter = fmt.Sprintf(`%s->'%s'`, retFilter, args[idx])
		}

		switch filter.Op {
		case rmetav1.ListOptions_Filter_OP_EQ:
			switch filter.Value.Kind.(type) {
			case *structpb.Value_BoolValue:
				if filter.Value.GetBoolValue() {
					retFilter = fmt.Sprintf(`%s->>'%s'`, retFilter, args[len(args)-1])
					ret = append(ret, goqu.L(retFilter).Eq(getPBVal(filter.Value)))
				} else {
					retFilter = fmt.Sprintf(`%s ? '%s'`, retFilter, args[len(args)-1])
					ret = append(ret, goqu.L(retFilter).IsNotTrue())
				}
			case *structpb.Value_NumberValue:
				if filter.Value.GetNumberValue() != 0 {
					retFilter = fmt.Sprintf(`%s->>'%s'`, retFilter, args[len(args)-1])
					retFilter = fmt.Sprintf(`(%s)::int`, retFilter)
					ret = append(ret, goqu.L(retFilter).Eq(getPBVal(filter.Value)))
				} else {
					retFilter = fmt.Sprintf(`%s ? '%s'`, retFilter, args[len(args)-1])
					ret = append(ret, goqu.L(retFilter).IsNotTrue())
				}

			case *structpb.Value_StringValue:
				if filter.Value.GetStringValue() != "" {
					retFilter = fmt.Sprintf(`%s->>'%s'`, retFilter, args[len(args)-1])
					ret = append(ret, goqu.L(retFilter).Eq(getPBVal(filter.Value)))
				} else {
					retFilter = fmt.Sprintf(`%s ? '%s'`, retFilter, args[len(args)-1])
					ret = append(ret, goqu.L(retFilter).IsNotTrue())
				}

			default:
				zap.L().Warn("Unsupported listFilter type. Skipping", zap.Any("val", filter.Value))
			}
		case rmetav1.ListOptions_Filter_OP_INCLUDES:
			switch filter.Value.Kind.(type) {
			case *structpb.Value_StringValue:
				if filter.Value.GetStringValue() != "" {
					retFilter = fmt.Sprintf(`%s->'%s' ? '%s'`, retFilter, args[len(args)-1], getPBVal(filter.Value))
					ret = append(ret, goqu.L(retFilter).IsTrue())
				}

			default:
				zap.L().Warn("Unsupported listFilter type. Skipping", zap.Any("val", filter.Value))
			}
		default:

		}
	}

	return ret
}

func getPBVal(arg *structpb.Value) any {
	switch arg.Kind.(type) {
	case *structpb.Value_StringValue:
		return arg.GetStringValue()
	case *structpb.Value_BoolValue:
		if arg.GetBoolValue() {
			return "true"
		} else {
			return ""
		}
	case *structpb.Value_NullValue:
		return nil
	case *structpb.Value_NumberValue:
		return arg.GetNumberValue()
	default:
		return nil
	}
}
