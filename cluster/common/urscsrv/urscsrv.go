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

package urscsrv

import (
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"google.golang.org/protobuf/types/known/structpb"
)

func FilterStatusUserUID(uid string) *rmetav1.ListOptions_Filter {
	return FilterFieldEQValStr("status.userRef.uid", uid)
}

func FilterStatusNamespaceUID(uid string) *rmetav1.ListOptions_Filter {
	return FilterFieldEQValStr("status.namespaceRef.uid", uid)
}

func FilterByUser(u *corev1.User) *rmetav1.ListOptions {

	return &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			FilterStatusUserUID(u.Metadata.Uid),
		},
	}
}

func FilterByUserRef(u *metav1.ObjectReference) *rmetav1.ListOptions {
	return &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			FilterStatusUserUID(u.Uid),
		},
	}
}

func FilterFieldEQValStr(field, val string) *rmetav1.ListOptions_Filter {
	return &rmetav1.ListOptions_Filter{
		Field: field,
		Op:    rmetav1.ListOptions_Filter_OP_EQ,
		Value: &structpb.Value{
			Kind: &structpb.Value_StringValue{
				StringValue: val,
			},
		},
	}
}

func FilterFieldIncludesValStr(field, val string) *rmetav1.ListOptions_Filter {
	return &rmetav1.ListOptions_Filter{
		Field: field,
		Op:    rmetav1.ListOptions_Filter_OP_INCLUDES,
		Value: &structpb.Value{
			Kind: &structpb.Value_StringValue{
				StringValue: val,
			},
		},
	}
}

func FilterFieldBooleanTrue(field string) *rmetav1.ListOptions_Filter {
	return &rmetav1.ListOptions_Filter{
		Field: field,
		Op:    rmetav1.ListOptions_Filter_OP_EQ,
		Value: &structpb.Value{
			Kind: &structpb.Value_BoolValue{
				BoolValue: true,
			},
		},
	}
}

func FilterFieldBooleanFalse(field string) *rmetav1.ListOptions_Filter {
	return &rmetav1.ListOptions_Filter{
		Field: field,
		Op:    rmetav1.ListOptions_Filter_OP_EQ,
		Value: &structpb.Value{
			Kind: &structpb.Value_BoolValue{
				BoolValue: false,
			},
		},
	}
}

type CommonListOpts interface {
	GetCommon() *metav1.CommonListOptions
}

func GetPublicListOptions(commonOpts CommonListOpts, filters ...*rmetav1.ListOptions_Filter) *rmetav1.ListOptions {

	ret := &rmetav1.ListOptions{
		Paginate: true,
		Filters: []*rmetav1.ListOptions_Filter{
			FilterFieldBooleanFalse("metadata.isSystemHidden"),
		},
	}

	return doGetPublicListOptions(ret, commonOpts, filters...)
}

func GetUserPublicListOptions(commonOpts CommonListOpts, filters ...*rmetav1.ListOptions_Filter) *rmetav1.ListOptions {

	ret := &rmetav1.ListOptions{
		Paginate: true,
		Filters: []*rmetav1.ListOptions_Filter{
			FilterFieldBooleanFalse("metadata.isSystemHidden"),
			FilterFieldBooleanFalse("metadata.isUserHidden"),
		},
	}

	return doGetPublicListOptions(ret, commonOpts, filters...)
}

func doGetPublicListOptions(parent *rmetav1.ListOptions, commonOpts CommonListOpts, filters ...*rmetav1.ListOptions_Filter) *rmetav1.ListOptions {

	ret := parent

	if commonOpts.GetCommon() != nil {
		ret.Page = commonOpts.GetCommon().Page
		ret.ItemsPerPage = commonOpts.GetCommon().ItemsPerPage
	}

	ret.Filters = append(ret.Filters, filters...)

	if commonOpts.GetCommon() != nil && commonOpts.GetCommon().OrderBy != nil &&
		commonOpts.GetCommon().OrderBy.Type != metav1.CommonListOptions_OrderBy_TYPE_UNSET {
		var typ rmetav1.ListOptions_OrderBy_Type
		var mode rmetav1.ListOptions_OrderBy_Mode
		switch commonOpts.GetCommon().OrderBy.Type {
		case metav1.CommonListOptions_OrderBy_CREATED_AT:
			typ = rmetav1.ListOptions_OrderBy_TYPE_CREATED_AT
		case metav1.CommonListOptions_OrderBy_NAME:
			typ = rmetav1.ListOptions_OrderBy_TYPE_NAME
		}

		switch commonOpts.GetCommon().OrderBy.Mode {
		case metav1.CommonListOptions_OrderBy_DESC:
			mode = rmetav1.ListOptions_OrderBy_MODE_DESC
		default:
			mode = rmetav1.ListOptions_OrderBy_MODE_ASC
		}

		ret.OrderBy = []*rmetav1.ListOptions_OrderBy{
			{
				Type: typ,
				Mode: mode,
			},
		}
	}

	return ret
}
