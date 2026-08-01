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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

type tstListOpts struct {
	common *metav1.CommonListOptions
}

func (t *tstListOpts) GetCommon() *metav1.CommonListOptions {
	return t.common
}

func findFilter(filters []*rmetav1.ListOptions_Filter, field string) *rmetav1.ListOptions_Filter {
	for _, f := range filters {
		if f.Field == field {
			return f
		}
	}
	return nil
}

func TestFilterFieldEQValStr(t *testing.T) {

	val := utilrand.GetRandomStringCanonical(8)
	f := FilterFieldEQValStr("status.userRef.uid", val)

	assert.Equal(t, "status.userRef.uid", f.Field)
	assert.Equal(t, rmetav1.ListOptions_Filter_OP_EQ, f.Op)
	assert.Equal(t, val, f.Value.GetStringValue())
}

func TestFilterFieldIncludesValStr(t *testing.T) {

	val := utilrand.GetRandomStringCanonical(8)
	f := FilterFieldIncludesValStr("spec.groups", val)

	assert.Equal(t, "spec.groups", f.Field)
	assert.Equal(t, rmetav1.ListOptions_Filter_OP_INCLUDES, f.Op)
	assert.Equal(t, val, f.Value.GetStringValue())
}

func TestFilterFieldBoolean(t *testing.T) {

	{
		f := FilterFieldBooleanTrue("spec.isPublic")
		assert.Equal(t, "spec.isPublic", f.Field)
		assert.Equal(t, rmetav1.ListOptions_Filter_OP_EQ, f.Op)
		assert.True(t, f.Value.GetBoolValue())
	}

	{
		f := FilterFieldBooleanFalse("metadata.isSystemHidden")
		assert.Equal(t, "metadata.isSystemHidden", f.Field)
		assert.Equal(t, rmetav1.ListOptions_Filter_OP_EQ, f.Op)
		assert.False(t, f.Value.GetBoolValue())
	}
}

func TestFilterStatusHelpers(t *testing.T) {

	{
		uid := utilrand.GetRandomStringCanonical(8)
		f := FilterStatusUserUID(uid)
		assert.Equal(t, "status.userRef.uid", f.Field)
		assert.Equal(t, uid, f.Value.GetStringValue())
	}

	{
		uid := utilrand.GetRandomStringCanonical(8)
		f := FilterStatusNamespaceUID(uid)
		assert.Equal(t, "status.namespaceRef.uid", f.Field)
		assert.Equal(t, uid, f.Value.GetStringValue())
	}
}

func TestFilterByUser(t *testing.T) {

	usr := &corev1.User{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
			Uid:  utilrand.GetRandomStringCanonical(16),
		},
	}

	{
		opts := FilterByUser(usr)
		assert.Equal(t, 1, len(opts.Filters))
		assert.Equal(t, "status.userRef.uid", opts.Filters[0].Field)
		assert.Equal(t, usr.Metadata.Uid, opts.Filters[0].Value.GetStringValue())
	}

	{
		opts := FilterByUserRef(&metav1.ObjectReference{
			Name: usr.Metadata.Name,
			Uid:  usr.Metadata.Uid,
		})
		assert.Equal(t, 1, len(opts.Filters))
		assert.Equal(t, usr.Metadata.Uid, opts.Filters[0].Value.GetStringValue())
	}
}

func TestGetPublicListOptions(t *testing.T) {

	{
		opts := GetPublicListOptions(&tstListOpts{})
		assert.True(t, opts.Paginate)
		assert.Equal(t, 1, len(opts.Filters))
		assert.NotNil(t, findFilter(opts.Filters, "metadata.isSystemHidden"))
		assert.Nil(t, findFilter(opts.Filters, "metadata.isUserHidden"))
		assert.Equal(t, 0, len(opts.OrderBy))
	}

	{
		extra := FilterFieldEQValStr("status.userRef.uid", "abc")
		opts := GetPublicListOptions(&tstListOpts{}, extra)
		assert.Equal(t, 2, len(opts.Filters))
		assert.NotNil(t, findFilter(opts.Filters, "status.userRef.uid"))
	}

	{
		opts := GetPublicListOptions(&tstListOpts{
			common: &metav1.CommonListOptions{
				Page:         3,
				ItemsPerPage: 42,
			},
		})
		assert.Equal(t, uint32(3), opts.Page)
		assert.Equal(t, uint32(42), opts.ItemsPerPage)
	}
}

func TestGetUserPublicListOptions(t *testing.T) {

	opts := GetUserPublicListOptions(&tstListOpts{})
	assert.True(t, opts.Paginate)
	assert.Equal(t, 2, len(opts.Filters))
	assert.NotNil(t, findFilter(opts.Filters, "metadata.isSystemHidden"))
	assert.NotNil(t, findFilter(opts.Filters, "metadata.isUserHidden"))

	for _, f := range opts.Filters {
		assert.False(t, f.Value.GetBoolValue())
	}
}

func TestGetPublicListOptionsOrderBy(t *testing.T) {

	{
		opts := GetPublicListOptions(&tstListOpts{
			common: &metav1.CommonListOptions{
				OrderBy: &metav1.CommonListOptions_OrderBy{
					Type: metav1.CommonListOptions_OrderBy_TYPE_UNSET,
				},
			},
		})
		assert.Equal(t, 0, len(opts.OrderBy))
	}

	{
		opts := GetPublicListOptions(&tstListOpts{
			common: &metav1.CommonListOptions{
				OrderBy: &metav1.CommonListOptions_OrderBy{
					Type: metav1.CommonListOptions_OrderBy_CREATED_AT,
					Mode: metav1.CommonListOptions_OrderBy_DESC,
				},
			},
		})
		assert.Equal(t, 1, len(opts.OrderBy))
		assert.Equal(t, rmetav1.ListOptions_OrderBy_TYPE_CREATED_AT, opts.OrderBy[0].Type)
		assert.Equal(t, rmetav1.ListOptions_OrderBy_MODE_DESC, opts.OrderBy[0].Mode)
	}

	{
		opts := GetPublicListOptions(&tstListOpts{
			common: &metav1.CommonListOptions{
				OrderBy: &metav1.CommonListOptions_OrderBy{
					Type: metav1.CommonListOptions_OrderBy_NAME,
					Mode: metav1.CommonListOptions_OrderBy_ASC,
				},
			},
		})
		assert.Equal(t, 1, len(opts.OrderBy))
		assert.Equal(t, rmetav1.ListOptions_OrderBy_TYPE_NAME, opts.OrderBy[0].Type)
		assert.Equal(t, rmetav1.ListOptions_OrderBy_MODE_ASC, opts.OrderBy[0].Mode)
	}

	{
		opts := GetUserPublicListOptions(&tstListOpts{
			common: &metav1.CommonListOptions{
				OrderBy: &metav1.CommonListOptions_OrderBy{
					Type: metav1.CommonListOptions_OrderBy_NAME,
				},
			},
		})
		assert.Equal(t, 1, len(opts.OrderBy))
		assert.Equal(t, rmetav1.ListOptions_OrderBy_MODE_ASC, opts.OrderBy[0].Mode)
	}
}
