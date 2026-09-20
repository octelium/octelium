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
	"testing"

	"github.com/doug-martin/goqu/v9"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

/*
func TestWatchEvents(t *testing.T) {

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name:            utilrand.GetRandomStringCanonical(6),
			Uid:             vutils.UUIDv4(),
			ResourceVersion: vutils.UUIDv4(),
		},
	}

	s, err := NewServer(context.Background(), nil)
	assert.Nil(t, err)

	{
		retI, err := s.getCreateWatchEvent(svc, "core", "v1", ucorev1.KindService)
		assert.Nil(t, err)

		ret, ok := retI.(*core.ServiceWatchEvent)
		assert.True(t, ok)
		assert.True(t, pbutils.IsEqual(ret.Event.GetCreate().Item, svc))
	}

	{

		svc2 := pbutils.Clone(svc).(*corev1.Service)
		svc2.Metadata.ResourceVersion = vutils.UUIDv4()

		retI, err := s.getUpdateWatchEvent(svc2, svc, "core", "v1", ucorev1.KindService)
		assert.Nil(t, err)

		ret, ok := retI.(*core.ServiceWatchEvent)
		assert.True(t, ok)
		assert.True(t, pbutils.IsEqual(ret.Event.GetUpdate().NewItem, svc2))
		assert.True(t, pbutils.IsEqual(ret.Event.GetUpdate().OldItem, svc))
	}

	{
		retI, err := s.getDeleteWatchEvent(svc, "core", "v1", ucorev1.KindService)
		assert.Nil(t, err)

		ret, ok := retI.(*core.ServiceWatchEvent)
		assert.True(t, ok)
		assert.True(t, pbutils.IsEqual(ret.Event.GetDelete().Item, svc))
	}
}
*/

func TestToResourceList(t *testing.T) {
	var lst []umetav1.ResourceObjectI
	for i := 0; i < 5; i++ {
		storage := &corev1.Namespace{
			Metadata: &metav1.Metadata{
				Uid:  vutils.UUIDv4(),
				Name: utilrand.GetRandomStringCanonical(6),
			},
			Spec: &corev1.Namespace_Spec{},
		}

		lst = append(lst, storage)
	}

	s, err := NewServer(context.Background(), nil)
	assert.Nil(t, err)

	rscListI, err := s.toResourceList(lst, &metav1.ListResponseMeta{}, "core", "v1", ucorev1.KindNamespace)
	assert.Nil(t, err)
	rscList, ok := rscListI.(*corev1.NamespaceList)
	assert.True(t, ok)
	assert.Equal(t, 5, len(rscList.Items))
	for i := 0; i < 5; i++ {
		assert.True(t, pbutils.IsEqual(lst[i], rscList.Items[i]))
	}
}

func TestGetListFilters(t *testing.T) {

	getFilterSQL := func(filters ...*rmetav1.ListOptions_Filter) (string, error) {
		exprs, err := getListFilters(&rmetav1.ListOptions{
			Filters: filters,
		})
		if err != nil {
			return "", err
		}

		sqln, _, err := goqu.From(tableName).Where(exprs...).Select("resource").ToSQL()
		return sqln, err
	}

	{
		sqln, err := getFilterSQL(&rmetav1.ListOptions_Filter{
			Field: "status.userRef.uid",
			Op:    rmetav1.ListOptions_Filter_OP_EQ,
			Value: &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: "uid1",
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t,
			`SELECT "resource" FROM "octelium_resources" WHERE (resource->'status'->'userRef'->>'uid' = 'uid1')`,
			sqln)
	}

	{
		sqln, err := getFilterSQL(&rmetav1.ListOptions_Filter{
			Field: "metadata.isSystemHidden",
			Op:    rmetav1.ListOptions_Filter_OP_EQ,
			Value: &structpb.Value{
				Kind: &structpb.Value_BoolValue{
					BoolValue: false,
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t,
			`SELECT "resource" FROM "octelium_resources" WHERE (jsonb_exists(resource->'metadata', 'isSystemHidden') IS NOT TRUE)`,
			sqln)
	}

	{
		sqln, err := getFilterSQL(&rmetav1.ListOptions_Filter{
			Field: "spec.groups",
			Op:    rmetav1.ListOptions_Filter_OP_INCLUDES,
			Value: &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: "grp1",
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t,
			`SELECT "resource" FROM "octelium_resources" WHERE (jsonb_exists(resource->'spec'->'groups', 'grp1') IS TRUE)`,
			sqln)
	}

	{
		sqln, err := getFilterSQL(&rmetav1.ListOptions_Filter{
			Field: "spec.groups",
			Op:    rmetav1.ListOptions_Filter_OP_INCLUDES,
			Value: &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: `grp1') IS NOT TRUE OR (1=1`,
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t,
			`SELECT "resource" FROM "octelium_resources" WHERE (jsonb_exists(resource->'spec'->'groups', 'grp1'') IS NOT TRUE OR (1=1') IS TRUE)`,
			sqln)
	}

	{
		sqln, err := getFilterSQL(&rmetav1.ListOptions_Filter{
			Field: "status.userRef.uid",
			Op:    rmetav1.ListOptions_Filter_OP_EQ,
			Value: &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: `uid1' OR '1'='1`,
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t,
			`SELECT "resource" FROM "octelium_resources" WHERE (resource->'status'->'userRef'->>'uid' = 'uid1'' OR ''1''=''1')`,
			sqln)
	}

	for _, field := range []string{
		"",
		"status.",
		"status.userRef'",
		"status.userRef.uid; DROP TABLE octelium_resources",
		"status.user Ref.uid",
		`status.userRef.uid' = 'x' OR '1'='1`,
	} {
		_, err := getFilterSQL(&rmetav1.ListOptions_Filter{
			Field: field,
			Op:    rmetav1.ListOptions_Filter_OP_EQ,
			Value: &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: "uid1",
				},
			},
		})
		assert.NotNil(t, err, "field: %s", field)
	}

	{
		_, err := getFilterSQL(&rmetav1.ListOptions_Filter{
			Field: "status.userRef.uid",
			Op:    rmetav1.ListOptions_Filter_OP_EQ,
		})
		assert.NotNil(t, err)
	}

	{
		_, err := getFilterSQL(nil)
		assert.NotNil(t, err)
	}

	{
		_, err := getFilterSQL(&rmetav1.ListOptions_Filter{
			Field: "status.userRef.uid",
			Op:    rmetav1.ListOptions_Filter_OP_UNSET,
			Value: &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: "uid1",
				},
			},
		})
		assert.NotNil(t, err)
	}

	{
		_, err := getFilterSQL(&rmetav1.ListOptions_Filter{
			Field: "spec.groups",
			Op:    rmetav1.ListOptions_Filter_OP_INCLUDES,
			Value: &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: "",
				},
			},
		})
		assert.NotNil(t, err)
	}

	{
		_, err := getFilterSQL(&rmetav1.ListOptions_Filter{
			Field: "spec.groups",
			Op:    rmetav1.ListOptions_Filter_OP_INCLUDES,
			Value: &structpb.Value{
				Kind: &structpb.Value_BoolValue{
					BoolValue: true,
				},
			},
		})
		assert.NotNil(t, err)
	}
}

func TestGetLabelFilter(t *testing.T) {

	getLabelSQL := func(path, k, v string) string {
		sqln, _, err := goqu.From(tableName).
			Where(getLabelFilter(path, k, v)).Select("resource").ToSQL()
		assert.Nil(t, err, "%+v", err)
		return sqln
	}

	assert.Equal(t,
		`SELECT "resource" FROM "octelium_resources" WHERE (resource->'metadata'->'specLabels'->>'email' = 'user-example-com')`,
		getLabelSQL(specLabelsPath, "email", "user-example-com"))

	assert.Equal(t,
		`SELECT "resource" FROM "octelium_resources" WHERE (resource->'metadata'->'systemLabels'->>'octelium-cert' = 'true')`,
		getLabelSQL(systemLabelsPath, "octelium-cert", "true"))

	assert.Equal(t,
		`SELECT "resource" FROM "octelium_resources" WHERE (resource->'metadata'->'specLabels'->>'email'' = ''x'' OR ''1''=''1' = 'v')`,
		getLabelSQL(specLabelsPath, `email' = 'x' OR '1'='1`, "v"))

	assert.Equal(t,
		`SELECT "resource" FROM "octelium_resources" WHERE (resource->'metadata'->'specLabels'->>'email' = 'v'' OR ''1''=''1')`,
		getLabelSQL(specLabelsPath, "email", `v' OR '1'='1`))
}
