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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

func genTestGroup() *corev1.Group {
	return &corev1.Group{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Group_Spec{},
	}
}

func TestCreateGroup(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	validGroups := []*corev1.Group{
		{
			Metadata: &metav1.Metadata{
				Name: "group-1",
			},
			Spec: &corev1.Group_Spec{},
		},
	}

	for _, grp := range validGroups {
		outGrp, err := srv.CreateGroup(ctx, grp)
		assert.Nil(t, err)

		_, err = srv.octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{Uid: outGrp.Metadata.Uid})
		assert.Nil(t, err)

		assert.True(t, pbutils.IsEqual(grp.Spec, outGrp.Spec))
	}
}

func TestGroup(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	_, err = srv.CreateGroup(ctx, &corev1.Group{Metadata: &metav1.Metadata{Name: "group-1"}, Spec: &corev1.Group_Spec{}})
	assert.Nil(t, err)

	_, err = srv.CreateUser(ctx, &corev1.User{Metadata: &metav1.Metadata{Name: "usr-1"},
		Spec: &corev1.User_Spec{Type: corev1.User_Spec_WORKLOAD, Groups: []string{"group-1"}}})
	assert.Nil(t, err)

	_, err = srv.DeleteGroup(ctx, &metav1.DeleteOptions{Name: "group-1"})
	assert.NotNil(t, err)

	_, err = srv.DeleteUser(ctx, &metav1.DeleteOptions{Name: "usr-1"})
	assert.Nil(t, err)

	_, err = srv.DeleteGroup(ctx, &metav1.DeleteOptions{Name: "group-1"})
	assert.Nil(t, err)
}

func TestGroupCRUD(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	grp := genTestGroup()

	item, err := srv.CreateGroup(ctx, grp)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, grp.Metadata.Name, item.Metadata.Name)
	assert.NotNil(t, item.Status)

	{
		_, err = srv.CreateGroup(ctx, grp)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.AlreadyExists(err), "%+v", err)
	}

	{
		ret, err := srv.GetGroup(ctx, &metav1.GetOptions{Uid: item.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, item.Metadata.Uid, ret.Metadata.Uid)

		ret, err = srv.GetGroup(ctx, &metav1.GetOptions{Name: item.Metadata.Name})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, item.Metadata.Uid, ret.Metadata.Uid)
	}

	{
		_, err = srv.GetGroup(ctx, &metav1.GetOptions{})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err = srv.GetGroup(ctx, &metav1.GetOptions{Name: utilrand.GetRandomStringCanonical(8)})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		attrs, err := structpb.NewStruct(map[string]any{
			"myKey": "myValue",
		})
		assert.Nil(t, err, "%+v", err)

		item.Spec.Attrs = attrs
		item.Metadata.DisplayName = "new display name"

		updated, err := srv.UpdateGroup(ctx, item)
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, updated.Spec.Attrs)
		assert.Equal(t, "new display name", updated.Metadata.DisplayName)
		item = updated
	}

	{
		_, err = srv.UpdateGroup(ctx, genTestGroup())
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
	}

	{
		itemList, err := srv.ListGroup(ctx, &corev1.ListGroupOptions{})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, len(itemList.Items) >= 1)

		_, err = srv.ListGroup(ctx, nil)
		assert.NotNil(t, err)
	}

	{
		_, err = srv.DeleteGroup(ctx, &metav1.DeleteOptions{Uid: item.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)

		_, err = srv.DeleteGroup(ctx, &metav1.DeleteOptions{Uid: item.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err), "%+v", err)
	}
}

func TestValidateGroup(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	policy, err := srv.CreatePolicy(ctx, &corev1.Policy{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{
							MatchAny: true,
						},
					},
					Effect: corev1.Policy_Spec_Rule_ALLOW,
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	invalids := []*corev1.Group{
		{},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		},
		{
			Spec: &corev1.Group_Spec{},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Group_Spec{
				Authorization: &corev1.Group_Spec_Authorization{
					Policies: []string{utilrand.GetRandomStringCanonical(8)},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Group_Spec{
				Authorization: &corev1.Group_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Name: utilrand.GetRandomStringCanonical(8),
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Condition: &corev1.Condition{
											Type: &corev1.Condition_Match{
												Match: "!!!!",
											},
										},
										Effect: corev1.Policy_Spec_Rule_ALLOW,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Group_Spec{
				Authorization: &corev1.Group_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Name: utilrand.GetRandomStringCanonical(8),
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, invalid := range invalids {
		_, err = srv.CreateGroup(ctx, invalid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	attrs, err := structpb.NewStruct(map[string]any{
		"myKey": "myValue",
	})
	assert.Nil(t, err, "%+v", err)

	valids := []*corev1.Group{
		genTestGroup(),
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Group_Spec{
				Attrs: attrs,
				Authorization: &corev1.Group_Spec_Authorization{
					Policies: []string{policy.Metadata.Name},
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Name: utilrand.GetRandomStringCanonical(8),
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
										Effect: corev1.Policy_Spec_Rule_ALLOW,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, valid := range valids {
		_, err = srv.CreateGroup(ctx, valid)
		assert.Nil(t, err, "%+v", err)
	}
}
