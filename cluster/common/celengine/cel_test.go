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

package celengine

import (
	"context"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestCondition(t *testing.T) {

	ctx := context.Background()
	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	srv, err := New(ctx, &Opts{})
	assert.Nil(t, err)

	{
		i := &corev1.RequestContext{}

		reqCtxMap, err := pbutils.ConvertToMap(i)
		assert.Nil(t, err)

		res, err := srv.isConditionMatchedAll(ctx, nil, reqCtxMap)
		assert.Nil(t, err, "%+v", err)
		assert.False(t, res)

		res, err = srv.isConditionMatchedAll(ctx, &corev1.Condition_All{}, reqCtxMap)
		assert.Nil(t, err, "%+v", err)
		assert.False(t, res)

		res, err = srv.isConditionMatchedAny(ctx, nil, reqCtxMap)
		assert.Nil(t, err, "%+v", err)
		assert.False(t, res)

		res, err = srv.isConditionMatchedAny(ctx, &corev1.Condition_Any{}, reqCtxMap)
		assert.Nil(t, err, "%+v", err)
		assert.False(t, res)

		{
			res, err = srv.isConditionMatchedAll(ctx, &corev1.Condition_All{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)

			res, err = srv.isConditionMatchedAll(ctx, &corev1.Condition_All{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "true",
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)

			res, err = srv.isConditionMatchedAll(ctx, &corev1.Condition_All{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)

			res, err = srv.isConditionMatchedAll(ctx, &corev1.Condition_All{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					{
						Type: &corev1.Condition_Not{
							Not: "2 > 3",
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)

			res, err = srv.isConditionMatchedAll(ctx, &corev1.Condition_All{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
					{
						Type: &corev1.Condition_Any_{
							Any: &corev1.Condition_Any{
								Of: []*corev1.Condition{
									{
										Type: &corev1.Condition_Match{
											Match: "2 > 1",
										},
									},
									{
										Type: &corev1.Condition_Match{
											Match: "3 < 2",
										},
									},
								},
							},
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)

			res, err = srv.isConditionMatchedAll(ctx, &corev1.Condition_All{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
					{
						Type: &corev1.Condition_Any_{
							Any: &corev1.Condition_Any{
								Of: []*corev1.Condition{
									{
										Type: &corev1.Condition_Match{
											Match: "2 < 1",
										},
									},
									{
										Type: &corev1.Condition_Match{
											Match: "3 < 2",
										},
									},
								},
							},
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.False(t, res)

			res, err = srv.isConditionMatchedAll(ctx, &corev1.Condition_All{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
					{
						Type: &corev1.Condition_All_{
							All: &corev1.Condition_All{
								Of: []*corev1.Condition{
									{
										Type: &corev1.Condition_Match{
											Match: "2 > 1",
										},
									},
									{
										Type: &corev1.Condition_Match{
											Match: "3 > 2",
										},
									},
								},
							},
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)

			res, err = srv.isConditionMatchedAll(ctx, &corev1.Condition_All{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
					{
						Type: &corev1.Condition_Not{
							Not: "2 < 1",
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)

			res, err = srv.isConditionMatchedAll(ctx, &corev1.Condition_All{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
					{},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.False(t, res)

			res, err = srv.isConditionMatchedAll(ctx, &corev1.Condition_All{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					{
						Type: &corev1.Condition_Match{
							Match: "3 < 2",
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.False(t, res)
		}

		{
			res, err = srv.isConditionMatchedAny(ctx, &corev1.Condition_Any{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)

			res, err = srv.isConditionMatchedAny(ctx, &corev1.Condition_Any{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					{
						Type: &corev1.Condition_Match{
							Match: "3 < 2",
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)

			res, err = srv.isConditionMatchedAny(ctx, &corev1.Condition_Any{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Any_{
							Any: &corev1.Condition_Any{
								Of: []*corev1.Condition{
									{
										Type: &corev1.Condition_Match{
											Match: "2 > 1",
										},
									},
									{
										Type: &corev1.Condition_Match{
											Match: "3 < 2",
										},
									},
								},
							},
						},
					},
					{
						Type: &corev1.Condition_Any_{
							Any: &corev1.Condition_Any{
								Of: []*corev1.Condition{
									{
										Type: &corev1.Condition_Match{
											Match: "4 > 1",
										},
									},
									{
										Type: &corev1.Condition_Match{
											Match: "5 < 2",
										},
									},
								},
							},
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)

			res, err = srv.isConditionMatchedAny(ctx, &corev1.Condition_Any{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					{
						Type: &corev1.Condition_Match{
							Match: "3 > 2",
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)
		}

		{
			res, err = srv.isConditionMatchedNone(ctx, &corev1.Condition_None{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 < 1",
						},
					},
					{
						Type: &corev1.Condition_Match{
							Match: "3 < 2",
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)
		}

		{
			res, err = srv.isConditionMatchedNone(ctx, &corev1.Condition_None{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 < 1",
						},
					},
					{
						Type: &corev1.Condition_All_{
							All: &corev1.Condition_All{
								Of: []*corev1.Condition{
									{
										Type: &corev1.Condition_Match{
											Match: "2 < 1",
										},
									},
									{
										Type: &corev1.Condition_Match{
											Match: "2 > 1",
										},
									},
								},
							},
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)
		}

		{
			res, err = srv.isConditionMatchedNone(ctx, &corev1.Condition_None{
				Of: []*corev1.Condition{
					{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					{
						Type: &corev1.Condition_Match{
							Match: "3 < 2",
						},
					},
				},
			}, reqCtxMap)
			assert.Nil(t, err, "%+v", err)
			assert.False(t, res)
		}

		{
			res, err = srv.isConditionNotMatched(ctx, reqCtxMap, "2 > 1")
			assert.Nil(t, err, "%+v", err)
			assert.False(t, res)
		}

		{
			res, err = srv.isConditionNotMatched(ctx, reqCtxMap, "2 < 1")
			assert.Nil(t, err, "%+v", err)
			assert.True(t, res)
		}
	}

	{
		i := &corev1.RequestContext{
			User:    tests.GenUser([]string{"g1", "g2"}),
			Service: tests.GenService("net1"),
		}

		reqCtxMap, err := pbutils.ConvertToMap(i)
		assert.Nil(t, err)

		res, err := srv.isConditionMatchedAll(ctx, &corev1.Condition_All{
			Of: []*corev1.Condition{
				{
					Type: &corev1.Condition_Match{
						Match: fmt.Sprintf(`ctx.user.metadata.name == "%s"`, i.User.Metadata.Name),
					},
				},
				{
					Type: &corev1.Condition_Match{
						Match: `"g1" in ctx.user.spec.groups`,
					},
				},
				{
					Type: &corev1.Condition_Match{
						Match: fmt.Sprintf(`ctx.service.metadata.name == "%s"`, i.Service.Metadata.Name),
					},
				},
			},
		}, map[string]any{
			"ctx": reqCtxMap,
		})

		assert.Nil(t, err, "%+v", err)
		assert.True(t, res)

	}

}

func TestEvalPolicyString(t *testing.T) {

	ctx := context.Background()
	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	srv, err := New(ctx, &Opts{})
	assert.Nil(t, err)

	userUID := vutils.UUIDv4()
	userName := utilrand.GetRandomString(12)
	res, err := srv.EvalPolicyString(ctx, `ctx.userUID + ctx.userName`, map[string]any{
		"ctx": map[string]any{
			"userUID":  userUID,
			"userName": userName,
		},
	})
	assert.Nil(t, err)
	assert.Equal(t, res, userUID+userName)
}

func TestEvalPolicy(t *testing.T) {

	ctx := context.Background()
	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	srv, err := New(ctx, &Opts{})
	assert.Nil(t, err)

	userUID := vutils.UUIDv4()
	userName := utilrand.GetRandomString(12)
	{
		res, err := srv.EvalPolicy(ctx,
			fmt.Sprintf(`ctx.userUID + ctx.userName == "%s%s"`, userUID, userName),
			map[string]any{
				"ctx": map[string]any{
					"userUID":  userUID,
					"userName": userName,
				},
			})
		assert.Nil(t, err)
		assert.True(t, res)
	}

	{
		res, err := srv.EvalPolicy(ctx,
			fmt.Sprintf(`ctx.userUID + ctx.userName + "invalid" == "%s%s"`, userUID, userName),
			map[string]any{
				"ctx": map[string]any{
					"userUID":  userUID,
					"userName": userName,
				},
			})
		assert.Nil(t, err)
		assert.False(t, res)
	}
}
