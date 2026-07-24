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
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func genMatchAnyCondition() *corev1.Condition {
	return &corev1.Condition{
		Type: &corev1.Condition_MatchAny{
			MatchAny: true,
		},
	}
}

func genNestedAllCondition(depth int) *corev1.Condition {
	c := genMatchAnyCondition()
	for i := 0; i < depth; i++ {
		c = &corev1.Condition{
			Type: &corev1.Condition_All_{
				All: &corev1.Condition_All{
					Of: []*corev1.Condition{c},
				},
			},
		}
	}
	return c
}

func genPolicyWithCondition(name string, cond *corev1.Condition) *corev1.Policy {
	return &corev1.Policy{
		Metadata: &metav1.Metadata{Name: name},
		Spec: &corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Condition: cond,
					Effect:    corev1.Policy_Spec_Rule_ALLOW,
				},
			},
		},
	}
}

func TestPolicy(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	p1, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)

	_, err = srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-2.pol-2"}, Spec: &corev1.Policy_Spec{}})
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsInvalidArg(err))

	p2, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)
	assert.Equal(t, p2.Status.ParentPolicyRef.Uid, p1.Metadata.Uid)

	p3, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-3.pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)
	assert.Equal(t, p3.Status.ParentPolicyRef.Uid, p2.Metadata.Uid)

	p4, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-4.pol-3.pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)

	p5, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-5.pol-4.pol-3.pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)

	p6, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-6.pol-5.pol-4.pol-3.pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)

	_, err = srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-7.pol-6.pol-5.pol-4.pol-3.pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsInvalidArg(err))

	_, err = srv.DeletePolicy(ctx, &metav1.DeleteOptions{
		Name: p6.Metadata.Name,
	})
	assert.Nil(t, err)

	_, err = srv.DeletePolicy(ctx, &metav1.DeleteOptions{
		Name: p4.Metadata.Name,
	})
	assert.NotNil(t, err)

	_, err = srv.DeletePolicy(ctx, &metav1.DeleteOptions{
		Name: p5.Metadata.Name,
	})
	assert.Nil(t, err)

	_, err = srv.DeletePolicy(ctx, &metav1.DeleteOptions{
		Name: p4.Metadata.Name,
	})
	assert.Nil(t, err)
}

func TestValidatePolicy(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	invalids := []*corev1.Policy{
		{},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		},
		{
			Spec: &corev1.Policy_Spec{},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					{
						Condition: genMatchAnyCondition(),
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					{
						Condition: genMatchAnyCondition(),
						Effect:    corev1.Policy_Spec_Rule_ALLOW,
						Priority:  priorityMaxVal + 1,
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					{
						Condition: genMatchAnyCondition(),
						Effect:    corev1.Policy_Spec_Rule_ALLOW,
						Priority:  -1*priorityMaxVal - 1,
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					{
						Effect: corev1.Policy_Spec_Rule_ALLOW,
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
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
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					{
						Condition: &corev1.Condition{
							Type: &corev1.Condition_Match{
								Match: "",
							},
						},
						Effect: corev1.Policy_Spec_Rule_ALLOW,
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					{
						Condition: &corev1.Condition{
							Type: &corev1.Condition_All_{
								All: &corev1.Condition_All{},
							},
						},
						Effect: corev1.Policy_Spec_Rule_ALLOW,
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Policy_Spec{
				EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{
					{
						Condition: genMatchAnyCondition(),
					},
				},
			},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Policy_Spec{
				EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{
					{
						Effect: corev1.Policy_Spec_EnforcementRule_ENFORCE,
					},
				},
			},
		},
	}

	for _, invalid := range invalids {
		_, err = srv.CreatePolicy(ctx, invalid)
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		var rules []*corev1.Policy_Spec_Rule
		for i := 0; i < maxPolicyRules+1; i++ {
			rules = append(rules, &corev1.Policy_Spec_Rule{
				Condition: genMatchAnyCondition(),
				Effect:    corev1.Policy_Spec_Rule_ALLOW,
			})
		}
		_, err = srv.CreatePolicy(ctx, &corev1.Policy{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Policy_Spec{
				Rules: rules,
			},
		})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	valids := []*corev1.Policy{
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec:     &corev1.Policy_Spec{},
		},
		{
			Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					{
						Name:      utilrand.GetRandomStringCanonical(8),
						Condition: genMatchAnyCondition(),
						Effect:    corev1.Policy_Spec_Rule_ALLOW,
						Priority:  priorityMaxVal,
					},
					{
						Condition: genMatchAnyCondition(),
						Effect:    corev1.Policy_Spec_Rule_DENY,
						Priority:  -1 * priorityMaxVal,
					},
				},
				EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{
					{
						Condition: genMatchAnyCondition(),
						Effect:    corev1.Policy_Spec_EnforcementRule_ENFORCE,
					},
					{
						Condition: genMatchAnyCondition(),
						Effect:    corev1.Policy_Spec_EnforcementRule_IGNORE,
					},
				},
			},
		},
	}

	for _, valid := range valids {
		_, err = srv.CreatePolicy(ctx, valid)
		assert.Nil(t, err, "%+v", err)
	}
}

func TestPolicyConditionDepth(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	{
		_, err = srv.CreatePolicy(ctx, genPolicyWithCondition(
			utilrand.GetRandomStringCanonical(8), genNestedAllCondition(maxConditionDepth)))
		assert.Nil(t, err, "%+v", err)
	}

	{
		_, err = srv.CreatePolicy(ctx, genPolicyWithCondition(
			utilrand.GetRandomStringCanonical(8), genNestedAllCondition(maxConditionDepth+1)))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}

	{
		_, err = srv.CreatePolicy(ctx, genPolicyWithCondition(
			utilrand.GetRandomStringCanonical(8), genNestedAllCondition(maxConditionDepth*4)))
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", err)
	}
}

func newCondMatch(arg string) *corev1.Condition {
	return &corev1.Condition{
		Type: &corev1.Condition_Match{Match: arg},
	}
}

func newCondList(n int) []*corev1.Condition {
	var ret []*corev1.Condition
	for i := 0; i < n; i++ {
		ret = append(ret, &corev1.Condition{
			Type: &corev1.Condition_MatchAny{MatchAny: true},
		})
	}
	return ret
}

func TestConditionTypes(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	invalids := []*corev1.Condition{
		nil,
		{},
		newCondMatch(""),
		newCondMatch("   "),
		newCondMatch("!!!!"),
		newCondMatch(strings.Repeat("a", maxCELExpressionLen+1)),
		{
			Type: &corev1.Condition_Not{Not: ""},
		},
		{
			Type: &corev1.Condition_Not{Not: "!!!!"},
		},
		{
			Type: &corev1.Condition_All_{
				All: &corev1.Condition_All{},
			},
		},
		{
			Type: &corev1.Condition_Any_{
				Any: &corev1.Condition_Any{},
			},
		},
		{
			Type: &corev1.Condition_None_{
				None: &corev1.Condition_None{},
			},
		},
		{
			Type: &corev1.Condition_All_{
				All: &corev1.Condition_All{
					Of: newCondList(maxConditionChildren + 1),
				},
			},
		},
		{
			Type: &corev1.Condition_Any_{
				Any: &corev1.Condition_Any{
					Of: newCondList(maxConditionChildren + 1),
				},
			},
		},
		{
			Type: &corev1.Condition_None_{
				None: &corev1.Condition_None{
					Of: newCondList(maxConditionChildren + 1),
				},
			},
		},
		{
			Type: &corev1.Condition_All_{
				All: &corev1.Condition_All{
					Of: []*corev1.Condition{nil},
				},
			},
		},
		{
			Type: &corev1.Condition_Any_{
				Any: &corev1.Condition_Any{
					Of: []*corev1.Condition{
						newCondMatch("true"),
						newCondMatch("!!!!"),
					},
				},
			},
		},
		{
			Type: &corev1.Condition_Opa{
				Opa: &corev1.Condition_OPA{},
			},
		},
		{
			Type: &corev1.Condition_Opa{
				Opa: &corev1.Condition_OPA{
					Type: &corev1.Condition_OPA_Inline{Inline: ""},
				},
			},
		},
		{
			Type: &corev1.Condition_Opa{
				Opa: &corev1.Condition_OPA{
					Type: &corev1.Condition_OPA_Inline{Inline: "   "},
				},
			},
		},
		{
			Type: &corev1.Condition_Opa{
				Opa: &corev1.Condition_OPA{
					Type: &corev1.Condition_OPA_Inline{Inline: "!!!!"},
				},
			},
		},
		{
			Type: &corev1.Condition_Opa{
				Opa: &corev1.Condition_OPA{
					Type: &corev1.Condition_OPA_Inline{
						Inline: strings.Repeat("a", maxOPAScriptLen+1),
					},
				},
			},
		},
	}

	for _, cond := range invalids {
		err := srv.validateCondition(ctx, cond)
		assert.NotNil(t, err, "%+v", cond)
	}

	valids := []*corev1.Condition{
		{
			Type: &corev1.Condition_MatchAny{MatchAny: true},
		},
		newCondMatch("true"),
		{
			Type: &corev1.Condition_Not{Not: "true"},
		},
		{
			Type: &corev1.Condition_All_{
				All: &corev1.Condition_All{
					Of: []*corev1.Condition{
						newCondMatch("true"),
						{Type: &corev1.Condition_MatchAny{MatchAny: true}},
					},
				},
			},
		},
		{
			Type: &corev1.Condition_Any_{
				Any: &corev1.Condition_Any{
					Of: newCondList(maxConditionChildren),
				},
			},
		},
		{
			Type: &corev1.Condition_None_{
				None: &corev1.Condition_None{
					Of: []*corev1.Condition{
						newCondMatch("true"),
					},
				},
			},
		},
		{
			Type: &corev1.Condition_All_{
				All: &corev1.Condition_All{
					Of: []*corev1.Condition{
						{
							Type: &corev1.Condition_Any_{
								Any: &corev1.Condition_Any{
									Of: []*corev1.Condition{
										{
											Type: &corev1.Condition_None_{
												None: &corev1.Condition_None{
													Of: []*corev1.Condition{
														newCondMatch("true"),
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
			},
		},
	}

	for _, cond := range valids {
		err := srv.validateCondition(ctx, cond)
		assert.Nil(t, err, "%+v", err)
	}
}

func TestConditionMixedNestingDepth(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	wrap := func(depth int) *corev1.Condition {
		c := newCondMatch("true")
		for i := 0; i < depth; i++ {
			switch i % 3 {
			case 0:
				c = &corev1.Condition{
					Type: &corev1.Condition_All_{
						All: &corev1.Condition_All{Of: []*corev1.Condition{c}},
					},
				}
			case 1:
				c = &corev1.Condition{
					Type: &corev1.Condition_Any_{
						Any: &corev1.Condition_Any{Of: []*corev1.Condition{c}},
					},
				}
			default:
				c = &corev1.Condition{
					Type: &corev1.Condition_None_{
						None: &corev1.Condition_None{Of: []*corev1.Condition{c}},
					},
				}
			}
		}
		return c
	}

	{
		err := srv.validateCondition(ctx, wrap(maxConditionDepth))
		assert.Nil(t, err, "%+v", err)
	}

	{
		err := srv.validateCondition(ctx, wrap(maxConditionDepth+1))
		assert.NotNil(t, err)
	}

	{
		err := srv.validateCondition(ctx, wrap(maxConditionDepth*8))
		assert.NotNil(t, err)
	}
}
