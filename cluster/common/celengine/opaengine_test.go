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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
)

func TestOPAResultTypes(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)
	condition := "package octelium.condition\nmatch := input.ctx.value"
	expr := "package octelium.eval\nresult := input.ctx.value"
	assert.Nil(t, srv.AddPolicyOPA(ctx, condition))
	assert.Nil(t, srv.AddPolicyStringOPA(ctx, expr))
	assert.Nil(t, srv.AddPolicyMapAnyOPA(ctx, expr))

	for _, value := range []any{true, false, "value", 1, nil, []any{"value"}, map[string]any{"key": "value"}} {
		input := map[string]any{"ctx": map[string]any{"value": value}}
		res, err := srv.opaEngine.EvalPolicy(ctx, condition, input)
		if v, ok := value.(bool); ok {
			assert.Nil(t, err)
			assert.Equal(t, v, res)
		} else {
			assert.NotNil(t, err)
			assert.False(t, res)
		}
		str, err := srv.EvalPolicyStringOPA(ctx, expr, input)
		if v, ok := value.(string); ok {
			assert.Nil(t, err)
			assert.Equal(t, v, str)
		} else {
			assert.NotNil(t, err)
			assert.Empty(t, str)
		}
		obj, err := srv.OPAEvalPolicyMapStrAny(ctx, expr, input)
		if v, ok := value.(map[string]any); ok {
			assert.Nil(t, err)
			assert.Equal(t, v, obj)
		} else {
			assert.NotNil(t, err)
			assert.Nil(t, obj)
		}
	}

	res, err := srv.opaEngine.EvalPolicy(ctx, condition, nil)
	assert.Nil(t, err)
	assert.False(t, res)
	_, err = srv.EvalPolicyStringOPA(ctx, expr, nil)
	assert.ErrorIs(t, err, ErrOPAUndefined)
	_, err = srv.OPAEvalPolicyMapStrAny(ctx, expr, nil)
	assert.ErrorIs(t, err, ErrOPAUndefined)
	_, err = srv.EvalPolicyStringOPA(ctx, "invalid", nil)
	assert.NotNil(t, err)
	_, err = srv.OPAEvalPolicyMapStrAny(ctx, "invalid", nil)
	assert.NotNil(t, err)
}

func TestOPAPolicyLimits(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)
	for _, expr := range []string{"", "invalid", strings.Repeat(" ", 20001)} {
		assert.NotNil(t, srv.AddPolicyOPA(ctx, expr))
		assert.NotNil(t, srv.AddPolicyStringOPA(ctx, expr))
		assert.NotNil(t, srv.AddPolicyMapAnyOPA(ctx, expr))
		_, err := srv.opaEngine.EvalPolicy(ctx, expr, nil)
		assert.NotNil(t, err)
	}
	expr := "package octelium.condition\nmatch := true"
	assert.Nil(t, srv.AddPolicyOPA(ctx, expr+strings.Repeat(" ", 20000-len(expr))))

	ctx, cancel := context.WithCancel(ctx)
	cancel()
	res, err := srv.opaEngine.EvalPolicy(ctx, `package octelium.condition
match if {
	some i in numbers.range(1, 40000)
	some j in numbers.range(1, 40000)
	i * j == -1
}`, nil)
	assert.NotNil(t, err)
	assert.False(t, res)
}

func TestOPABuiltinErrors(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)
	for _, expr := range []string{
		`package octelium.condition
match if { 1 / input.ctx.zero == 1 }`,
		`package octelium.condition
match if { json.unmarshal(input.ctx.value) }`,
		`package octelium.condition
match if { regex.match("[", input.ctx.value) }`,
	} {
		res, err := srv.opaEngine.EvalPolicy(ctx, expr, map[string]any{
			"ctx": map[string]any{"zero": 0, "value": "invalid"},
		})
		assert.NotNil(t, err)
		assert.False(t, res)
	}
	for _, expr := range []string{
		`package octelium.condition
match if { net.lookup_ip_addr("example.com") }`,
		`package octelium.condition
match if { opa.runtime() }`,
		`package octelium.condition
match if { trace("value") }`,
	} {
		assert.NotNil(t, srv.AddPolicyOPA(ctx, expr))
	}
}

func TestConditionOPA(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	srv, err := New(ctx, &Opts{})
	assert.Nil(t, err)

	{
		i := &corev1.RequestContext{
			User: &corev1.User{
				Spec: &corev1.User_Spec{
					Type: corev1.User_Spec_HUMAN,
				},
			},
		}

		reqCtxMap, err := pbutils.ConvertToMap(i)
		assert.Nil(t, err)

		res, err := srv.EvalCondition(ctx, &corev1.Condition{
			Type: &corev1.Condition_Opa{
				Opa: &corev1.Condition_OPA{
					Type: &corev1.Condition_OPA_Inline{
						Inline: `
package octelium.condition

match if {
	input.ctx.user.spec.type == "HUMAN"
	input.attrs.attr1 == "val1"
}
						`,
					},
				},
			},
		}, map[string]any{
			"ctx": reqCtxMap,
			"attrs": map[string]any{
				"attr1": "val1",
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, res)
	}

	{
		i := &corev1.RequestContext{
			User: &corev1.User{
				Spec: &corev1.User_Spec{
					Type: corev1.User_Spec_HUMAN,
				},
			},
		}

		reqCtxMap, err := pbutils.ConvertToMap(i)
		assert.Nil(t, err)

		res, err := srv.EvalCondition(ctx, &corev1.Condition{
			Type: &corev1.Condition_Opa{
				Opa: &corev1.Condition_OPA{
					Type: &corev1.Condition_OPA_Inline{
						Inline: `
package octelium.condition

match if {
	input.ctx.user.spec.type == "WORKLOAD"
	input.attrs.attr1 == "val1"
}

match222 if {
	2 > 1
}
						`,
					},
				},
			},
		}, map[string]any{
			"ctx": reqCtxMap,
			"attrs": map[string]any{
				"attr1": "val1",
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.False(t, res)
	}
}

func TestDoEvaluatePolicy(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	e, err := newOPAEngine(ctx, nil)
	assert.Nil(t, err)

	usr := tests.GenUser(nil)
	res, err := e.doEvalPolicy(ctx, `
package octelium.eval

result := {
	"upstream": {
		"url": sprintf("https://%s.example.com", [input.ctx.user.metadata.name])
	}
}`, map[string]any{
		"ctx": map[string]any{
			"user": pbutils.MustConvertToMap(usr),
		},
	}, "eval", "result")
	assert.Nil(t, err, "%+v", err)

	cfg := &corev1.Service_Spec_Config{}

	cfgMap, ok := res.(map[string]any)
	assert.True(t, ok)

	err = pbutils.UnmarshalFromMap(cfgMap, cfg)
	assert.Nil(t, err)

	assert.Equal(t, fmt.Sprintf("https://%s.example.com", usr.Metadata.Name), cfg.Upstream.GetUrl())
}

func TestOPAQueryCache(t *testing.T) {
	ctx := context.Background()
	const script = `package octelium
condition := {"match": false, "alternate": true}
eval := {"match": "value", "result": {"parent": "default"}}
optional := {"result": input.ctx.missing}`
	cases := []struct {
		mod, qry string
		want     any
	}{
		{"condition", "match", false},
		{"condition", "alternate", true},
		{"eval", "match", "value"},
		{"eval", "result", map[string]any{"parent": "default"}},
		{"optional", "result", nil},
	}
	for _, order := range []string{"Forward", "Reverse"} {
		t.Run(order, func(t *testing.T) {
			e, err := newOPAEngine(ctx, nil)
			assert.Nil(t, err)
			var queries []*rego.PreparedEvalQuery
			for i := range cases {
				idx := i
				if order == "Reverse" {
					idx = len(cases) - 1 - i
				}
				tc := cases[idx]
				pq, err := e.getOrSetPQ(ctx, script, tc.mod, tc.qry)
				assert.Nil(t, err)
				for _, previous := range queries {
					assert.NotSame(t, previous, pq, "%s.%s", tc.mod, tc.qry)
				}
				queries = append(queries, pq)
				for range 2 {
					res, err := e.doEvalPolicy(ctx, script, nil, tc.mod, tc.qry)
					if tc.want == nil {
						assert.ErrorIs(t, err, ErrOPAUndefined)
					} else {
						assert.Nil(t, err)
					}
					assert.Equal(t, tc.want, res, "%s.%s", tc.mod, tc.qry)
					cached, err := e.getOrSetPQ(ctx, script, tc.mod, tc.qry)
					assert.Nil(t, err)
					assert.Same(t, pq, cached)
				}
			}
		})
	}
}

func TestOPAQueryCacheConcurrent(t *testing.T) {
	const script = `package octelium
condition := {"match": input.ctx.allowed}
eval := {"result": input.ctx.value}`
	condition := &corev1.Condition{Type: &corev1.Condition_Opa{Opa: &corev1.Condition_OPA{
		Type: &corev1.Condition_OPA_Inline{Inline: script},
	}}}
	for _, prime := range []string{"Cold", "Condition", "String", "Map"} {
		t.Run(prime, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			srv, err := New(ctx, nil)
			assert.Nil(t, err)
			switch prime {
			case "Condition":
				assert.Nil(t, srv.AddPolicyOPA(ctx, script))
			case "String":
				assert.Nil(t, srv.AddPolicyStringOPA(ctx, script))
			case "Map":
				assert.Nil(t, srv.AddPolicyMapAnyOPA(ctx, script))
			}
			var wg sync.WaitGroup
			for i := range 16 {
				wg.Go(func() {
					for j := range 16 {
						var value any
						switch j % 4 {
						case 0:
							value = map[string]any{"parent": fmt.Sprintf("config-%d-%d", i, j)}
						case 1:
							value = fmt.Sprintf("user-%d-%d", i, j)
						case 2:
							value = true
						case 3:
							value = false
						}
						allowed := (i+j)%3 == 0
						input := map[string]any{"ctx": map[string]any{"allowed": allowed, "value": value}}
						res, err := srv.EvalCondition(ctx, condition, input)
						assert.Nil(t, err)
						assert.Equal(t, allowed, res)
						str, err := srv.EvalPolicyStringOPA(ctx, script, input)
						if want, ok := value.(string); ok {
							assert.Nil(t, err)
							assert.Equal(t, want, str)
						} else {
							assert.NotNil(t, err)
							assert.Empty(t, str)
						}
						obj, err := srv.OPAEvalPolicyMapStrAny(ctx, script, input)
						if want, ok := value.(map[string]any); ok {
							assert.Nil(t, err)
							assert.Equal(t, want, obj)
						} else {
							assert.NotNil(t, err)
							assert.Nil(t, obj)
						}
					}
				})
			}
			wg.Wait()
		})
	}
}
