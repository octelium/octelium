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
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/open-policy-agent/opa/v1/ast"
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

func TestOPAInputCache(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)

	reqCtxMap := pbutils.MustConvertToMap(&corev1.RequestContext{
		User: &corev1.User{
			Metadata: &metav1.Metadata{Name: "usr-1", Uid: "uid-1"},
			Spec:     &corev1.User_Spec{Type: corev1.User_Spec_HUMAN},
		},
		Groups: []*corev1.Group{
			{Metadata: &metav1.Metadata{Name: "grp-1"}},
			{Metadata: &metav1.Metadata{Name: "grp-2"}},
		},
		Request: &corev1.RequestContext_Request{
			Type: &corev1.RequestContext_Request_Http{
				Http: &corev1.RequestContext_Request_HTTP{
					Method:  "GET",
					Path:    "/api/v1/items",
					Headers: map[string]string{"x-a": "1", "x-b": "2"},
				},
			},
		},
	})

	valuesMap := map[string]any{
		"str":     "value",
		"float":   1.5,
		"int":     3,
		"int64":   int64(1<<53 + 1),
		"uint32":  uint32(7),
		"big":     1e21,
		"neg0":    math.Copysign(0, -1),
		"nan":     math.NaN(),
		"inf":     math.Inf(-1),
		"number":  json.Number("12.50"),
		"bool":    true,
		"null":    nil,
		"nilMap":  map[string]any(nil),
		"nilList": []any(nil),
		"list":    []any{"a", 1.0, map[string]any{"k": "v"}},
		"strs":    []string{"a", "b"},
		"bytes":   []byte("bytes"),
		"time":    time.Date(2026, 11, 1, 10, 0, 0, 123456789, time.UTC),
		"struct": struct {
			Name string `json:"name"`
		}{Name: "struct"},
		"nested": map[string]any{"a": map[string]any{"b": []any{map[string]any{"c": "d"}}}},
	}

	attrs := map[string]any{"attr1": "val1"}

	inputs := []map[string]any{
		nil,
		{},
		{"ctx": reqCtxMap},
		{"ctx": reqCtxMap, "attrs": attrs},
		{"ctx": valuesMap},
		{"ctx": valuesMap, "attrs": map[string]any(nil)},
		{"ctx": map[string]any(nil)},
		{"ctx": "value", "list": []any{reqCtxMap}, "strs": []string{"a"}, "int": 1},
	}

	conditions := []*corev1.Condition{}
	for _, script := range []string{
		`match if { input.ctx.request.http.method == "GET" }`,
		`match if { startswith(input.ctx.request.http.path, "/api/v1") }`,
		`match if { input.attrs.attr1 == "val1" }`,
		`match if { "grp-2" in {g.metadata.name | some g in input.ctx.groups} }`,
		`match if { input.ctx.request.http.method == "POST" with input.ctx.request.http.method as "POST" }`,
		`match if { input == null }`,
		`match if { is_null(input.ctx.null) }`,
		`match if { input.ctx.big == 1000000000000000000000 }`,
		`match if { input.ctx.int64 == 9007199254740993 }`,
		`match if { count(input.ctx) > 3 }`,
		`match := input.ctx.bool`,
	} {
		conditions = append(conditions, &corev1.Condition{
			Type: &corev1.Condition_Opa{
				Opa: &corev1.Condition_OPA{
					Type: &corev1.Condition_OPA_Inline{
						Inline: "package octelium.condition\n" + script,
					},
				},
			},
		})
	}
	conditions = append(conditions, &corev1.Condition{
		Type: &corev1.Condition_All_{
			All: &corev1.Condition_All{
				Of: []*corev1.Condition{
					conditions[0],
					{Type: &corev1.Condition_Match{Match: `ctx.request.http.method == "GET"`}},
					{
						Type: &corev1.Condition_Any_{
							Any: &corev1.Condition_Any{
								Of: []*corev1.Condition{conditions[2], conditions[3]},
							},
						},
					},
				},
			},
		},
	})

	evals := []string{
		`result := input`,
		`result := json.marshal(input)`,
		`result := {k: type_name(v) | some k, v in input.ctx}`,
		`result := object.union(input.ctx, {"added": {"k": "v"}})`,
		`result := object.remove(input.ctx, ["str", "user"])`,
		`result := json.patch(input, [{"op": "add", "path": "/ctx/patched", "value": 1}])`,
		`result := json.remove(input, ["ctx/str", "ctx/user"])`,
		`result := json.filter(input, ["ctx/str", "ctx/request/http"])`,
		`result := r if { r := input with input.ctx.str as "changed" }`,
		`result := r if { r := input with input as {"ctx": {"replaced": true}} }`,
		`result := sprintf("%v", [input])`,
		`result := [k | some k, _ in input.ctx]`,
		`result := object.keys(input)`,
		`result := input.ctx.str`,
		`result := sprintf("%v %v %v %v %v", [input.ctx.big, input.ctx.neg0, input.ctx.float, input.ctx.nan, input.ctx.inf])`,
	}

	type evalResult struct {
		res any
		err string
	}

	doEval := func(ctx context.Context, input map[string]any) []evalResult {
		var ret []evalResult
		add := func(res any, err error) {
			r := evalResult{res: res}
			if err != nil {
				r.err = err.Error()
			}
			ret = append(ret, r)
		}
		for _, condition := range conditions {
			add(srv.EvalCondition(ctx, condition, input))
		}
		for _, script := range evals {
			script = "package octelium.eval\n" + script
			add(srv.EvalPolicyStringOPA(ctx, script, input))
			add(srv.OPAEvalPolicyMapStrAny(ctx, script, input))
		}
		return ret
	}

	for i, input := range inputs {
		want := doEval(ctx, input)
		assert.Equal(t, want, doEval(ctx, input), "input %d", i)

		cctx := WithOPAInputCache(ctx)
		c := cctx.Value(opaInputCacheCtxKey{}).(*opaInputCache)
		assert.Empty(t, c.vals)

		assert.Equal(t, want, doEval(cctx, input), "input %d", i)
		var cached []map[string]any
		for _, v := range input {
			if m, ok := v.(map[string]any); ok && m != nil {
				cached = append(cached, m)
			}
		}
		assert.Len(t, c.vals, len(cached), "input %d", i)

		vals := maps.Clone(c.vals)

		assert.Equal(t, want, doEval(cctx, input), "input %d", i)
		assert.Len(t, c.vals, len(vals), "input %d", i)
		for k, entry := range vals {
			assert.Same(t, entry, c.vals[k])
			assert.False(t, entry.inUse)
		}
		for _, m := range cached {
			entry, ok := c.vals[reflect.ValueOf(m).Pointer()]
			assert.True(t, ok)
			assert.Equal(t, reflect.ValueOf(m).Pointer(), reflect.ValueOf(entry.m).Pointer())
			fresh, err := toOPAValue(m)
			assert.Nil(t, err)
			assert.Equal(t, 0, entry.val.Compare(fresh), "input %d", i)
		}

		val, release, err := c.getInput(input)
		assert.Nil(t, err)
		for k, v := range input {
			if m, ok := v.(map[string]any); ok && m != nil {
				entry := c.vals[reflect.ValueOf(m).Pointer()]
				assert.True(t, entry.inUse)
				assert.Same(t, entry.val, val.(ast.Object).Get(ast.StringTerm(k)).Value)
			}
		}
		rs, err := rego.New(rego.Query("input"), rego.Input(input)).Eval(ctx)
		assert.Nil(t, err)
		parsed, err := rego.New(rego.Query("input"), rego.ParsedInput(val)).Eval(ctx)
		assert.Nil(t, err)
		assert.Equal(t, rs, parsed, "input %d", i)
		release()
		for _, entry := range c.vals {
			assert.False(t, entry.inUse)
		}
	}
}

func TestOPAInputCacheInUse(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)

	expr := "package octelium.eval\nresult := input.ctx.value"
	m := map[string]any{"value": "value"}
	input := map[string]any{"ctx": m}
	cctx := WithOPAInputCache(ctx)
	c := cctx.Value(opaInputCacheCtxKey{}).(*opaInputCache)

	val, release, err := c.getInput(input)
	assert.Nil(t, err)
	assert.Len(t, c.vals, 1)
	entry := c.vals[reflect.ValueOf(m).Pointer()]
	assert.True(t, entry.inUse)
	assert.Same(t, entry.val, val.(ast.Object).Get(ast.StringTerm("ctx")).Value)

	other, otherRelease, err := c.getInput(input)
	assert.Nil(t, err)
	otherVal := other.(ast.Object).Get(ast.StringTerm("ctx")).Value
	assert.NotSame(t, entry.val, otherVal)
	assert.Equal(t, 0, entry.val.Compare(otherVal))
	assert.Len(t, c.vals, 1)

	res, err := srv.EvalPolicyStringOPA(cctx, expr, input)
	assert.Nil(t, err)
	assert.Equal(t, "value", res)
	assert.True(t, entry.inUse)
	assert.Same(t, entry, c.vals[reflect.ValueOf(m).Pointer()])

	otherRelease()
	assert.True(t, entry.inUse)
	release()
	assert.False(t, entry.inUse)

	res, err = srv.EvalPolicyStringOPA(cctx, expr, input)
	assert.Nil(t, err)
	assert.Equal(t, "value", res)
	assert.False(t, entry.inUse)

	val, release, err = c.getInput(map[string]any{"ctx": m, "attrs": m})
	assert.Nil(t, err)
	ctxVal := val.(ast.Object).Get(ast.StringTerm("ctx")).Value
	attrsVal := val.(ast.Object).Get(ast.StringTerm("attrs")).Value
	assert.True(t, ctxVal == entry.val || attrsVal == entry.val)
	assert.False(t, ctxVal == entry.val && attrsVal == entry.val)
	assert.Equal(t, 0, ctxVal.Compare(attrsVal))
	assert.True(t, entry.inUse)
	release()
	assert.False(t, entry.inUse)

	for range 8 {
		_, _, err = c.getInput(map[string]any{"ctx": m, "attrs": map[string]any{"value": func() {}}})
		assert.NotNil(t, err)
		assert.False(t, entry.inUse)
		assert.Len(t, c.vals, 1)
	}

	val, release, err = c.getInput(nil)
	assert.Nil(t, err)
	assert.Equal(t, 0, val.Compare(ast.NullValue))
	release()
	assert.Len(t, c.vals, 1)
}

func TestOPAInputCacheMaps(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)

	expr := "package octelium.eval\nresult := sprintf(\"%s %s\", [input.ctx.value, object.get(input, [\"attrs\", \"value\"], \"\")])"
	first := map[string]any{"value": "first"}
	second := map[string]any{"value": "second"}
	equal := map[string]any{"value": "first"}
	attrs := map[string]any{"value": "attrs"}

	cctx := WithOPAInputCache(ctx)
	c := cctx.Value(opaInputCacheCtxKey{}).(*opaInputCache)

	for _, tc := range []struct {
		input map[string]any
		want  string
		len   int
	}{
		{map[string]any{"ctx": first}, "first ", 1},
		{map[string]any{"ctx": second}, "second ", 2},
		{map[string]any{"ctx": first}, "first ", 2},
		{map[string]any{"ctx": equal}, "first ", 3},
		{map[string]any{"ctx": first, "attrs": attrs}, "first attrs", 4},
		{map[string]any{"ctx": second, "attrs": attrs}, "second attrs", 4},
		{map[string]any{"ctx": attrs, "attrs": first}, "attrs first", 4},
	} {
		res, err := srv.EvalPolicyStringOPA(cctx, expr, tc.input)
		assert.Nil(t, err)
		assert.Equal(t, tc.want, res)
		assert.Len(t, c.vals, tc.len)
	}

	for _, m := range []map[string]any{first, second, equal, attrs} {
		entry, ok := c.vals[reflect.ValueOf(m).Pointer()]
		assert.True(t, ok)
		fresh, err := toOPAValue(m)
		assert.Nil(t, err)
		assert.Equal(t, 0, entry.val.Compare(fresh))
	}

	res, err := srv.EvalPolicyStringOPA(ctx, expr, map[string]any{"ctx": first})
	assert.Nil(t, err)
	assert.Equal(t, "first ", res)
	assert.Len(t, c.vals, 4)

	other := WithOPAInputCache(ctx)
	res, err = srv.EvalPolicyStringOPA(other, expr, map[string]any{"ctx": first})
	assert.Nil(t, err)
	assert.Equal(t, "first ", res)
	assert.Len(t, other.Value(opaInputCacheCtxKey{}).(*opaInputCache).vals, 1)
	assert.Len(t, c.vals, 4)
}

func TestOPAInputCacheErrors(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)

	expr := "package octelium.eval\nresult := input.ctx.str"
	for _, value := range []any{
		func() {},
		make(chan int),
		map[string]any{"nested": func() {}},
		[]any{"valid", make(chan int)},
	} {
		input := map[string]any{
			"ctx":   map[string]any{"str": "value", "value": value},
			"attrs": map[string]any{"value": "valid"},
		}
		_, wantErr := srv.EvalPolicyStringOPA(ctx, expr, input)
		assert.NotNil(t, wantErr)
		_, wantCondErr := srv.opaEngine.EvalPolicy(ctx, "package octelium.condition\nmatch := true", input)
		assert.NotNil(t, wantCondErr)

		cctx := WithOPAInputCache(ctx)
		c := cctx.Value(opaInputCacheCtxKey{}).(*opaInputCache)
		for range 2 {
			res, err := srv.EvalPolicyStringOPA(cctx, expr, input)
			assert.NotNil(t, err)
			if err != nil {
				assert.Equal(t, wantErr.Error(), err.Error())
			}
			assert.Empty(t, res)
			ok, err := srv.opaEngine.EvalPolicy(cctx, "package octelium.condition\nmatch := true", input)
			assert.NotNil(t, err)
			if err != nil {
				assert.Equal(t, wantCondErr.Error(), err.Error())
			}
			assert.False(t, ok)
			_, ok = c.vals[reflect.ValueOf(input["ctx"]).Pointer()]
			assert.False(t, ok)
		}

		_, wantErr = srv.EvalPolicyStringOPA(ctx, "invalid", input)
		assert.NotNil(t, wantErr)
		other := WithOPAInputCache(ctx)
		_, err := srv.EvalPolicyStringOPA(other, "invalid", input)
		assert.NotNil(t, err)
		if err != nil {
			assert.Equal(t, wantErr.Error(), err.Error())
		}
		assert.Empty(t, other.Value(opaInputCacheCtxKey{}).(*opaInputCache).vals)
	}
}

func TestOPAInputCacheContext(t *testing.T) {
	ctx := context.Background()
	assert.Nil(t, ctx.Value(opaInputCacheCtxKey{}))

	cctx := WithOPAInputCache(ctx)
	c, ok := cctx.Value(opaInputCacheCtxKey{}).(*opaInputCache)
	assert.True(t, ok)
	assert.True(t, WithOPAInputCache(cctx) == cctx)

	tctx, cancel := context.WithTimeout(cctx, time.Minute)
	defer cancel()
	assert.True(t, WithOPAInputCache(tctx) == tctx)
	assert.Same(t, c, tctx.Value(opaInputCacheCtxKey{}))

	assert.NotSame(t, c, WithOPAInputCache(ctx).Value(opaInputCacheCtxKey{}))

	input := map[string]any{"ctx": map[string]any{"value": "value"}}
	opt, release, err := getOPAEvalInput(ctx, input)
	assert.Nil(t, err)
	evalCtx := &rego.EvalContext{}
	opt(evalCtx)
	assert.Equal(t, any(input), *evalCtx.RawInput())
	assert.Nil(t, evalCtx.ParsedInput())
	release()

	opt, release, err = getOPAEvalInput(tctx, input)
	assert.Nil(t, err)
	evalCtx = &rego.EvalContext{}
	opt(evalCtx)
	assert.Nil(t, evalCtx.RawInput())
	val, err := toOPAValue(input)
	assert.Nil(t, err)
	assert.Equal(t, 0, evalCtx.ParsedInput().Compare(val))
	assert.Len(t, c.vals, 1)
	for _, entry := range c.vals {
		assert.True(t, entry.inUse)
	}
	release()
	for _, entry := range c.vals {
		assert.False(t, entry.inUse)
	}
}

func TestOPAInputCacheConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)

	const script = `package octelium
condition := {"match": input.ctx.allowed == input.own.allowed}
eval := {"result": {"shared": input.ctx.value, "own": input.own.value, "with": x, "keys": object.keys(input.ctx)}} if {
	x := input.ctx.value with input.ctx.value as "changed"
}`
	condition := &corev1.Condition{Type: &corev1.Condition_Opa{Opa: &corev1.Condition_OPA{
		Type: &corev1.Condition_OPA_Inline{Inline: script},
	}}}

	shared := map[string]any{
		"allowed": true,
		"value":   "shared",
		"nested":  map[string]any{"a": "b", "c": []any{"d", "e"}},
	}
	keys := []any{"allowed", "nested", "value"}

	cctx := WithOPAInputCache(ctx)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for j := range 16 {
				own := map[string]any{
					"allowed": (i+j)%2 == 0,
					"value":   fmt.Sprintf("own-%d-%d", i, j),
				}
				input := map[string]any{"ctx": shared, "own": own}
				res, err := srv.EvalCondition(cctx, condition, input)
				assert.Nil(t, err)
				assert.Equal(t, own["allowed"], res)
				obj, err := srv.OPAEvalPolicyMapStrAny(cctx, script, input)
				assert.Nil(t, err)
				assert.Equal(t, map[string]any{
					"shared": "shared",
					"own":    own["value"],
					"with":   "changed",
					"keys":   keys,
				}, obj)
			}
		})
	}
	wg.Wait()

	c := cctx.Value(opaInputCacheCtxKey{}).(*opaInputCache)
	assert.Len(t, c.vals, 1+16*16)
	for _, entry := range c.vals {
		assert.False(t, entry.inUse)
	}
	fresh, err := toOPAValue(shared)
	assert.Nil(t, err)
	assert.Equal(t, 0, c.vals[reflect.ValueOf(shared).Pointer()].val.Compare(fresh))
}
