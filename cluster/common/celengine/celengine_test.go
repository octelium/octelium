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
	"strings"
	"sync"
	"testing"
	"time"

	"cel.dev/cel-go/common/types"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvalPolicyAny(t *testing.T) {

	ctx := context.Background()
	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	srv, err := New(ctx, &Opts{})
	assert.Nil(t, err)

	reqCtx := &corev1.RequestContext{
		User: tests.GenUser(nil),
	}

	res, err := srv.EvalPolicyMapStrAny(ctx,
		`{"upstream": {"url": "https://" + ctx.user.metadata.name + ".example.com"}}`, map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		})
	assert.Nil(t, err)

	cfg := &corev1.Service_Spec_Config{}

	err = pbutils.UnmarshalFromMap(res, cfg)
	assert.Nil(t, err)

	assert.Equal(t, fmt.Sprintf("https://%s.example.com", reqCtx.User.Metadata.Name), cfg.Upstream.GetUrl())
}

func TestCELPolicyTypes(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)

	for _, tc := range []struct {
		expr string
		bool bool
		str  bool
	}{
		{"true", true, false},
		{`"value"`, false, true},
		{"42", false, false},
		{`{"key": "value"}`, false, false},
		{"ctx.value", true, true},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			assert.Nil(t, srv.AddPolicyMapAny(ctx, tc.expr))
			assert.Equal(t, tc.bool, srv.AddPolicy(ctx, tc.expr) == nil)
			assert.Equal(t, tc.str, srv.AddPolicyString(ctx, tc.expr) == nil)
			assert.Equal(t, tc.bool, srv.AddPolicy(ctx, tc.expr) == nil)
		})
	}

	for _, value := range []any{true, false, "value", int64(1), nil, []string{"value"}} {
		input := map[string]any{"ctx": map[string]any{"value": value}}
		res, err := srv.EvalPolicy(ctx, "ctx.value", input)
		if v, ok := value.(bool); ok {
			assert.Nil(t, err)
			assert.Equal(t, v, res)
		} else {
			assert.NotNil(t, err)
			assert.False(t, res)
		}
		str, err := srv.EvalPolicyString(ctx, "ctx.value", input)
		if v, ok := value.(string); ok {
			assert.Nil(t, err)
			assert.Equal(t, v, str)
		} else {
			assert.NotNil(t, err)
			assert.Empty(t, str)
		}
	}

	for _, expr := range []string{"", "(", "unknownVariable", strings.Repeat(" ", 10001)} {
		assert.NotNil(t, srv.AddPolicy(ctx, expr))
		assert.NotNil(t, srv.AddPolicyString(ctx, expr))
		assert.NotNil(t, srv.AddPolicyMapAny(ctx, expr))
		_, err := srv.EvalPolicyMapStrAny(ctx, expr, nil)
		assert.NotNil(t, err)
	}
	assert.Nil(t, srv.AddPolicy(ctx, "true"+strings.Repeat(" ", 9996)))
}

func TestCELMissingInput(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)

	for _, expr := range []string{
		"ctx.user.name == 'alice'",
		"ctx.values[0] == 'alice'",
		"ctx.values[-1] == 'alice'",
		"ctx.absent.field == 'alice'",
	} {
		res, err := srv.EvalPolicy(ctx, expr, map[string]any{
			"ctx": map[string]any{"values": []string{}, "absent": nil},
		})
		assert.Nil(t, err, expr)
		assert.False(t, res, expr)
	}

	for _, expr := range []string{"1 / ctx.zero == 1", `ctx.value.matches("[")`, "ctx.value + 1 == 2"} {
		res, err := srv.EvalPolicy(ctx, expr, map[string]any{
			"ctx": map[string]any{"zero": int64(0), "value": "value"},
		})
		assert.NotNil(t, err, expr)
		assert.False(t, res, expr)
	}

	_, err = srv.EvalPolicyString(ctx, "ctx.missing", map[string]any{"ctx": map[string]any{}})
	assert.NotNil(t, err)
	_, err = srv.EvalPolicyMapStrAny(ctx, "ctx.missing", map[string]any{"ctx": map[string]any{}})
	assert.NotNil(t, err)
}

func TestCELMissingInputErrors(t *testing.T) {
	ctx := context.Background()
	assert.False(t, isCELMissingInputErr(ctx, nil))
	for _, msg := range []string{
		"no such key: user", "no such field: user", "undefined field: user",
		"unknown field: user", "no such attribute: user", "no such attribute(s): user",
		"null field selection", "null select", "null attribute",
		"index out of bounds", "index out of range",
	} {
		assert.True(t, isCELMissingInputErr(ctx, fmt.Errorf("%s", msg)), msg)
		assert.True(t, isCELMissingInputErr(nil, fmt.Errorf("%s", msg)), msg)
	}
	for _, err := range []error{
		context.Canceled, context.DeadlineExceeded,
		fmt.Errorf("cost limit exceeded: no such key"),
		fmt.Errorf("operation cancelled: no such field"),
		fmt.Errorf("operation canceled: no such field"),
		fmt.Errorf("interrupted: no such key"),
		fmt.Errorf("division by zero"),
	} {
		assert.False(t, isCELMissingInputErr(ctx, err), err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	assert.False(t, isCELMissingInputErr(ctx, fmt.Errorf("no such key")))
}

func TestCELResultConversion(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)

	res, err := srv.EvalPolicyMapStrAny(ctx, `{
		"str": "value", "int": -1, "uint": 2u, "float": 1.5,
		"bool": true, "bytes": b"abc", "null": null,
		"list": [1, {"nested": [false, null, "value"]}],
		"emptyMap": {}, "emptyList": [],
		"timestamp": timestamp("2025-01-01T00:00:00Z"), "duration": duration("1s")
	}`, nil)
	assert.Nil(t, err)
	assert.Equal(t, map[string]any{
		"str": "value", "int": int64(-1), "uint": uint64(2), "float": 1.5,
		"bool": true, "bytes": []byte("abc"), "null": nil,
		"list":     []any{int64(1), map[string]any{"nested": []any{false, nil, "value"}}},
		"emptyMap": map[string]any{}, "emptyList": []any{},
		"timestamp": time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), "duration": time.Second,
	}, res)
	assert.Nil(t, convertCelToGo(nil))
	assert.Equal(t, int64(1), convertCelToGo(types.IntOne))

	for _, expr := range []string{"true", `"value"`, "[1, 2]", "null"} {
		res, err := srv.EvalPolicyMapStrAny(ctx, expr, nil)
		assert.NotNil(t, err)
		assert.Nil(t, res)
	}
}

func TestCELJSONMarshal(t *testing.T) {
	ctx := t.Context()
	srv, err := New(ctx, nil)
	require.Nil(t, err)
	const expr = `json.marshal({"user": ctx.user, "items": ctx.items, "enabled": ctx.enabled, "empty": {}, "null": null})`
	const match = `json.parse(` + expr + `).user == ctx.user && json.parse(` + expr + `).enabled == ctx.enabled`
	require.Nil(t, srv.AddPolicyString(ctx, expr))
	require.Nil(t, srv.AddPolicy(ctx, match))
	for i := range 8 {
		t.Run(fmt.Sprintf("User%d", i), func(t *testing.T) {
			t.Parallel()
			for j := range 16 {
				value := map[string]any{
					"user":    fmt.Sprintf("user-%d-%d\"\\\n", i, j),
					"items":   []any{map[string]any{"index": int64(j)}, nil, []string{"one", "two"}},
					"enabled": i%2 == 0,
					"empty":   map[string]any{}, "null": nil,
				}
				want, err := json.Marshal(value)
				require.Nil(t, err)
				input := map[string]any{"ctx": value}
				out, err := srv.EvalPolicyString(t.Context(), expr, input)
				require.Nil(t, err)
				assert.Equal(t, string(want), out)
				matched, err := srv.EvalPolicy(t.Context(), match, input)
				require.Nil(t, err)
				assert.True(t, matched)
				obj, err := srv.EvalPolicyMapStrAny(t.Context(), `{"body": `+expr+`}`, input)
				require.Nil(t, err)
				assert.Equal(t, map[string]any{"body": string(want)}, obj)
			}
		})
	}
}

func TestCELJSONMarshalErrors(t *testing.T) {
	srv, err := New(t.Context(), nil)
	require.Nil(t, err)
	for _, expr := range []string{
		`json.marshal({"nested": {true: "value"}})`,
		`json.marshal({"nested": {1: "number", "1": "string"}})`,
	} {
		out, err := srv.EvalPolicyString(t.Context(), expr, nil)
		assert.ErrorContains(t, err, "Could not marshal json")
		assert.Empty(t, out)
		matched, err := srv.EvalPolicy(t.Context(), expr+` != "{}"`, nil)
		assert.ErrorContains(t, err, "Could not marshal json")
		assert.False(t, matched)
		obj, err := srv.EvalPolicyMapStrAny(t.Context(), `{"body": `+expr+`}`, nil)
		assert.ErrorContains(t, err, "Could not marshal json")
		assert.Nil(t, obj)
	}
}

func TestCELPolicyLimits(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)
	values := make([]int64, 2000)
	expr := "ctx.values.map(x, ctx.values.map(y, x + y)).size() > 0"
	input := map[string]any{"ctx": map[string]any{"values": values}}
	res, err := srv.EvalPolicy(ctx, expr, input)
	assert.ErrorContains(t, err, "cost limit")
	assert.False(t, res)

	ctx, cancel := context.WithCancel(ctx)
	cancel()
	res, err = srv.EvalPolicy(ctx, expr, input)
	assert.NotNil(t, err)
	assert.False(t, res)

	res, err = srv.EvalPolicy(context.Background(), "true", nil)
	assert.Nil(t, err)
	assert.True(t, res)
}

func TestPolicyConcurrent(t *testing.T) {
	ctx := context.Background()
	srv, err := New(ctx, nil)
	assert.Nil(t, err)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for j := range 16 {
				value := fmt.Sprintf("user-%d-%d", i, j)
				input := map[string]any{"ctx": map[string]any{"value": value, "allow": i%2 == 0}}
				res, err := srv.EvalPolicy(ctx, "ctx.allow", input)
				assert.Nil(t, err)
				assert.Equal(t, i%2 == 0, res)
				str, err := srv.EvalPolicyString(ctx, "ctx.value", input)
				assert.Nil(t, err)
				assert.Equal(t, value, str)
				obj, err := srv.EvalPolicyMapStrAny(ctx, `{"value": ctx.value}`, input)
				assert.Nil(t, err)
				assert.Equal(t, map[string]any{"value": value}, obj)
				str, err = srv.EvalPolicyStringOPA(ctx, "package octelium.eval\nresult := input.ctx.value", input)
				assert.Nil(t, err)
				assert.Equal(t, value, str)
				obj, err = srv.OPAEvalPolicyMapStrAny(ctx, `package octelium.eval
result := {"value": input.ctx.value}`, input)
				assert.Nil(t, err)
				assert.Equal(t, map[string]any{"value": value}, obj)
			}
		})
	}
	wg.Wait()
}

func TestCELListPolicyLimits(t *testing.T) {
	ctx := t.Context()
	srv, err := New(ctx, nil)
	require.Nil(t, err)
	const size = 1200
	for _, method := range []string{"hasAny", "hasAll"} {
		t.Run(method, func(t *testing.T) {
			list, args := make([]int64, size), make([]int64, size)
			for i := range args {
				args[i] = 1
			}
			if method == "hasAll" {
				list[len(list)-1] = 1
			}
			input := map[string]any{"ctx": map[string]any{"list": list, "args": args}}
			expr := "ctx.list." + method + "(ctx.args)"
			require.Nil(t, srv.AddPolicy(ctx, expr))
			res, err := srv.EvalPolicy(ctx, expr, input)
			assert.ErrorContains(t, err, "cost limit")
			assert.False(t, res)

			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			res, err = srv.EvalPolicy(cancelled, expr, input)
			assert.ErrorIs(t, err, context.Canceled)
			assert.False(t, res)

			input["ctx"] = map[string]any{"list": []int64{1, 2}, "args": []int64{2}}
			res, err = srv.EvalPolicy(ctx, expr, input)
			assert.Nil(t, err)
			assert.True(t, res)
		})
	}
}

func TestCELListResultLimits(t *testing.T) {
	ctx := t.Context()
	srv, err := New(ctx, nil)
	require.Nil(t, err)
	const size = 1200
	for _, method := range []string{"hasAny", "hasAll"} {
		t.Run(method, func(t *testing.T) {
			list, args := make([]int64, size), make([]int64, size)
			for i := range args {
				args[i] = 1
			}
			if method == "hasAll" {
				list[len(list)-1] = 1
			}
			input := map[string]any{"ctx": map[string]any{"list": list, "args": args}}
			expr := "ctx.list." + method + "(ctx.args)"
			for _, tc := range []struct {
				name string
				eval func(context.Context) error
			}{
				{"String", func(ctx context.Context) error {
					_, err := srv.EvalPolicyString(ctx, expr+` ? "allow" : "deny"`, input)
					return err
				}},
				{"Map", func(ctx context.Context) error {
					_, err := srv.EvalPolicyMapStrAny(ctx, `{"match": `+expr+`}`, input)
					return err
				}},
				{"Match", func(ctx context.Context) error {
					res, err := srv.EvalCondition(ctx, &corev1.Condition{Type: &corev1.Condition_Match{Match: expr}}, input)
					assert.False(t, res)
					return err
				}},
				{"Not", func(ctx context.Context) error {
					res, err := srv.EvalCondition(ctx, &corev1.Condition{Type: &corev1.Condition_Not{Not: expr}}, input)
					assert.False(t, res)
					return err
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					assert.ErrorContains(t, tc.eval(ctx), "cost limit")
					cancelled, cancel := context.WithCancel(ctx)
					cancel()
					assert.ErrorIs(t, tc.eval(cancelled), context.Canceled)
				})
			}
		})
	}
}

func TestCELListConcurrentLimits(t *testing.T) {
	ctx := t.Context()
	srv, err := New(ctx, nil)
	require.Nil(t, err)
	const size = 1200
	for _, method := range []string{"hasAny", "hasAll"} {
		list, args := make([]int64, size), make([]int64, size)
		for i := range args {
			args[i] = 1
		}
		if method == "hasAll" {
			list[len(list)-1] = 1
		}
		large := map[string]any{"ctx": map[string]any{"list": list, "args": args}}
		small := map[string]any{"ctx": map[string]any{"list": []int64{1, 2}, "args": []int64{2}}}
		expr := "ctx.list." + method + "(ctx.args)"
		require.Nil(t, srv.AddPolicy(ctx, expr))
		for worker := range 4 {
			t.Run(fmt.Sprintf("%s/%d", method, worker), func(t *testing.T) {
				t.Parallel()
				if worker%2 == 0 {
					res, err := srv.EvalPolicy(ctx, expr, large)
					assert.ErrorContains(t, err, "cost limit")
					assert.False(t, res)
				}
				for range 8 {
					res, err := srv.EvalPolicy(ctx, expr, small)
					assert.Nil(t, err)
					assert.True(t, res)
				}
			})
		}
	}
}
