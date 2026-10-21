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

package cellib

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/checker/decls"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMethodsListBoundaries(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	assert.Nil(t, err)
	for _, expr := range []string{
		`[3, 1, 2].min() == 1`, `[1u, 3u, 2u].max() == 3u`,
		`[1.5, 0.5, 2.5].min() == 0.5`, `[false, true].max()`,
		`["z", "a", "b"].min() == "a"`, `[b"a", b"z"].max() == b"z"`,
		`[duration("2s"), duration("1s")].min() == duration("1s")`,
		`[timestamp("2024-01-01T00:00:00Z"), timestamp("2025-01-01T00:00:00Z")].max() == timestamp("2025-01-01T00:00:00Z")`,
		`![1, 2].hasAny([])`, `[1, 2].hasAll([])`,
		`![1, 2].hasAny([3, 4])`, `![1, 2].hasAll([1, 3])`,
		`[1, 2].hasAll([1, 1])`, `["a", "a"].hasAny(["b", "a"])`,
	} {
		ast, iss := env.Compile(expr)
		assert.Nil(t, iss.Err(), expr)
		prg, err := env.Program(ast)
		assert.Nil(t, err)
		out, _, err := prg.Eval(map[string]any{})
		assert.Nil(t, err, expr)
		assert.Equal(t, true, out.Value(), expr)
	}
	for _, expr := range []string{"ctx.min()", "ctx.max()", "ctx.hasAny([1])", "ctx.hasAll([1])"} {
		ast, iss := env.Compile(expr)
		assert.Nil(t, iss.Err())
		prg, err := env.Program(ast)
		assert.Nil(t, err)
		_, _, err = prg.Eval(map[string]any{"ctx": "invalid"})
		assert.NotNil(t, err)
	}
	for _, op := range []string{"min", "max"} {
		ast, iss := env.Compile("ctx." + op + "()")
		assert.Nil(t, iss.Err())
		prg, err := env.Program(ast)
		assert.Nil(t, err)
		_, _, err = prg.Eval(map[string]any{"ctx": []int{}})
		assert.NotNil(t, err)
	}
	list := types.DefaultTypeAdapter.NativeToValue([]int{1})
	assert.True(t, types.IsError(methodListHasAny(types.IntOne, list)))
	assert.True(t, types.IsError(methodListHasAny(list, types.IntOne)))
	assert.True(t, types.IsError(methodListHasAll(types.IntOne, list)))
	assert.True(t, types.IsError(methodListHasAll(list, types.IntOne)))
	assert.True(t, types.IsError(methodListMin()(types.DefaultTypeAdapter.NativeToValue([]map[string]any{{}}))))
}

func TestMethodsList(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		env, err := cel.NewEnv(
			cel.Declarations(
				decls.NewVar("ctx", decls.Dyn),
				decls.NewVar("attrs", decls.Dyn),
			),
			CELLib(),
		)
		assert.Nil(t, err)

		{
			ast, iss := env.Compile(`ctx.arg.hasAll(["a", "b", "c"])`)
			assert.Nil(t, iss.Err())

			prg, err := env.Program(ast)
			assert.Nil(t, err)

			out, _, err := prg.ContextEval(ctx, map[string]any{
				"ctx": map[string]any{
					"arg": []string{"a", "b", "c", "d", "x"},
				},
			})
			assert.Nil(t, err)
			assert.True(t, out.Value().(bool))
		}

		{
			ast, iss := env.Compile(`ctx.arg.hasAny(["a", "b", "c"])`)
			assert.Nil(t, iss.Err())

			prg, err := env.Program(ast)
			assert.Nil(t, err)

			out, _, err := prg.ContextEval(ctx, map[string]any{
				"ctx": map[string]any{
					"arg": []string{"a", "b", "c", "d", "x"},
				},
			})
			assert.Nil(t, err)
			assert.True(t, out.Value().(bool))
		}

		{
			ast, iss := env.Compile(`ctx.arg.min() == 3`)
			assert.Nil(t, iss.Err())

			prg, err := env.Program(ast)
			assert.Nil(t, err)

			out, _, err := prg.ContextEval(ctx, map[string]any{
				"ctx": map[string]any{
					"arg": []int{3, 6, 4, 8},
				},
			})
			assert.Nil(t, err)
			assert.True(t, out.Value().(bool))
		}

		{
			ast, iss := env.Compile(`ctx.arg.max() == 11`)
			assert.Nil(t, iss.Err())

			prg, err := env.Program(ast)
			assert.Nil(t, err)

			out, _, err := prg.ContextEval(ctx, map[string]any{
				"ctx": map[string]any{
					"arg": []int{6, 11, 3, 9},
				},
			})
			assert.Nil(t, err)
			assert.True(t, out.Value().(bool))
		}

	}

}

func TestListMembershipValues(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	require.Nil(t, err)
	for _, tc := range []struct {
		name       string
		list, args any
		any, all   bool
	}{
		{"Empty", []int64{}, []int64{}, false, true},
		{"EmptyReceiver", []int64{}, []int64{1}, false, false},
		{"EmptyArgument", []int64{1}, []int64{}, false, true},
		{"Duplicates", []int64{1, 2}, []int64{1, 1}, true, true},
		{"SomeMatch", []int64{1, 2}, []int64{2, 3}, true, false},
		{"NoMatch", []int64{1, 2}, []int64{3, 4}, false, false},
		{"Uint", []uint64{1, math.MaxUint64}, []uint64{math.MaxUint64}, true, true},
		{"Double", []float64{1.5, -2.5}, []float64{-2.5, 1.5}, true, true},
		{"NaN", []float64{math.NaN()}, []float64{math.NaN()}, false, false},
		{"SignedZero", []float64{0}, []float64{math.Copysign(0, -1)}, true, true},
		{"Bool", []bool{true, false}, []bool{false}, true, true},
		{"String", []string{"a", "b"}, []string{"b", "c"}, true, false},
		{"Bytes", [][]byte{[]byte("a"), {0, 0xff}}, [][]byte{{0, 0xff}}, true, true},
		{"Duration", []time.Duration{time.Second, time.Minute}, []time.Duration{time.Minute}, true, true},
		{"Timestamp", []time.Time{time.Unix(1, 0).UTC()}, []time.Time{time.Unix(1, 0).In(time.FixedZone("zone", 3600))}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, method := range []string{"hasAny", "hasAll"} {
				ast, iss := env.Compile("ctx.list." + method + "(ctx.args)")
				require.Nil(t, iss.Err())
				prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
				require.Nil(t, err)
				out, _, err := prg.ContextEval(t.Context(), map[string]any{"ctx": map[string]any{"list": tc.list, "args": tc.args}})
				require.Nil(t, err)
				want := tc.any
				if method == "hasAll" {
					want = tc.all
				}
				assert.Equal(t, want, out.Value(), method)
			}
		})
	}
}

func TestListMembershipTypes(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	require.Nil(t, err)
	for _, method := range []string{"hasAny", "hasAll"} {
		for _, expr := range []string{
			`[1].` + method + `(["1"])`,
			`[1].` + method + `([1.0])`,
			`[{"value": 1}].` + method + `([{ "value": 1}])`,
			`[[1]].` + method + `([[1]])`,
			`[1].` + method + `({1: true})`,
		} {
			_, iss := env.Compile(expr)
			assert.NotNil(t, iss.Err(), expr)
		}
		ast, iss := env.Compile("ctx.list." + method + "(ctx.args)")
		require.Nil(t, iss.Err())
		prg, err := env.Program(ast)
		require.Nil(t, err)
		for _, input := range []map[string]any{
			{"list": "invalid", "args": []int64{}},
			{"list": []int64{}, "args": "invalid"},
			{"list": map[string]any{}, "args": []int64{}},
			{"list": []int64{}, "args": map[string]any{}},
			{"list": nil, "args": []int64{}},
			{"list": []int64{}, "args": nil},
			{"list": []any{int64(1), uint64(2)}, "args": []any{float64(1), int64(2)}},
			{"list": []any{int64(1), "a"}, "args": []any{true}},
		} {
			_, _, err := prg.Eval(map[string]any{"ctx": input})
			assert.NotNil(t, err, "%s: %+v", method, input)
		}
	}
}

func TestListMembershipExpressions(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	require.Nil(t, err)
	for _, expr := range []string{
		`[true].hasAll([[1].hasAny([1])])`,
		`[[1].hasAll([1])].hasAny([true])`,
		`[1, 2].map(item, [item].hasAny([item])).all(arg, arg)`,
		`[1, 2].all(arg, [arg].hasAll([arg]))`,
		`cel.bind(item, [1, 2], cel.bind(arg, [2], item.hasAny(arg) && item.hasAll(arg)))`,
		`ctx.list.hasAny(ctx.list.filter(item, [item].hasAll(ctx.args)))`,
		`ctx.list.hasAll([ctx.list.hasAny(ctx.args) ? 2 : 3])`,
		`ctx.list.hasAny(ctx.args) && ctx.list.hasAll(ctx.args)`,
	} {
		ast, iss := env.Compile(expr)
		require.Nil(t, iss.Err(), expr)
		prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		require.Nil(t, err)
		out, _, err := prg.ContextEval(t.Context(), map[string]any{"ctx": map[string]any{"list": []int64{1, 2}, "args": []int64{2}}})
		require.Nil(t, err, expr)
		assert.Equal(t, true, out.Value(), expr)
	}
}

func TestListMembershipCompatibility(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	require.Nil(t, err)
	options := []cel.EnvOption{cel.Variable("ctx", cel.DynType)}
	for _, typ := range comparableTypes {
		options = append(options,
			cel.Function("hasAny", cel.MemberOverload(fmt.Sprintf("lst_hasAny_%s", typ.typeName),
				[]*cel.Type{cel.ListType(typ.celType), cel.ListType(typ.celType)}, cel.BoolType, cel.BinaryBinding(methodListHasAny))),
			cel.Function("hasAll", cel.MemberOverload(fmt.Sprintf("lst_hasAll_%s", typ.typeName),
				[]*cel.Type{cel.ListType(typ.celType), cel.ListType(typ.celType)}, cel.BoolType, cel.BinaryBinding(methodListHasAll))),
		)
	}
	legacy, err := cel.NewEnv(options...)
	require.Nil(t, err)
	values := []ref.Val{types.IntOne, types.Uint(1), types.Double(1), types.Int(2), types.Uint(2), types.Double(2), types.String("a"), types.True,
		types.NullValue, types.NewErr("invalid value"), types.NewUnknown(1, nil)}
	for _, method := range []string{"hasAny", "hasAll"} {
		expr := "ctx.list." + method + "(ctx.args)"
		ast, iss := env.Compile(expr)
		require.Nil(t, iss.Err())
		prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		require.Nil(t, err)
		ast, iss = legacy.Compile(expr)
		require.Nil(t, iss.Err())
		before, err := legacy.Program(ast, cel.EvalOptions(cel.OptOptimize))
		require.Nil(t, err)
		for i, value := range values {
			for j, arg := range values {
				input := map[string]any{"ctx": map[string]any{
					"list": types.NewRefValList(types.DefaultTypeAdapter, []ref.Val{types.IntOne, value}),
					"args": types.NewRefValList(types.DefaultTypeAdapter, []ref.Val{types.Int(2), arg}),
				}}
				want, _, wantErr := before.Eval(input)
				out, _, err := prg.Eval(input)
				if wantErr != nil {
					assert.NotNil(t, err, "%s: %d/%d", method, i, j)
					continue
				}
				require.Nil(t, err, "%s: %d/%d", method, i, j)
				assert.Equal(t, want, out, "%s: %d/%d", method, i, j)
			}
		}
	}
}

func TestListMembershipArguments(t *testing.T) {
	for _, method := range []string{"hasAny", "hasAll"} {
		t.Run(method, func(t *testing.T) {
			for _, args := range [][]int64{{2}, {}} {
				var listCalls, argCalls int
				env, err := cel.NewEnv(CELLib(),
					cel.Function("source", cel.Overload("source", []*cel.Type{}, cel.ListType(cel.IntType),
						cel.FunctionBinding(func(...ref.Val) ref.Val {
							listCalls++
							return types.DefaultTypeAdapter.NativeToValue([]int64{1, 2})
						}))),
					cel.Function("arguments", cel.Overload("arguments", []*cel.Type{}, cel.ListType(cel.IntType),
						cel.FunctionBinding(func(...ref.Val) ref.Val {
							argCalls++
							return types.DefaultTypeAdapter.NativeToValue(args)
						}))),
				)
				require.Nil(t, err)
				ast, iss := env.Compile("source()." + method + "(arguments())")
				require.Nil(t, iss.Err())
				prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
				require.Nil(t, err)
				out, _, err := prg.ContextEval(t.Context(), map[string]any{})
				require.Nil(t, err)
				assert.Equal(t, len(args) > 0 || method == "hasAll", out.Value())
				assert.Equal(t, 1, listCalls)
				assert.Equal(t, 1, argCalls)
			}
		})
	}
}

func TestListMembershipShortCircuit(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	require.Nil(t, err)
	const size = 1200
	for _, method := range []string{"hasAny", "hasAll"} {
		t.Run(method, func(t *testing.T) {
			list, args := make([]int64, size), make([]int64, size)
			for i := range args {
				args[i] = 1
			}
			if method == "hasAny" {
				list[0] = 1
			}
			ast, iss := env.Compile("ctx.list." + method + "(ctx.args)")
			require.Nil(t, iss.Err())
			prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize), cel.CostLimit(20_000), cel.InterruptCheckFrequency(100))
			require.Nil(t, err)
			out, _, err := prg.ContextEval(t.Context(), map[string]any{"ctx": map[string]any{"list": list, "args": args}})
			require.Nil(t, err)
			assert.Equal(t, method == "hasAny", out.Value())
		})
	}
}

func TestListMembershipSharedCost(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	require.Nil(t, err)
	for _, method := range []string{"hasAny", "hasAll"} {
		t.Run(method, func(t *testing.T) {
			list, args := make([]int64, 20), make([]int64, 4)
			for i := range args {
				args[i] = 1
			}
			expr := "ctx.list." + method + "(ctx.args)"
			if method == "hasAll" {
				list[len(list)-1] = 1
			} else {
				expr = "!" + expr
			}
			input := map[string]any{"ctx": map[string]any{"list": list, "args": args}}
			ast, iss := env.Compile(expr)
			require.Nil(t, iss.Err())
			prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize), cel.CostLimit(math.MaxUint64))
			require.Nil(t, err)
			out, details, err := prg.ContextEval(t.Context(), input)
			require.Nil(t, err)
			assert.Equal(t, true, out.Value())
			require.NotNil(t, details.ActualCost())
			cost := *details.ActualCost()
			require.Positive(t, cost)
			ast, iss = env.Compile(expr + " && " + expr)
			require.Nil(t, iss.Err())
			prg, err = env.Program(ast, cel.EvalOptions(cel.OptOptimize), cel.CostLimit(cost+cost/2))
			require.Nil(t, err)
			_, _, err = prg.ContextEval(t.Context(), input)
			assert.ErrorContains(t, err, "cost limit")
		})
	}
}

func TestListMembershipCancellation(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	require.Nil(t, err)
	const size = 1200
	for _, method := range []string{"hasAny", "hasAll"} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			list, args := make([]int64, size), make([]int64, size)
			for i := range args {
				args[i] = 1
			}
			if method == "hasAll" {
				list[len(list)-1] = 1
			}
			var reads int
			value := &tstMembershipList{
				Lister: types.DefaultTypeAdapter.NativeToValue(list).(traits.Lister),
				visit: func() {
					reads++
					if reads == 128 {
						cancel()
					}
				},
			}
			ast, iss := env.Compile("ctx.list." + method + "(ctx.args)")
			require.Nil(t, iss.Err())
			prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize), cel.CostLimit(1_000_000), cel.InterruptCheckFrequency(100))
			require.Nil(t, err)
			_, _, err = prg.ContextEval(ctx, map[string]any{"ctx": map[string]any{"list": value, "args": args}})
			assert.ErrorIs(t, err, context.Canceled)
			assert.GreaterOrEqual(t, reads, 128)
			assert.Less(t, reads, 256)
		})
	}
}

type tstMembershipList struct {
	traits.Lister
	visit func()
}

func (l *tstMembershipList) Get(index ref.Val) ref.Val {
	l.visit()
	return l.Lister.Get(index)
}

func (l *tstMembershipList) Iterator() traits.Iterator {
	return &tstMembershipIterator{Iterator: l.Lister.Iterator(), visit: l.visit}
}

type tstMembershipIterator struct {
	traits.Iterator
	visit func()
}

func (it *tstMembershipIterator) Next() ref.Val {
	it.visit()
	return it.Iterator.Next()
}

func methodListHasAny(listVal ref.Val, listArgVal ref.Val) ref.Val {
	list, ok := listVal.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(list)
	}
	listArg, ok := listArgVal.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(list)
	}

	sz := listArg.Size().(types.Int)
	for i := types.Int(0); i < sz; i++ {
		if isInList(list, listArg.Get(types.Int(i))) {
			return types.Bool(true)
		}
	}
	return types.Bool(false)
}

func methodListHasAll(listVal ref.Val, listArgVal ref.Val) ref.Val {
	list, ok := listVal.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(list)
	}
	listArg, ok := listArgVal.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(list)
	}

	sz := listArg.Size().(types.Int)
	for i := types.Int(0); i < sz; i++ {
		if !isInList(list, listArg.Get(types.Int(i))) {
			return types.Bool(false)
		}
	}
	return types.Bool(true)
}

func isInList(list traits.Lister, item ref.Val) bool {

	sz := list.Size().(types.Int)
	for i := types.Int(0); i < sz; i++ {
		if list.Get(types.Int(i)).Equal(item) == types.True {
			return true
		}
	}
	return false
}
