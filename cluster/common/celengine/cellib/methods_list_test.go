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
	"testing"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/checker/decls"
	"cel.dev/cel-go/common/types"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
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
