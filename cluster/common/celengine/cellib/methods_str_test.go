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

func TestMethodsStrBoundaries(t *testing.T) {
	assert.Equal(t, types.String("héllo"), strToLower(types.String("HÉLLO")))
	assert.Equal(t, types.String("HÉLLO"), strToUpper(types.String("héllo")))
	assert.Equal(t, types.String(""), strToLower(types.String("")))
	assert.True(t, types.IsError(strToLower(types.IntOne)))
	assert.True(t, types.IsError(strToUpper(types.IntOne)))
	assert.True(t, types.IsError(strSplit(types.IntOne, types.String(","))))
	assert.True(t, types.IsError(strSplit(types.String("value"), types.IntOne)))
	assert.Equal(t, types.True, types.DefaultTypeAdapter.NativeToValue([]string{"a", "", "b"}).Equal(strSplit(types.String("a,,b"), types.String(","))))
	assert.Equal(t, types.True, strMatches(types.String("value"), types.String("^val")))
	assert.Equal(t, types.False, strMatches(types.String("value"), types.String("^other")))
	assert.True(t, types.IsError(strMatches(types.String("value"), types.String("["))))
	assert.True(t, types.IsError(strMatches(types.IntOne, types.String(".*"))))
	assert.True(t, types.IsError(strMatches(types.String("value"), types.IntOne)))
}

func TestMethodsStr(t *testing.T) {

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
			ast, iss := env.Compile(`ctx.arg.toLower() == "some_value"`)
			assert.Nil(t, iss.Err())

			prg, err := env.Program(ast)
			assert.Nil(t, err)

			out, _, err := prg.ContextEval(ctx, map[string]any{
				"ctx": map[string]any{
					"arg": "Some_Value",
				},
			})
			assert.Nil(t, err)
			assert.True(t, out.Value().(bool))
		}

		{
			ast, iss := env.Compile(`ctx.arg.toUpper() == "SOME_VALUE"`)
			assert.Nil(t, iss.Err())

			prg, err := env.Program(ast)
			assert.Nil(t, err)

			out, _, err := prg.ContextEval(ctx, map[string]any{
				"ctx": map[string]any{
					"arg": "Some_Value",
				},
			})
			assert.Nil(t, err)
			assert.True(t, out.Value().(bool))
		}

		{
			ast, iss := env.Compile(`ctx.arg.split("_")[0] == "some"`)
			assert.Nil(t, iss.Err())

			prg, err := env.Program(ast)
			assert.Nil(t, err)

			out, _, err := prg.ContextEval(ctx, map[string]any{
				"ctx": map[string]any{
					"arg": "some_value",
				},
			})
			assert.Nil(t, err)
			assert.True(t, out.Value().(bool))
		}

		{
			ast, iss := env.Compile(`ctx.arg.matches("^[a-z]{5}$")`)
			assert.Nil(t, iss.Err())

			prg, err := env.Program(ast)
			assert.Nil(t, err)

			out, _, err := prg.ContextEval(ctx, map[string]any{
				"ctx": map[string]any{
					"arg": "cairo",
				},
			})
			assert.Nil(t, err)
			assert.True(t, out.Value().(bool))
		}
	}

}
