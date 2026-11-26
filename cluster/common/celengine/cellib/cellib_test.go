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
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/checker/decls"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCELLib(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewVar("ctx", decls.Dyn),
			decls.NewVar("attrs", decls.Dyn),
		),
		CELLib(),
	)
	assert.Nil(t, err)

	{

		ast, iss := env.Compile("now() > timestamp(ctx.time)")
		assert.Nil(t, iss.Err())

		prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		assert.Nil(t, err)

		out, _, err := prg.ContextEval(ctx, map[string]any{
			"ctx": map[string]any{
				"time": time.Now().Add(-1 * time.Minute).Format(time.RFC3339Nano),
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
		ast, iss := env.Compile(`json.parse(ctx.arg)["k1"] == "v1"`)
		assert.Nil(t, iss.Err())

		prg, err := env.Program(ast)
		assert.Nil(t, err)

		out, _, err := prg.ContextEval(ctx, map[string]any{
			"ctx": map[string]any{
				"arg": `{"k1": "v1", "k2": "v2"}`,
			},
		})
		assert.Nil(t, err)
		assert.True(t, out.Value().(bool))
	}

}

func TestCELLibExtensions(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.ListType(cel.IntType)), CELLib())
	require.Nil(t, err)

	for _, tc := range []struct {
		expr string
		want any
	}{
		{`"%s-%.2f".format(["a", 1.5])`, "a-1.50"},
		{`["a", "b"].join("-")`, "a-b"},
		{`"abc".reverse()`, "cba"},
		{`strings.quote("a\nb")`, `"a\nb"`},
		{`math.sqrt(4.0)`, 2.0},
		{`math.least([3, 1, 2])`, int64(1)},
		{`math.bitAnd(12, 10)`, int64(8)},
		{`cel.bind(x, 2, x * x)`, int64(4)},
		{`base64.encode(b"hello")`, "aGVsbG8="},
		{`string(base64.decode("aGVsbG8"))`, "hello"},
		{`json.encode({"b": 1, "a": 2})`, `{"a":2,"b":1}`},
		{`json.parse("{\"a\": 1}").a`, 1.0},
	} {
		ast, iss := env.Compile(tc.expr)
		require.Nil(t, iss.Err(), tc.expr)
		prg, err := env.Program(ast)
		require.Nil(t, err)
		out, _, err := prg.Eval(map[string]any{})
		assert.Nil(t, err, tc.expr)
		assert.Equal(t, tc.want, out.Value(), tc.expr)
	}

	for _, expr := range []string{
		`base64.encodeUrl(b"hello")`,
		`base64.decodeUrl("aGVsbG8")`,
		`yaml.encode({"a": 1})`,
		`yaml.parse("a: 1")`,
		`json.parse("1", int)`,
		`"%.101f".format([1.0])`,
	} {
		_, iss := env.Compile(expr)
		assert.NotNil(t, iss.Err(), expr)
	}

	assert.Contains(t, env.Functions(), "cel.@block")

	ast, iss := env.Compile("math.least(ctx)")
	require.Nil(t, iss.Err())
	prg, err := env.Program(ast, cel.CostLimit(1_000_000))
	require.Nil(t, err)
	out, det, err := prg.Eval(map[string]any{"ctx": make([]int64, 1000)})
	require.Nil(t, err)
	assert.Equal(t, int64(0), out.Value())
	assert.Equal(t, uint64(1002), *det.ActualCost())
}
