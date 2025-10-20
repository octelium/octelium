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

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
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
