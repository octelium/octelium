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
	"encoding/json"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/checker/decls"
	"cel.dev/cel-go/common/types"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
)

func TestFunctionInputErrors(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	assert.Nil(t, err)
	for _, tc := range []struct {
		expr string
		arg  any
	}{
		{"json.parse(ctx)", ""},
		{"json.parse(ctx)", "{"},
		{"json.parse(ctx)", "[1,2]"},
		{"json.parse(ctx)", "1"},
		{"json.parse(ctx)", "{\"key\": NaN}"},
		{"json.parse(ctx)", true},
		{"net.isPrivateIP(ctx)", "invalid"},
		{"net.isPrivateIP(ctx)", ""},
		{`net.isIPInRange(ctx, "10.0.0.0/8")`, "invalid"},
		{`net.isIPInRange("10.0.0.1", ctx)`, "invalid"},
		{`net.isIPInRange("10.0.0.1", ctx)`, "10.0.0.0/33"},
		{`time.isWeekdayInTZ(timestamp("2025-01-01T00:00:00Z"), ctx)`, "Invalid/Timezone"},
		{`time.isWeekendInTZ(timestamp("2025-01-01T00:00:00Z"), ctx)`, "Invalid/Timezone"},
		{"time.isWeekday(ctx)", "invalid"},
		{"time.isWeekend(ctx)", "invalid"},
	} {
		ast, iss := env.Compile(tc.expr)
		assert.Nil(t, iss.Err(), tc.expr)
		prg, err := env.Program(ast)
		assert.Nil(t, err)
		_, _, err = prg.ContextEval(context.Background(), map[string]any{"ctx": tc.arg})
		assert.NotNil(t, err, "%s: %+v", tc.expr, tc.arg)
	}
}

func TestFunctionNetworkBoundaries(t *testing.T) {
	env, err := cel.NewEnv(CELLib())
	assert.Nil(t, err)
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{`net.isIP("")`, false},
		{`net.isIP("127.0.0.1:80")`, false},
		{`net.isIP("fe80::1%eth0")`, false},
		{`net.isIPv4("192.168.001.1")`, false},
		{`net.isIPv6("::ffff:192.168.1.1")`, true},
		{`net.isPrivateIP("::ffff:10.0.0.1")`, true},
		{`net.isPrivateIP("fd00::1")`, true},
		{`net.isPrivateIP("127.0.0.1")`, false},
		{`net.isIPInRange("10.0.0.0", "10.0.0.0/24")`, true},
		{`net.isIPInRange("10.0.0.255", "10.0.0.0/24")`, true},
		{`net.isIPInRange("10.0.1.0", "10.0.0.0/24")`, false},
		{`net.isIPInRange("::ffff:10.0.0.1", "10.0.0.0/24")`, true},
		{`net.isIPInRange("2001:db8::1", "2001:db8::/32")`, true},
		{`net.isIPInRange("2001:db9::1", "2001:db8::/32")`, false},
		{`net.isIPInRange("10.0.0.1", "::/0")`, false},
	} {
		ast, iss := env.Compile(tc.expr)
		assert.Nil(t, iss.Err())
		prg, err := env.Program(ast)
		assert.Nil(t, err)
		out, _, err := prg.Eval(map[string]any{})
		assert.Nil(t, err, tc.expr)
		assert.Equal(t, tc.want, out.Value(), tc.expr)
	}
}

func TestFunctionTimeHelpers(t *testing.T) {
	for _, zone := range []string{"", "UTC", "America/New_York"} {
		loc, err := getTZLocation(types.String(zone))
		assert.Nil(t, err)
		assert.NotNil(t, loc)
	}
	_, err := getTZLocation(types.Int(1))
	assert.NotNil(t, err)
	_, err = getTZLocation(types.String("Invalid/Timezone"))
	assert.NotNil(t, err)
	_, err = toTime(types.String("2025-01-01"))
	assert.NotNil(t, err)
	now := time.Now()
	res, err := toTime(types.Timestamp{Time: now})
	assert.Nil(t, err)
	assert.Equal(t, now, res)
}

func TestFunctionJSON(t *testing.T) {

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
			ast, iss := env.Compile(`json.parse(ctx.arg)["k1"] == "v1"`)
			assert.Nil(t, iss.Err())

			prg, err := env.Program(ast)
			assert.Nil(t, err)

			out, _, err := prg.ContextEval(ctx, map[string]any{
				"ctx": map[string]any{
					"arg": `{"k1": "v1"}`,
				},
			})
			assert.Nil(t, err)
			assert.True(t, out.Value().(bool))
		}

		{
			ast, iss := env.Compile(`json.marshal(json.parse(ctx.arg))`)
			assert.Nil(t, iss.Err())

			prg, err := env.Program(ast)
			assert.Nil(t, err)

			out, _, err := prg.ContextEval(ctx, map[string]any{
				"ctx": map[string]any{
					"arg": `{"k1": "v1"}`,
				},
			})
			assert.Nil(t, err)

			outStr, ok := out.Value().(string)
			assert.True(t, ok)
			res := make(map[string]any)
			err = json.Unmarshal([]byte(outStr), &res)
			assert.Nil(t, err)

			v1, ok := res["k1"]
			assert.True(t, ok)
			assert.Equal(t, "v1", v1)
		}

	}

}

func TestFunctionNet(t *testing.T) {
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

	cases := []struct {
		expr string
		want bool
	}{
		{`net.isIP("192.168.1.1")`, true},
		{`net.isIP("not-an-ip")`, false},
		{`net.isIPv4("10.0.0.1")`, true},
		{`net.isIPv4("2001:db8::1")`, false},
		{`net.isIPv6("2001:db8::1")`, true},
		{`net.isIPv6("192.168.1.1")`, false},
		{`net.isPrivateIP("10.5.0.1")`, true},
		{`net.isPrivateIP("8.8.8.8")`, false},
		{`net.isIPInRange("192.168.1.50", "192.168.1.0/24")`, true},
		{`net.isIPInRange("10.0.0.1", "192.168.1.0/24")`, false},
	}

	for _, tc := range cases {
		ast, iss := env.Compile(tc.expr)
		assert.Nil(t, iss.Err())

		prg, err := env.Program(ast)
		assert.Nil(t, err)

		out, _, err := prg.ContextEval(ctx, map[string]any{})
		assert.Nil(t, err)

		res, ok := out.Value().(bool)
		assert.True(t, ok)
		assert.Equal(t, tc.want, res)
	}
}

func TestFunctionTime(t *testing.T) {
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

	cases := []struct {
		expr string
		want bool
	}{
		{`time.isWeekday(timestamp("2023-10-18T12:00:00Z"))`, true},
		{`time.isWeekend(timestamp("2023-10-18T12:00:00Z"))`, false},

		{`time.isWeekday(timestamp("2023-10-21T12:00:00Z"))`, false},
		{`time.isWeekend(timestamp("2023-10-21T12:00:00Z"))`, true},

		{`time.isWeekdayInTZ(timestamp("2023-10-20T23:00:00Z"), "Asia/Tokyo")`, false},
		{`time.isWeekendInTZ(timestamp("2023-10-20T23:00:00Z"), "Asia/Tokyo")`, true},

		{`time.isWeekdayInTZ(timestamp("2023-10-22T23:00:00Z"), "Asia/Tokyo")`, true},
		{`time.isWeekendInTZ(timestamp("2023-10-22T23:00:00Z"), "Asia/Tokyo")`, false},
	}

	for _, tc := range cases {

		ast, iss := env.Compile(tc.expr)
		assert.Nil(t, iss.Err())

		prg, err := env.Program(ast)
		assert.Nil(t, err)

		out, _, err := prg.ContextEval(ctx, map[string]any{})
		assert.Nil(t, err)

		res, ok := out.Value().(bool)
		assert.True(t, ok)
		assert.Equal(t, tc.want, res)
	}
}
