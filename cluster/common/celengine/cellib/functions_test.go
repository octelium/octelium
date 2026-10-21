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
	"math"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/checker/decls"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestFunctionJSONMarshalLiterals(t *testing.T) {
	env, err := cel.NewEnv(CELLib())
	require.Nil(t, err)
	for _, tc := range []struct {
		expr string
		want string
	}{
		{`{"value": "test"}`, `{"value":"test"}`},
		{`{"nested": {"items": [{"enabled": true}, null, [1, 2u, 3.5]]}}`, `{"nested":{"items":[{"enabled":true},null,[1,2,3.5]]}}`},
		{`[{"value": "test"}, {}, []]`, `[{"value":"test"},{},[]]`},
		{`[1, 2].map(x, {"value": x})`, `[{"value":1},{"value":2}]`},
		{`[{"value": 1}] + [{"value": 2}]`, `[{"value":1},{"value":2}]`},
		{`{"": "", "unicode": "日本語", "quote": "\"\\\n"}`, `{"":"","quote":"\"\\\n","unicode":"日本語"}`},
		{`{"min": -9223372036854775808, "max": 9223372036854775807, "uint": 18446744073709551615u}`, `{"max":9223372036854775807,"min":-9223372036854775808,"uint":18446744073709551615}`},
		{`{1: "one", -2: "two"}`, `{"-2":"two","1":"one"}`},
		{`{18446744073709551615u: "max"}`, `{"18446744073709551615":"max"}`},
		{`{"bytes": b"abc", "time": timestamp("2025-01-01T00:00:00Z"), "duration": duration("1s")}`, `{"bytes":"YWJj","duration":1000000000,"time":"2025-01-01T00:00:00Z"}`},
		{`{}`, `{}`},
		{`[]`, `[]`},
		{`null`, `null`},
		{`true`, `true`},
		{`false`, `false`},
		{`"value"`, `"value"`},
		{`-1`, `-1`},
		{`18446744073709551615u`, `18446744073709551615`},
		{`1.5`, `1.5`},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			ast, iss := env.Compile("json.marshal(" + tc.expr + ")")
			require.Nil(t, iss.Err())
			for _, opt := range []cel.EvalOption{0, cel.OptOptimize} {
				prg, err := env.Program(ast, cel.EvalOptions(opt))
				require.Nil(t, err)
				out, _, err := prg.ContextEval(t.Context(), map[string]any{})
				require.Nil(t, err)
				assert.Equal(t, tc.want, out.Value())
			}
		})
	}
}

func TestFunctionJSONMarshalValues(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	require.Nil(t, err)
	ast, iss := env.Compile("json.marshal(ctx)")
	require.Nil(t, iss.Err())
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	require.Nil(t, err)
	for _, value := range []any{
		map[string]any{"nested": []any{map[string]any{"value": true}, nil}},
		[]any{map[string]any{"value": "test"}, false, nil},
		map[int64]string{-1: "negative", math.MaxInt64: "max"},
		map[uint64]string{math.MaxUint64: "max"},
		map[string]any{}, []any{},
		map[string]any(nil), []any(nil),
		[2]any{map[string]any{"value": "test"}, nil},
		[]byte("abc"), []byte(nil),
		int64(math.MinInt64), int64(math.MaxInt64), uint64(math.MaxUint64),
		true, false, "value", 1.5, nil,
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), time.Second,
	} {
		want, err := json.Marshal(value)
		require.Nil(t, err)
		out, _, err := prg.ContextEval(t.Context(), map[string]any{"ctx": value})
		require.Nil(t, err, "%T: %+v", value, value)
		assert.Equal(t, string(want), out.Value(), "%T: %+v", value, value)
	}
	for _, value := range []any{
		map[string]ref.Val{"value": types.NewRefValMap(types.DefaultTypeAdapter, map[ref.Val]ref.Val{types.String("nested"): types.NullValue})},
		map[string]any{"value": map[ref.Val]ref.Val{types.String("nested"): types.NullValue}},
	} {
		out, _, err := prg.ContextEval(t.Context(), map[string]any{"ctx": value})
		require.Nil(t, err)
		assert.Equal(t, `{"value":{"nested":null}}`, out.Value())
	}
}

func TestFunctionJSONMarshalErrors(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	require.Nil(t, err)
	for _, expr := range []string{
		`json.marshal({true: "value"})`,
		`json.marshal({"nested": [{false: "value"}]})`,
		`json.marshal({1: "number", "1": "string"})`,
		`json.marshal({"nested": {1: "number", "1": "string"}})`,
		`json.marshal(ctx)`,
		`json.marshal({"nested": [ctx]})`,
		`json.marshal(ctx) == "{}"`,
	} {
		ast, iss := env.Compile(expr)
		require.Nil(t, iss.Err())
		prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		require.Nil(t, err)
		for _, value := range []any{
			math.NaN(), math.Inf(1), math.Inf(-1),
			map[bool]string{true: "value"},
			[]ref.Val{types.NewErr("invalid value")},
			map[string]ref.Val{"value": types.NewUnknown(1, nil)},
		} {
			_, _, err := prg.ContextEval(t.Context(), map[string]any{"ctx": value})
			assert.NotNil(t, err, "%s: %T", expr, value)
		}
	}
}

func TestFunctionJSONMarshalCycles(t *testing.T) {
	env, err := cel.NewEnv(cel.Variable("ctx", cel.DynType), CELLib())
	require.Nil(t, err)
	ast, iss := env.Compile("json.marshal(ctx)")
	require.Nil(t, iss.Err())
	prg, err := env.Program(ast)
	require.Nil(t, err)
	obj := map[string]any{}
	obj["self"] = obj
	list := make([]any, 1)
	list[0] = list
	for _, value := range []any{obj, list} {
		_, _, err := prg.ContextEval(t.Context(), map[string]any{"ctx": value})
		assert.ErrorContains(t, err, "Could not marshal json")
	}
	out, _, err := prg.ContextEval(t.Context(), map[string]any{"ctx": map[string]any{"value": "test"}})
	require.Nil(t, err)
	assert.Equal(t, `{"value":"test"}`, out.Value())
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
