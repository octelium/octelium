// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pbutils

import (
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const testPackage = "octelium.pbutils.test"

type testFieldType struct {
	name     string
	typ      descriptorpb.FieldDescriptorProto_Type
	typeName string
	isKey    bool
	isScalar bool
}

var testFieldTypes = []testFieldType{
	{name: "bool", typ: descriptorpb.FieldDescriptorProto_TYPE_BOOL, isKey: true, isScalar: true},
	{name: "int32", typ: descriptorpb.FieldDescriptorProto_TYPE_INT32, isKey: true, isScalar: true},
	{name: "sint32", typ: descriptorpb.FieldDescriptorProto_TYPE_SINT32, isKey: true, isScalar: true},
	{name: "sfixed32", typ: descriptorpb.FieldDescriptorProto_TYPE_SFIXED32, isKey: true, isScalar: true},
	{name: "uint32", typ: descriptorpb.FieldDescriptorProto_TYPE_UINT32, isKey: true, isScalar: true},
	{name: "fixed32", typ: descriptorpb.FieldDescriptorProto_TYPE_FIXED32, isKey: true, isScalar: true},
	{name: "int64", typ: descriptorpb.FieldDescriptorProto_TYPE_INT64, isKey: true, isScalar: true},
	{name: "sint64", typ: descriptorpb.FieldDescriptorProto_TYPE_SINT64, isKey: true, isScalar: true},
	{name: "sfixed64", typ: descriptorpb.FieldDescriptorProto_TYPE_SFIXED64, isKey: true, isScalar: true},
	{name: "uint64", typ: descriptorpb.FieldDescriptorProto_TYPE_UINT64, isKey: true, isScalar: true},
	{name: "fixed64", typ: descriptorpb.FieldDescriptorProto_TYPE_FIXED64, isKey: true, isScalar: true},
	{name: "float", typ: descriptorpb.FieldDescriptorProto_TYPE_FLOAT, isScalar: true},
	{name: "double", typ: descriptorpb.FieldDescriptorProto_TYPE_DOUBLE, isScalar: true},
	{name: "string", typ: descriptorpb.FieldDescriptorProto_TYPE_STRING, isKey: true, isScalar: true},
	{name: "bytes", typ: descriptorpb.FieldDescriptorProto_TYPE_BYTES, isScalar: true},
	{name: "enum", typ: descriptorpb.FieldDescriptorProto_TYPE_ENUM, typeName: "." + testPackage + ".Color", isScalar: true},
	{name: "null_value", typ: descriptorpb.FieldDescriptorProto_TYPE_ENUM, typeName: ".google.protobuf.NullValue", isScalar: true},
	{name: "message", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: "." + testPackage + ".Kinds"},
	{name: "timestamp", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.Timestamp"},
	{name: "duration", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.Duration"},
	{name: "bool_value", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.BoolValue"},
	{name: "int32_value", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.Int32Value"},
	{name: "int64_value", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.Int64Value"},
	{name: "uint32_value", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.UInt32Value"},
	{name: "uint64_value", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.UInt64Value"},
	{name: "float_value", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.FloatValue"},
	{name: "double_value", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.DoubleValue"},
	{name: "string_value", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.StringValue"},
	{name: "bytes_value", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.BytesValue"},
	{name: "struct", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.Struct"},
	{name: "list_value", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.ListValue"},
	{name: "value", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.Value"},
	{name: "empty", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.Empty"},
	{name: "any", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.Any"},
	{name: "field_mask", typ: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, typeName: ".google.protobuf.FieldMask"},
}

type testDescriptors struct {
	kinds     protoreflect.MessageDescriptor
	legacy    protoreflect.MessageDescriptor
	extString protoreflect.ExtensionType
}

func newTestField(name string, number int32,
	label descriptorpb.FieldDescriptorProto_Label, typ testFieldType) *descriptorpb.FieldDescriptorProto {
	ret := &descriptorpb.FieldDescriptorProto{
		Name:   proto.String(name),
		Number: proto.Int32(number),
		Label:  label.Enum(),
		Type:   typ.typ.Enum(),
	}
	if typ.typeName != "" {
		ret.TypeName = proto.String(typ.typeName)
	}
	return ret
}

func getTestMapEntryName(name string) string {
	var ret strings.Builder
	for part := range strings.SplitSeq(name, "_") {
		ret.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	ret.WriteString("Entry")
	return ret.String()
}

func newTestDescriptors(t testing.TB) *testDescriptors {
	t.Helper()

	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	stringType := testFieldTypes[slices.IndexFunc(testFieldTypes, func(itm testFieldType) bool {
		return itm.name == "string"
	})]

	kinds := &descriptorpb.DescriptorProto{
		Name:      proto.String("Kinds"),
		OneofDecl: []*descriptorpb.OneofDescriptorProto{{Name: proto.String("choice")}},
	}

	addField := func(fd *descriptorpb.FieldDescriptorProto) {
		kinds.Field = append(kinds.Field, fd)
	}

	nextNumber := func() int32 {
		return int32(len(kinds.Field) + 1)
	}

	addMap := func(name string, key, value testFieldType) {
		entry := &descriptorpb.DescriptorProto{
			Name: proto.String(getTestMapEntryName(name)),
			Field: []*descriptorpb.FieldDescriptorProto{
				newTestField("key", 1, optional, key),
				newTestField("value", 2, optional, value),
			},
			Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
		}
		kinds.NestedType = append(kinds.NestedType, entry)
		addField(newTestField(name, nextNumber(), repeated, testFieldType{
			typ:      descriptorpb.FieldDescriptorProto_TYPE_MESSAGE,
			typeName: fmt.Sprintf(".%s.Kinds.%s", testPackage, entry.GetName()),
		}))
	}

	for _, typ := range testFieldTypes {
		addField(newTestField("v_"+typ.name, nextNumber(), optional, typ))
		addField(newTestField("r_"+typ.name, nextNumber(), repeated, typ))
		addMap("m_"+typ.name, stringType, typ)

		if typ.isKey {
			addMap("k_"+typ.name, typ, stringType)
		}
	}

	for _, typ := range testFieldTypes {
		fd := newTestField("c_"+typ.name, nextNumber(), optional, typ)
		fd.OneofIndex = proto.Int32(0)
		addField(fd)
	}

	for _, typ := range testFieldTypes {
		if !typ.isScalar {
			continue
		}
		fd := newTestField("o_"+typ.name, nextNumber(), optional, typ)
		fd.OneofIndex = proto.Int32(int32(len(kinds.OneofDecl)))
		fd.Proto3Optional = proto.Bool(true)
		kinds.OneofDecl = append(kinds.OneofDecl, &descriptorpb.OneofDescriptorProto{
			Name: proto.String("_o_" + typ.name),
		})
		addField(fd)
	}

	customJSON := newTestField("custom_json", nextNumber(), optional, stringType)
	customJSON.JsonName = proto.String("customJSONName")
	addField(customJSON)

	kindsFile, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("pbutils_test_kinds.proto"),
		Package: proto.String(testPackage),
		Syntax:  proto.String("proto3"),
		Dependency: []string{
			"google/protobuf/any.proto",
			"google/protobuf/duration.proto",
			"google/protobuf/empty.proto",
			"google/protobuf/field_mask.proto",
			"google/protobuf/struct.proto",
			"google/protobuf/timestamp.proto",
			"google/protobuf/wrappers.proto",
		},
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name: proto.String("Color"),
			Value: []*descriptorpb.EnumValueDescriptorProto{
				{Name: proto.String("COLOR_UNSPECIFIED"), Number: proto.Int32(0)},
				{Name: proto.String("RED"), Number: proto.Int32(1)},
				{Name: proto.String("BLUE"), Number: proto.Int32(2)},
				{Name: proto.String("BLACK"), Number: proto.Int32(-1)},
			},
		}},
		MessageType: []*descriptorpb.DescriptorProto{kinds},
	}, protoregistry.GlobalFiles)
	require.NoError(t, err)

	legacyFile, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name:    proto.String("pbutils_test_legacy.proto"),
		Package: proto.String(testPackage),
		Syntax:  proto.String("proto2"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Legacy"),
			Field: []*descriptorpb.FieldDescriptorProto{
				{
					Name:   proto.String("required_int32"),
					Number: proto.Int32(1),
					Label:  descriptorpb.FieldDescriptorProto_LABEL_REQUIRED.Enum(),
					Type:   descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
				},
				{
					Name:         proto.String("optional_string"),
					Number:       proto.Int32(2),
					Label:        optional.Enum(),
					Type:         descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
					DefaultValue: proto.String("default"),
				},
				{
					Name:     proto.String("item"),
					Number:   proto.Int32(3),
					Label:    optional.Enum(),
					Type:     descriptorpb.FieldDescriptorProto_TYPE_GROUP.Enum(),
					TypeName: proto.String("." + testPackage + ".Legacy.Item"),
				},
				{
					Name:     proto.String("children"),
					Number:   proto.Int32(4),
					Label:    repeated.Enum(),
					Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
					TypeName: proto.String("." + testPackage + ".Legacy"),
				},
			},
			NestedType: []*descriptorpb.DescriptorProto{{
				Name: proto.String("Item"),
				Field: []*descriptorpb.FieldDescriptorProto{{
					Name:   proto.String("value"),
					Number: proto.Int32(1),
					Label:  optional.Enum(),
					Type:   descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum(),
				}},
			}},
			ExtensionRange: []*descriptorpb.DescriptorProto_ExtensionRange{{
				Start: proto.Int32(100),
				End:   proto.Int32(200),
			}},
		}},
		Extension: []*descriptorpb.FieldDescriptorProto{{
			Name:     proto.String("ext_string"),
			Number:   proto.Int32(100),
			Label:    optional.Enum(),
			Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
			Extendee: proto.String("." + testPackage + ".Legacy"),
		}},
	}, protoregistry.GlobalFiles)
	require.NoError(t, err)

	return &testDescriptors{
		kinds:     kindsFile.Messages().ByName("Kinds"),
		legacy:    legacyFile.Messages().ByName("Legacy"),
		extString: dynamicpb.NewExtensionType(legacyFile.Extensions().ByName("ext_string")),
	}
}

func (d *testDescriptors) newKinds(t testing.TB, in string) proto.Message {
	t.Helper()
	ret := dynamicpb.NewMessage(d.kinds)
	require.NoError(t, prototext.Unmarshal([]byte(in), ret))
	return ret
}

func (d *testDescriptors) newLegacy(t testing.TB, in string) proto.Message {
	t.Helper()
	ret := dynamicpb.NewMessage(d.legacy)
	require.NoError(t, prototext.UnmarshalOptions{AllowPartial: true}.Unmarshal([]byte(in), ret))
	return ret
}

func setTestField(m proto.Message, name string, v protoreflect.Value) proto.Message {
	m.ProtoReflect().Set(m.ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name(name)), v)
	return m
}

func isIdentical(a, b any) bool {
	switch a := a.(type) {
	case map[string]any:
		b, ok := b.(map[string]any)
		if !ok || (a == nil) != (b == nil) || len(a) != len(b) {
			return false
		}
		for k, v := range a {
			if bv, ok := b[k]; !ok || !isIdentical(v, bv) {
				return false
			}
		}
		return true
	case []any:
		b, ok := b.([]any)
		if !ok || (a == nil) != (b == nil) || len(a) != len(b) {
			return false
		}
		for i := range a {
			if !isIdentical(a[i], b[i]) {
				return false
			}
		}
		return true
	case float64:
		b, ok := b.(float64)
		return ok && math.Float64bits(a) == math.Float64bits(b)
	default:
		return a == b
	}
}

func requireIdentical(t testing.TB, want, got any, msgAndArgs ...any) {
	t.Helper()
	if !isIdentical(want, got) {
		require.Equal(t, want, got, msgAndArgs...)
		require.Failf(t, "Not identical", "want: %#v\ngot: %#v", want, got)
	}
}

func requireSameConvertToMap(t testing.TB, in proto.Message) (map[string]any, error) {
	t.Helper()

	want, wantErr := convertToMapJSON(in)
	got, err := ConvertToMap(in)
	if wantErr != nil {
		if err == nil || err.Error() != wantErr.Error() || got != nil {
			require.EqualError(t, err, wantErr.Error(), "%s", prototext.Format(in))
			require.Nil(t, got, "%s", prototext.Format(in))
		}
		return nil, err
	}

	if err != nil {
		require.NoError(t, err, "%s", prototext.Format(in))
	}
	if !isIdentical(want, got) {
		requireIdentical(t, want, got, "%s", prototext.Format(in))
	}

	return got, nil
}

func TestConvertToMapKinds(t *testing.T) {
	d := newTestDescriptors(t)
	negZero := math.Copysign(0, -1)

	for _, itm := range []struct {
		name string
		in   string
		want map[string]any
	}{
		{
			name: "empty",
			in:   ``,
			want: map[string]any{},
		},
		{
			name: "implicit presence zero values",
			in: `v_bool: false v_int32: 0 v_int64: 0 v_uint64: 0 v_float: 0 v_double: 0
				v_string: "" v_bytes: "" v_enum: COLOR_UNSPECIFIED v_null_value: NULL_VALUE`,
			want: map[string]any{},
		},
		{
			name: "explicit presence zero values",
			in: `o_bool: false o_int32: 0 o_uint32: 0 o_int64: 0 o_uint64: 0 o_float: 0 o_double: 0
				o_string: "" o_bytes: "" o_enum: COLOR_UNSPECIFIED o_null_value: NULL_VALUE`,
			want: map[string]any{
				"oBool":      false,
				"oInt32":     float64(0),
				"oUint32":    float64(0),
				"oInt64":     "0",
				"oUint64":    "0",
				"oFloat":     float64(0),
				"oDouble":    float64(0),
				"oString":    "",
				"oBytes":     "",
				"oEnum":      "COLOR_UNSPECIFIED",
				"oNullValue": nil,
			},
		},
		{
			name: "32-bit integers",
			in: `v_int32: -2147483648 v_sint32: 2147483647 v_sfixed32: -1 v_uint32: 4294967295 v_fixed32: 1
				r_int32: [0, 1, -1] r_uint32: [0, 7]`,
			want: map[string]any{
				"vInt32":    float64(math.MinInt32),
				"vSint32":   float64(math.MaxInt32),
				"vSfixed32": float64(-1),
				"vUint32":   float64(math.MaxUint32),
				"vFixed32":  float64(1),
				"rInt32":    []any{float64(0), float64(1), float64(-1)},
				"rUint32":   []any{float64(0), float64(7)},
			},
		},
		{
			name: "64-bit integers",
			in: `v_int64: -9223372036854775808 v_sint64: 9223372036854775807 v_sfixed64: -1
				v_uint64: 18446744073709551615 v_fixed64: 9007199254740993 r_int64: [0, -1] r_uint64: [0, 1]`,
			want: map[string]any{
				"vInt64":    "-9223372036854775808",
				"vSint64":   "9223372036854775807",
				"vSfixed64": "-1",
				"vUint64":   "18446744073709551615",
				"vFixed64":  "9007199254740993",
				"rInt64":    []any{"0", "-1"},
				"rUint64":   []any{"0", "1"},
			},
		},
		{
			name: "doubles",
			in: `v_double: -0 r_double: [0, -0, 0.1, 1e-7, 1e21, 123456789.125, 5e-324,
				1.7976931348623157e308, inf, -inf, nan]`,
			want: map[string]any{
				"vDouble": negZero,
				"rDouble": []any{
					float64(0), negZero, 0.1, 1e-7, 1e21, 123456789.125, 5e-324,
					math.MaxFloat64, "Infinity", "-Infinity", "NaN",
				},
			},
		},
		{
			name: "floats",
			in: `v_float: 0.3 r_float: [0, -0, 0.1, 16777217, 3.4028235e38, 1e-45, 1e-7, 1e21,
				123456.789, inf, -inf, nan]`,
			want: map[string]any{
				"vFloat": 0.3,
				"rFloat": []any{
					float64(0), negZero, 0.1, 16777216.0, 3.4028235e38, 1e-45, 1e-7, 1e21,
					123456.79, "Infinity", "-Infinity", "NaN",
				},
			},
		},
		{
			name: "strings",
			in: `v_string: "héllo ✓" r_string: ["", "  ", "\x00\x1f\x7f", "<script>&</script>",
				"😀", "\"quoted\" \\ slash", "line\nbreak\ttab"]`,
			want: map[string]any{
				"vString": "héllo ✓",
				"rString": []any{
					"", "  ", "\x00\x1f\x7f", "<script>&</script>",
					"😀", "\"quoted\" \\ slash", "line\nbreak\ttab",
				},
			},
		},
		{
			name: "bytes",
			in:   `v_bytes: "\x00\xff\xfe" r_bytes: ["", "abc", "\xfb\xff"]`,
			want: map[string]any{
				"vBytes": "AP/+",
				"rBytes": []any{"", "YWJj", "+/8="},
			},
		},
		{
			name: "enums",
			in: `v_enum: RED o_enum: BLACK r_enum: [COLOR_UNSPECIFIED, RED, BLACK, 977, -5]
				m_enum: {key: "a" value: BLUE} m_enum: {key: "b" value: 42} m_enum: {key: "c" value: COLOR_UNSPECIFIED}`,
			want: map[string]any{
				"vEnum": "RED",
				"oEnum": "BLACK",
				"rEnum": []any{"COLOR_UNSPECIFIED", "RED", "BLACK", float64(977), float64(-5)},
				"mEnum": map[string]any{"a": "BLUE", "b": float64(42), "c": "COLOR_UNSPECIFIED"},
			},
		},
		{
			name: "unknown enum",
			in:   `v_enum: 977`,
			want: map[string]any{"vEnum": float64(977)},
		},
		{
			name: "negative unknown enum",
			in:   `v_enum: -2147483648`,
			want: map[string]any{"vEnum": float64(math.MinInt32)},
		},
		{
			name: "null values",
			in: `r_null_value: [NULL_VALUE, NULL_VALUE] m_null_value: {key: "a" value: NULL_VALUE}
				c_null_value: NULL_VALUE`,
			want: map[string]any{
				"rNullValue": []any{nil, nil},
				"mNullValue": map[string]any{"a": nil},
				"cNullValue": nil,
			},
		},
		{
			name: "oneof zero int",
			in:   `c_int32: 0`,
			want: map[string]any{"cInt32": float64(0)},
		},
		{
			name: "oneof zero string",
			in:   `c_string: ""`,
			want: map[string]any{"cString": ""},
		},
		{
			name: "oneof zero enum",
			in:   `c_enum: COLOR_UNSPECIFIED`,
			want: map[string]any{"cEnum": "COLOR_UNSPECIFIED"},
		},
		{
			name: "oneof empty message",
			in:   `c_message: {}`,
			want: map[string]any{"cMessage": map[string]any{}},
		},
		{
			name: "oneof empty timestamp",
			in:   `c_timestamp: {}`,
			want: map[string]any{"cTimestamp": "1970-01-01T00:00:00Z"},
		},
		{
			name: "map keys",
			in: `k_bool: {key: true value: "t"} k_bool: {key: false value: "f"}
				k_int32: {key: -1 value: "a"} k_sint32: {key: -2147483648 value: "b"} k_sfixed32: {key: 3 value: "c"}
				k_uint32: {key: 4294967295 value: "d"} k_fixed32: {key: 0 value: "e"}
				k_int64: {key: -9223372036854775808 value: "f"} k_sint64: {key: 9223372036854775807 value: "g"}
				k_sfixed64: {key: -1 value: "h"} k_uint64: {key: 18446744073709551615 value: "i"}
				k_fixed64: {key: 1 value: "j"} k_string: {key: "" value: "k"} k_string: {key: "ü ✓" value: "l"}`,
			want: map[string]any{
				"kBool":     map[string]any{"true": "t", "false": "f"},
				"kInt32":    map[string]any{"-1": "a"},
				"kSint32":   map[string]any{"-2147483648": "b"},
				"kSfixed32": map[string]any{"3": "c"},
				"kUint32":   map[string]any{"4294967295": "d"},
				"kFixed32":  map[string]any{"0": "e"},
				"kInt64":    map[string]any{"-9223372036854775808": "f"},
				"kSint64":   map[string]any{"9223372036854775807": "g"},
				"kSfixed64": map[string]any{"-1": "h"},
				"kUint64":   map[string]any{"18446744073709551615": "i"},
				"kFixed64":  map[string]any{"1": "j"},
				"kString":   map[string]any{"": "k", "ü ✓": "l"},
			},
		},
		{
			name: "map values",
			in: `m_bool: {key: "a" value: false} m_int32: {key: "a" value: 0} m_int64: {key: "a" value: 5}
				m_uint64: {key: "a" value: 0} m_double: {key: "a" value: nan} m_double: {key: "b" value: -0}
				m_float: {key: "a" value: 0.1} m_string: {key: "a" value: ""} m_bytes: {key: "a" value: "\x01"}
				m_message: {key: "a" value: {}} m_message: {key: "b" value: {v_int32: 1}}`,
			want: map[string]any{
				"mBool":    map[string]any{"a": false},
				"mInt32":   map[string]any{"a": float64(0)},
				"mInt64":   map[string]any{"a": "5"},
				"mUint64":  map[string]any{"a": "0"},
				"mDouble":  map[string]any{"a": "NaN", "b": negZero},
				"mFloat":   map[string]any{"a": 0.1},
				"mString":  map[string]any{"a": ""},
				"mBytes":   map[string]any{"a": "AQ=="},
				"mMessage": map[string]any{"a": map[string]any{}, "b": map[string]any{"vInt32": float64(1)}},
			},
		},
		{
			name: "nested messages",
			in:   `v_message: {v_message: {v_string: "deep" r_message: [{}, {v_bool: true}]}} r_message: [{}]`,
			want: map[string]any{
				"vMessage": map[string]any{
					"vMessage": map[string]any{
						"vString":  "deep",
						"rMessage": []any{map[string]any{}, map[string]any{"vBool": true}},
					},
				},
				"rMessage": []any{map[string]any{}},
			},
		},
		{
			name: "custom JSON name",
			in:   `custom_json: "value"`,
			want: map[string]any{"customJSONName": "value"},
		},
		{
			name: "timestamps",
			in: `v_timestamp: {seconds: 1700000000 nanos: 1000000}
				r_timestamp: [{}, {seconds: 1700000000}, {seconds: 1 nanos: 120000000}, {seconds: 1 nanos: 123456000},
				{seconds: 1 nanos: 100}, {seconds: 1 nanos: 5}, {seconds: 1 nanos: 999999999}, {seconds: -1 nanos: 500000000},
				{seconds: -62135596800}, {seconds: 253402300799 nanos: 999999999}]
				m_timestamp: {key: "a" value: {seconds: 951782400}}`,
			want: map[string]any{
				"vTimestamp": "2023-11-14T22:13:20.001Z",
				"rTimestamp": []any{
					"1970-01-01T00:00:00Z",
					"2023-11-14T22:13:20Z",
					"1970-01-01T00:00:01.120Z",
					"1970-01-01T00:00:01.123456Z",
					"1970-01-01T00:00:01.000000100Z",
					"1970-01-01T00:00:01.000000005Z",
					"1970-01-01T00:00:01.999999999Z",
					"1969-12-31T23:59:59.500Z",
					"0001-01-01T00:00:00Z",
					"9999-12-31T23:59:59.999999999Z",
				},
				"mTimestamp": map[string]any{"a": "2000-02-29T00:00:00Z"},
			},
		},
		{
			name: "durations",
			in: `v_duration: {seconds: 90}
				r_duration: [{}, {seconds: 1 nanos: 500000000}, {seconds: -1 nanos: -500000000}, {nanos: -1},
				{nanos: 1000}, {nanos: 10000000}, {seconds: 315576000000}, {seconds: -315576000000 nanos: -999999999}]`,
			want: map[string]any{
				"vDuration": "90s",
				"rDuration": []any{
					"0s", "1.500s", "-1.500s", "-0.000000001s", "0.000001s", "0.010s",
					"315576000000s", "-315576000000.999999999s",
				},
			},
		},
		{
			name: "wrappers",
			in: `v_bool_value: {} v_int32_value: {value: -1} v_int64_value: {} v_uint32_value: {value: 4294967295}
				v_uint64_value: {value: 18446744073709551615} v_float_value: {value: 0.1} v_double_value: {value: nan}
				v_string_value: {} v_bytes_value: {value: "\x01"} r_int64_value: [{}, {value: -5}]
				m_bool_value: {key: "a" value: {value: true}}`,
			want: map[string]any{
				"vBoolValue":   false,
				"vInt32Value":  float64(-1),
				"vInt64Value":  "0",
				"vUint32Value": float64(math.MaxUint32),
				"vUint64Value": "18446744073709551615",
				"vFloatValue":  0.1,
				"vDoubleValue": "NaN",
				"vStringValue": "",
				"vBytesValue":  "AQ==",
				"rInt64Value":  []any{"0", "-5"},
				"mBoolValue":   map[string]any{"a": true},
			},
		},
		{
			name: "struct",
			in: `v_struct: {
					fields: {key: "a" value: {number_value: 1.5}}
					fields: {key: "b" value: {null_value: NULL_VALUE}}
					fields: {key: "c" value: {list_value: {values: [{string_value: "x"}, {bool_value: false}, {struct_value: {}}]}}}
					fields: {key: "d" value: {struct_value: {fields: {key: "e" value: {string_value: ""}}}}}
					fields: {key: "f" value: {number_value: -0}}
				}
				r_struct: [{}]`,
			want: map[string]any{
				"vStruct": map[string]any{
					"a": 1.5,
					"b": nil,
					"c": []any{"x", false, map[string]any{}},
					"d": map[string]any{"e": ""},
					"f": negZero,
				},
				"rStruct": []any{map[string]any{}},
			},
		},
		{
			name: "list and value",
			in: `v_list_value: {} r_list_value: [{values: [{null_value: NULL_VALUE}, {list_value: {}}]}]
				v_value: {null_value: NULL_VALUE} r_value: [{number_value: 1e21}, {string_value: "s"}, {bool_value: true}]
				m_value: {key: "a" value: {struct_value: {}}}`,
			want: map[string]any{
				"vListValue": []any{},
				"rListValue": []any{[]any{nil, []any{}}},
				"vValue":     nil,
				"rValue":     []any{1e21, "s", true},
				"mValue":     map[string]any{"a": map[string]any{}},
			},
		},
		{
			name: "empty messages",
			in:   `v_empty: {} r_empty: [{}, {}] m_empty: {key: "a" value: {}}`,
			want: map[string]any{
				"vEmpty": map[string]any{},
				"rEmpty": []any{map[string]any{}, map[string]any{}},
				"mEmpty": map[string]any{"a": map[string]any{}},
			},
		},
		{
			name: "any",
			in:   `v_any: {type_url: "type.googleapis.com/google.protobuf.Duration" value: "\x08\x01"}`,
			want: map[string]any{
				"vAny": map[string]any{
					"@type": "type.googleapis.com/google.protobuf.Duration",
					"value": "1s",
				},
			},
		},
		{
			name: "field mask",
			in:   `v_field_mask: {paths: ["a_b", "c"]}`,
			want: map[string]any{"vFieldMask": "aB,c"},
		},
	} {
		t.Run(itm.name, func(t *testing.T) {
			got, err := requireSameConvertToMap(t, d.newKinds(t, itm.in))
			require.NoError(t, err)
			requireIdentical(t, itm.want, got)
		})
	}
}

func TestConvertToMapErrors(t *testing.T) {
	d := newTestDescriptors(t)

	for _, itm := range []struct {
		name string
		in   proto.Message
		err  string
	}{
		{
			name: "timestamp seconds above range",
			in:   d.newKinds(t, `v_timestamp: {seconds: 253402300800}`),
			err:  "seconds out of range",
		},
		{
			name: "timestamp seconds below range",
			in:   d.newKinds(t, `r_timestamp: [{}, {seconds: -62135596801}]`),
			err:  "seconds out of range",
		},
		{
			name: "timestamp negative nanos",
			in:   d.newKinds(t, `m_timestamp: {key: "a" value: {nanos: -1}}`),
			err:  "nanos out of range",
		},
		{
			name: "timestamp nanos above range",
			in:   d.newKinds(t, `c_timestamp: {nanos: 1000000000}`),
			err:  "nanos out of range",
		},
		{
			name: "duration seconds above range",
			in:   d.newKinds(t, `v_duration: {seconds: 315576000001}`),
			err:  "seconds out of range",
		},
		{
			name: "duration seconds below range",
			in:   d.newKinds(t, `v_duration: {seconds: -315576000001}`),
			err:  "seconds out of range",
		},
		{
			name: "duration nanos out of range",
			in:   d.newKinds(t, `v_duration: {nanos: -1000000000}`),
			err:  "nanos out of range",
		},
		{
			name: "duration positive seconds negative nanos",
			in:   d.newKinds(t, `v_duration: {seconds: 1 nanos: -1}`),
			err:  "signs of seconds and nanos do not match",
		},
		{
			name: "duration negative seconds positive nanos",
			in:   d.newKinds(t, `r_duration: [{seconds: -1 nanos: 1}]`),
			err:  "signs of seconds and nanos do not match",
		},
		{
			name: "value without kind",
			in:   d.newKinds(t, `v_value: {}`),
			err:  "none of the oneof fields is set",
		},
		{
			name: "struct value without kind",
			in:   d.newKinds(t, `v_struct: {fields: {key: "a" value: {}}}`),
			err:  "none of the oneof fields is set",
		},
		{
			name: "value NaN",
			in:   d.newKinds(t, `r_value: [{number_value: nan}]`),
			err:  "invalid NaN value",
		},
		{
			name: "value infinity",
			in:   d.newKinds(t, `m_value: {key: "a" value: {number_value: -inf}}`),
			err:  "invalid -Inf value",
		},
		{
			name: "invalid string",
			in:   setTestField(d.newKinds(t, `v_int32: 1`), "v_string", protoreflect.ValueOfString("\xff")),
			err:  "invalid UTF-8",
		},
		{
			name: "invalid oneof string",
			in:   setTestField(d.newKinds(t, ``), "c_string", protoreflect.ValueOfString("a\xfeb")),
			err:  "invalid UTF-8",
		},
		{
			name: "invalid map key",
			in:   &corev1.RequestContext_Request_HTTP{Headers: map[string]string{"x\xff": "a"}},
			err:  "invalid UTF-8",
		},
		{
			name: "invalid map value",
			in:   &corev1.RequestContext_Request_HTTP{Headers: map[string]string{"x": "\xc3\x28"}},
			err:  "invalid UTF-8",
		},
		{
			name: "invalid struct key",
			in:   &structpb.Struct{Fields: map[string]*structpb.Value{"\xff": structpb.NewBoolValue(true)}},
			err:  "invalid UTF-8",
		},
		{
			name: "nil struct value",
			in:   &structpb.Struct{Fields: map[string]*structpb.Value{"a": nil}},
			err:  "none of the oneof fields is set",
		},
		{
			name: "nil list element",
			in: &structpb.Struct{Fields: map[string]*structpb.Value{
				"a": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{nil}}),
			}},
			err: "none of the oneof fields is set",
		},
		{
			name: "unresolvable any",
			in:   d.newKinds(t, `v_any: {type_url: "type.googleapis.com/octelium.Unknown"}`),
			err:  "octelium.Unknown",
		},
		{
			name: "invalid field mask",
			in:   d.newKinds(t, `v_field_mask: {paths: ["a b"]}`),
			err:  "invalid path",
		},
		{
			name: "irreversible field mask",
			in:   d.newKinds(t, `v_field_mask: {paths: ["aB"]}`),
			err:  "irreversible value",
		},
		{
			name: "missing required field",
			in:   d.newLegacy(t, `optional_string: "x"`),
			err:  "required field",
		},
		{
			name: "missing nested required field",
			in:   d.newLegacy(t, `required_int32: 1 children: [{required_int32: 2}, {}]`),
			err:  "required field",
		},
		{
			name: "top-level timestamp",
			in:   timestamppb.New(time.Unix(1, 0)),
			err:  "cannot unmarshal",
		},
		{
			name: "top-level duration",
			in:   durationpb.New(time.Second),
			err:  "cannot unmarshal",
		},
		{
			name: "top-level wrapper",
			in:   wrapperspb.Int64(1),
			err:  "cannot unmarshal",
		},
		{
			name: "top-level list value",
			in:   &structpb.ListValue{},
			err:  "cannot unmarshal",
		},
		{
			name: "top-level string value",
			in:   structpb.NewStringValue("a"),
			err:  "cannot unmarshal",
		},
		{
			name: "top-level field mask",
			in:   &fieldmaskpb.FieldMask{Paths: []string{"a"}},
			err:  "cannot unmarshal",
		},
	} {
		t.Run(itm.name, func(t *testing.T) {
			_, err := requireSameConvertToMap(t, itm.in)
			require.ErrorContains(t, err, itm.err)
		})
	}
}

func TestConvertToMapMessages(t *testing.T) {
	d := newTestDescriptors(t)

	nestedNil := &structpb.Value{Kind: &structpb.Value_StructValue{}}
	nestedNilList := &structpb.Value{Kind: &structpb.Value_ListValue{}}

	withExtension := d.newLegacy(t, `required_int32: 1`)
	withExtension.ProtoReflect().Set(d.extString.TypeDescriptor(), protoreflect.ValueOfString("ext"))

	for _, itm := range []struct {
		name string
		in   proto.Message
		want map[string]any
	}{
		{
			name: "nil",
			in:   nil,
			want: map[string]any{},
		},
		{
			name: "typed nil",
			in:   (*corev1.RequestContext)(nil),
			want: map[string]any{},
		},
		{
			name: "typed nil struct",
			in:   (*structpb.Struct)(nil),
			want: map[string]any{},
		},
		{
			name: "empty",
			in:   &emptypb.Empty{},
			want: map[string]any{},
		},
		{
			name: "struct",
			in: &structpb.Struct{Fields: map[string]*structpb.Value{
				"a": structpb.NewNumberValue(2),
				"b": nestedNil,
				"c": nestedNilList,
			}},
			want: map[string]any{"a": float64(2), "b": map[string]any{}, "c": []any{}},
		},
		{
			name: "top-level struct value",
			in:   structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{"a": structpb.NewBoolValue(true)}}),
			want: map[string]any{"a": true},
		},
		{
			name: "top-level null value",
			in:   structpb.NewNullValue(),
			want: nil,
		},
		{
			name: "top-level any",
			in: func() proto.Message {
				ret, _ := anypb.New(durationpb.New(time.Second))
				return ret
			}(),
			want: map[string]any{"@type": "type.googleapis.com/google.protobuf.Duration", "value": "1s"},
		},
		{
			name: "nil repeated message",
			in:   &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{nil, {Name: "rule"}}},
			want: map[string]any{"rules": []any{map[string]any{}, map[string]any{"name": "rule"}}},
		},
		{
			name: "nil map message",
			in: &corev1.Region_Status{VersionInfoMap: map[string]*corev1.Region_Status_VersionInfo{
				"a": nil,
				"b": {},
			}},
			want: map[string]any{"versionInfoMap": map[string]any{"a": map[string]any{}, "b": map[string]any{}}},
		},
		{
			name: "proto2",
			in:   d.newLegacy(t, `required_int32: 0 optional_string: "" item: {} children: [{required_int32: -1 item: {value: 0}}]`),
			want: map[string]any{
				"requiredInt32":  float64(0),
				"optionalString": "",
				"item":           map[string]any{},
				"children":       []any{map[string]any{"requiredInt32": float64(-1), "item": map[string]any{"value": float64(0)}}},
			},
		},
		{
			name: "proto2 default value",
			in:   d.newLegacy(t, `required_int32: 1 optional_string: "default"`),
			want: map[string]any{"requiredInt32": float64(1), "optionalString": "default"},
		},
		{
			name: "proto2 extension",
			in:   withExtension,
			want: map[string]any{"requiredInt32": float64(1), "[octelium.pbutils.test.ext_string]": "ext"},
		},
		{
			name: "user",
			in: &corev1.User{
				ApiVersion: "core/v1",
				Kind:       "User",
				Metadata: &metav1.Metadata{
					Name:      "alice",
					CreatedAt: timestamppb.New(time.Date(2026, time.November, 1, 10, 0, 0, 123456789, time.UTC)),
					Labels:    map[string]string{"team": "platform"},
				},
				Spec: &corev1.User_Spec{
					Type:   corev1.User_Spec_HUMAN,
					Groups: []string{"engineering"},
				},
			},
			want: map[string]any{
				"apiVersion": "core/v1",
				"kind":       "User",
				"metadata": map[string]any{
					"name":      "alice",
					"createdAt": "2026-11-01T10:00:00.123456789Z",
					"labels":    map[string]any{"team": "platform"},
				},
				"spec": map[string]any{
					"type":   "HUMAN",
					"groups": []any{"engineering"},
				},
			},
		},
	} {
		t.Run(itm.name, func(t *testing.T) {
			got, err := requireSameConvertToMap(t, itm.in)
			require.NoError(t, err)
			requireIdentical(t, itm.want, got)
		})
	}
}

func TestConvertToMapRequestContext(t *testing.T) {
	reqCtx := newTestRequestContext()

	got, err := requireSameConvertToMap(t, reqCtx)
	require.NoError(t, err)

	session := got["session"].(map[string]any)
	assert.Equal(t, "CLIENT", session["status"].(map[string]any)["type"])
	assert.Equal(t, "2026-11-01T10:00:00.123456789Z", session["metadata"].(map[string]any)["createdAt"])
	assert.Equal(t, float64(3), session["status"].(map[string]any)["totalAuthentications"])
	assert.Equal(t, "GET", got["request"].(map[string]any)["http"].(map[string]any)["method"])
}

func TestMessageToStructRoundTrip(t *testing.T) {
	reqCtx := newTestRequestContext()

	s, err := MessageToStruct(reqCtx)
	require.NoError(t, err)

	ret := &corev1.RequestContext{}
	require.NoError(t, StructToMessage(s, ret))
	assert.True(t, proto.Equal(reqCtx, ret))
}

type testRandom struct {
	*rand.Rand
	invalid  bool
	maxDepth int
}

var testStrings = []string{
	"", "a", "hello world", "üñíçødé ✓", "  ", "<>&\"'\\", "\x00\x1f\x7f", "line\nbreak\ttab", "😀", "1e3",
}

func (r *testRandom) string() string {
	if r.invalid && r.IntN(16) == 0 {
		return "invalid\xff\xfe"
	}
	return testStrings[r.IntN(len(testStrings))]
}

func (r *testRandom) float() float64 {
	switch r.IntN(16) {
	case 0:
		return math.NaN()
	case 1:
		return math.Inf(1)
	case 2:
		return math.Inf(-1)
	case 3:
		return 0
	case 4:
		return math.Copysign(0, -1)
	case 5:
		return 1e-7
	case 6:
		return 1e21
	case 7:
		return 0.1
	case 8:
		return math.MaxFloat64
	case 9:
		return math.SmallestNonzeroFloat64
	case 10:
		return math.MaxFloat32
	case 11:
		return math.SmallestNonzeroFloat32
	default:
		return r.NormFloat64() * math.Pow(10, float64(r.IntN(50)-25))
	}
}

func (r *testRandom) scalar(fd protoreflect.FieldDescriptor) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(r.IntN(2) == 0)
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(r.string())
	case protoreflect.BytesKind:
		ret := make([]byte, r.IntN(40))
		for i := range ret {
			ret[i] = byte(r.IntN(256))
		}
		return protoreflect.ValueOfBytes(ret)
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32([]int32{0, -1, 1, 42, math.MaxInt32, math.MinInt32, r.Int32()}[r.IntN(7)])
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32([]uint32{0, 1, 42, math.MaxUint32, r.Uint32()}[r.IntN(5)])
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64([]int64{0, -1, 1, math.MaxInt64, math.MinInt64, 1<<53 + 1, r.Int64()}[r.IntN(7)])
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64([]uint64{0, 1, math.MaxUint64, 1<<53 + 1, r.Uint64()}[r.IntN(5)])
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(float32(r.float()))
	case protoreflect.DoubleKind:
		ret := r.float()
		if !r.invalid && fd.FullName() == "google.protobuf.Value.number_value" &&
			(math.IsNaN(ret) || math.IsInf(ret, 0)) {
			ret = 1.5
		}
		return protoreflect.ValueOfFloat64(ret)
	case protoreflect.EnumKind:
		if r.IntN(6) == 0 {
			return protoreflect.ValueOfEnum([]protoreflect.EnumNumber{977, -5}[r.IntN(2)])
		}
		values := fd.Enum().Values()
		return protoreflect.ValueOfEnum(values.Get(r.IntN(values.Len())).Number())
	default:
		panic(fd.Kind())
	}
}

func (r *testRandom) mapKey(fd protoreflect.FieldDescriptor) protoreflect.MapKey {
	if fd.Kind() == protoreflect.StringKind {
		return protoreflect.ValueOfString(r.string() + string(rune('a'+r.IntN(26)))).MapKey()
	}
	return r.scalar(fd).MapKey()
}

func (r *testRandom) populate(m protoreflect.Message, depth int) {
	md := m.Descriptor()
	fields := md.Fields()

	switch md.FullName() {
	case "google.protobuf.Timestamp":
		secs := r.Int64N(maxTimestampSeconds-minTimestampSeconds+1) + minTimestampSeconds
		nanos := []int32{0, 1000000, 120000000, 123456000, 5, 999999999, r.Int32N(maxNanos + 1)}[r.IntN(7)]
		if r.invalid && r.IntN(8) == 0 {
			secs, nanos = []int64{maxTimestampSeconds + 1, minTimestampSeconds - 1}[r.IntN(2)], -1
		}
		m.Set(fields.ByNumber(1), protoreflect.ValueOfInt64(secs))
		m.Set(fields.ByNumber(2), protoreflect.ValueOfInt32(nanos))
		return
	case "google.protobuf.Duration":
		secs := r.Int64N(2*maxDurationSeconds+1) - maxDurationSeconds
		nanos := []int32{0, 1000000, 120000000, 123456000, 5, 999999999, r.Int32N(maxNanos + 1)}[r.IntN(7)]
		if secs < 0 || (secs == 0 && r.IntN(2) == 0) {
			nanos = -nanos
		}
		if r.invalid && r.IntN(8) == 0 {
			nanos = -nanos
		}
		m.Set(fields.ByNumber(1), protoreflect.ValueOfInt64(secs))
		m.Set(fields.ByNumber(2), protoreflect.ValueOfInt32(nanos))
		return
	case "google.protobuf.Any":
		if r.invalid && r.IntN(2) == 0 {
			m.Set(fields.ByNumber(1), protoreflect.ValueOfString("type.googleapis.com/octelium.Unknown"))
			return
		}
		ret, _ := anypb.New(durationpb.New(time.Duration(r.Int64())))
		m.Set(fields.ByNumber(1), protoreflect.ValueOfString(ret.TypeUrl))
		m.Set(fields.ByNumber(2), protoreflect.ValueOfBytes(ret.Value))
		return
	case "google.protobuf.FieldMask":
		if !r.invalid {
			l := m.Mutable(fields.ByNumber(1)).List()
			for range r.IntN(3) {
				l.Append(protoreflect.ValueOfString([]string{"a", "a_b", "spec.config"}[r.IntN(3)]))
			}
			return
		}
	}

	for _, i := range r.Perm(fields.Len()) {
		fd := fields.Get(i)
		if r.IntN(3) == 0 {
			continue
		}
		if od := fd.ContainingOneof(); od != nil && m.WhichOneof(od) != nil {
			continue
		}

		switch {
		case fd.IsList():
			if fd.Message() != nil && depth >= r.maxDepth {
				continue
			}
			l := m.Mutable(fd).List()
			for range r.IntN(4) {
				if fd.Message() == nil {
					l.Append(r.scalar(fd))
					continue
				}
				v := l.NewElement()
				r.populate(v.Message(), depth+1)
				l.Append(v)
			}
		case fd.IsMap():
			if fd.MapValue().Message() != nil && depth >= r.maxDepth {
				continue
			}
			mp := m.Mutable(fd).Map()
			for range r.IntN(4) {
				if fd.MapValue().Message() == nil {
					mp.Set(r.mapKey(fd.MapKey()), r.scalar(fd.MapValue()))
					continue
				}
				v := mp.NewValue()
				r.populate(v.Message(), depth+1)
				mp.Set(r.mapKey(fd.MapKey()), v)
			}
		case fd.Message() != nil:
			if depth >= r.maxDepth {
				continue
			}
			r.populate(m.Mutable(fd).Message(), depth+1)
		default:
			v := r.scalar(fd)
			if fd.HasPresence() && r.IntN(4) == 0 {
				v = fd.Default()
			}
			m.Set(fd, v)
		}
	}
}

func TestConvertToMapRandom(t *testing.T) {
	d := newTestDescriptors(t)

	type messageType struct {
		newMsg   func() protoreflect.Message
		samples  int
		maxDepth int
	}

	messageTypes := []messageType{
		{newMsg: func() protoreflect.Message { return dynamicpb.NewMessage(d.kinds) }, samples: 300, maxDepth: 2},
		{newMsg: func() protoreflect.Message { return dynamicpb.NewMessage(d.legacy) }, samples: 500, maxDepth: 3},
	}

	hotTypes := map[protoreflect.FullName]bool{}
	for _, m := range []proto.Message{
		&corev1.RequestContext{}, &corev1.AccessLog{}, &corev1.Session{}, &corev1.User{}, &corev1.Device{},
		&corev1.Service{}, &corev1.Policy{}, &corev1.Group{}, &corev1.Namespace{}, &corev1.PolicyTrigger{},
	} {
		hotTypes[m.ProtoReflect().Descriptor().FullName()] = true
	}

	var globalTypes []protoreflect.MessageType
	protoregistry.GlobalTypes.RangeMessages(func(mt protoreflect.MessageType) bool {
		globalTypes = append(globalTypes, mt)
		return true
	})
	slices.SortFunc(globalTypes, func(a, b protoreflect.MessageType) int {
		return strings.Compare(string(a.Descriptor().FullName()), string(b.Descriptor().FullName()))
	})

	for _, mt := range globalTypes {
		samples := 20
		if hotTypes[mt.Descriptor().FullName()] {
			samples = 300
		}
		messageTypes = append(messageTypes, messageType{newMsg: mt.New, samples: samples, maxDepth: 3})
	}

	r := &testRandom{Rand: rand.New(rand.NewPCG(20261124, 1))}
	var nOK, nErr int

	for _, itm := range messageTypes {
		r.maxDepth = itm.maxDepth
		for i := range itm.samples {
			r.invalid = i%4 == 3
			m := itm.newMsg()
			r.populate(m, 0)

			if _, err := requireSameConvertToMap(t, m.Interface()); err != nil {
				nErr++
			} else {
				nOK++
			}
		}
	}

	t.Logf("types: %d, identical maps: %d, identical errors: %d", len(messageTypes), nOK, nErr)
	assert.Greater(t, nOK, 4*nErr)
}

func FuzzConvertToMap(f *testing.F) {
	r := &testRandom{Rand: rand.New(rand.NewPCG(1, 2)), maxDepth: 3}
	for _, m := range []proto.Message{
		&corev1.RequestContext{}, &corev1.AccessLog{}, &corev1.Session{}, &corev1.Service{}, &structpb.Struct{},
	} {
		r.populate(m.ProtoReflect(), 0)
		in, err := proto.Marshal(m)
		require.NoError(f, err)
		f.Add(in)
	}
	in, err := proto.Marshal(newTestRequestContext())
	require.NoError(f, err)
	f.Add(in)

	f.Fuzz(func(t *testing.T, in []byte) {
		for _, m := range []proto.Message{
			&corev1.RequestContext{},
			&corev1.AccessLog{},
			&corev1.Session{},
			&corev1.Service{},
			&structpb.Struct{},
		} {
			if err := proto.Unmarshal(in, m); err != nil {
				continue
			}
			requireSameConvertToMap(t, m)
		}
	})
}

func FuzzConvertToMapRandom(f *testing.F) {
	d := newTestDescriptors(f)

	f.Add(uint64(1), uint64(2), false)
	f.Add(uint64(3), uint64(4), true)
	f.Add(uint64(20261124), uint64(0), false)

	f.Fuzz(func(t *testing.T, seed1, seed2 uint64, invalid bool) {
		r := &testRandom{Rand: rand.New(rand.NewPCG(seed1, seed2)), invalid: invalid, maxDepth: 2}
		for _, md := range []protoreflect.MessageDescriptor{d.kinds, d.legacy} {
			m := dynamicpb.NewMessage(md)
			r.populate(m, 0)
			requireSameConvertToMap(t, m)
		}
	})
}

func newTestRequestContext() *corev1.RequestContext {
	at := time.Date(2026, time.November, 1, 10, 0, 0, 123456789, time.UTC)

	newMetadata := func(name string) *metav1.Metadata {
		return &metav1.Metadata{
			Uid:             "8b1f3c2a-0001-4d6e-9f10-" + fmt.Sprintf("%012d", len(name)),
			Name:            name,
			CreatedAt:       timestamppb.New(at),
			UpdatedAt:       timestamppb.New(at.Add(time.Hour)),
			ResourceVersion: "0195d3a1-7c2e-7001-8a4b-3c2d1e0f9a8b",
			Labels:          map[string]string{"team": "platform"},
		}
	}

	newRef := func(kind, name string) *metav1.ObjectReference {
		return &metav1.ObjectReference{ApiVersion: "core/v1", Kind: kind, Name: name, Uid: newMetadata(name).Uid}
	}

	newAuthentication := func(i int) *corev1.Session_Status_Authentication {
		return &corev1.Session_Status_Authentication{
			SetAt:                timestamppb.New(at.Add(time.Duration(-i) * time.Hour)),
			TokenID:              fmt.Sprintf("0a1b2c3d-%04d-4e5f-8a9b-0c1d2e3f4a5b", i),
			AccessTokenDuration:  &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 1}},
			RefreshTokenDuration: &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 24}},
			Info: &corev1.Session_Status_Authentication_Info{
				Type: corev1.Session_Status_Authentication_Info_IDENTITY_PROVIDER,
				Aal:  corev1.Session_Status_Authentication_Info_AAL2,
				Details: &corev1.Session_Status_Authentication_Info_IdentityProvider_{
					IdentityProvider: &corev1.Session_Status_Authentication_Info_IdentityProvider{
						IdentityProviderRef: newRef("IdentityProvider", "github"),
						Identifier:          "alice-gh",
						Email:               "alice@example.com",
					},
				},
				Downstream: &corev1.Session_Status_Authentication_Info_Downstream{
					IpAddress: "203.0.113.45",
					UserAgent: "octelium-cli/0.52.0 (linux; amd64)",
				},
				Geoip: &corev1.GeoIP{
					Ip:          "203.0.113.45",
					Country:     &corev1.GeoIP_Country{Code: "DE", Name: "Germany"},
					Coordinates: &corev1.GeoIP_Coordinates{Latitude: 52.52, Longitude: 13.405},
				},
			},
		}
	}

	attrs, _ := structpb.NewStruct(map[string]any{
		"tenant": "acme",
		"limits": map[string]any{"rps": 100.0, "burst": 20.0},
		"tags":   []any{"a", "b"},
	})

	session := &corev1.Session{
		ApiVersion: "core/v1",
		Kind:       "Session",
		Metadata:   newMetadata("alice-3f9a2b1c"),
		Spec: &corev1.Session_Spec{
			State:     corev1.Session_Spec_ACTIVE,
			ExpiresAt: timestamppb.New(at.Add(30 * 24 * time.Hour)),
		},
		Status: &corev1.Session_Status{
			Type:                  corev1.Session_Status_CLIENT,
			UserRef:               newRef("User", "alice"),
			DeviceRef:             newRef("Device", "alice-laptop"),
			Authentication:        newAuthentication(0),
			InitialAuthentication: newAuthentication(0),
			TotalAuthentications:  3,
			IsConnected:           true,
			Connection: &corev1.Session_Status_Connection{
				StartedAt:       timestamppb.New(at.Add(-2 * time.Hour)),
				Addresses:       []*metav1.DualStackNetwork{{V4: "100.64.0.12/32", V6: "fdee:b0b0:1::c/128"}},
				Type:            corev1.Session_Status_Connection_WIREGUARD,
				X25519PublicKey: []byte("0123456789abcdef0123456789abcdef"),
			},
		},
	}
	for i := range 3 {
		session.Status.LastAuthentications = append(session.Status.LastAuthentications, newAuthentication(i+1))
	}

	return &corev1.RequestContext{
		User: &corev1.User{
			ApiVersion: "core/v1",
			Kind:       "User",
			Metadata:   newMetadata("alice"),
			Spec: &corev1.User_Spec{
				Type:   corev1.User_Spec_HUMAN,
				Email:  "alice@example.com",
				Groups: []string{"engineering", "ops"},
			},
			Status: &corev1.User_Status{},
		},
		Session: session,
		Device: &corev1.Device{
			ApiVersion: "core/v1",
			Kind:       "Device",
			Metadata:   newMetadata("alice-laptop"),
			Spec:       &corev1.Device_Spec{State: corev1.Device_Spec_ACTIVE},
			Status: &corev1.Device_Status{
				UserRef:      newRef("User", "alice"),
				OsType:       corev1.Device_Status_LINUX,
				Hostname:     "alice-thinkpad",
				MacAddresses: []string{"00:11:22:33:44:55"},
			},
		},
		Groups: []*corev1.Group{
			{ApiVersion: "core/v1", Kind: "Group", Metadata: newMetadata("engineering"), Spec: &corev1.Group_Spec{}},
			{ApiVersion: "core/v1", Kind: "Group", Metadata: newMetadata("ops"), Spec: &corev1.Group_Spec{}},
		},
		Namespace: &corev1.Namespace{
			ApiVersion: "core/v1",
			Kind:       "Namespace",
			Metadata:   newMetadata("default"),
			Spec:       &corev1.Namespace_Spec{},
		},
		Service: &corev1.Service{
			ApiVersion: "core/v1",
			Kind:       "Service",
			Metadata:   newMetadata("api.default"),
			Spec: &corev1.Service_Spec{
				Mode:     corev1.Service_Spec_HTTP,
				Port:     8080,
				IsPublic: true,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "http://api.internal:8080"},
					},
				},
				Authorization: &corev1.Service_Spec_Authorization{
					InlinePolicies: []*corev1.InlinePolicy{{
						Name: "inline",
						Spec: &corev1.Policy_Spec{
							Attrs: attrs,
							Rules: []*corev1.Policy_Spec_Rule{{
								Name:      "allow-get",
								Effect:    corev1.Policy_Spec_Rule_ALLOW,
								Priority:  -1,
								Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: `ctx.request.http.method == "GET"`}},
							}},
						},
					}},
				},
			},
			Status: &corev1.Service_Status{
				NamespaceRef:    newRef("Namespace", "default"),
				PrimaryHostname: "api",
				Port:            8080,
			},
		},
		Request: &corev1.RequestContext_Request{
			Ip: "203.0.113.45",
			Type: &corev1.RequestContext_Request_Http{Http: &corev1.RequestContext_Request_HTTP{
				Method: "GET",
				Path:   "/api/v1/items",
				Host:   "api.example.com",
				Scheme: "https",
				Uri:    "/api/v1/items?limit=20",
				Size:   -1,
				Headers: map[string]string{
					"accept":       "application/json",
					"user-agent":   "Mozilla/5.0 (X11; Linux x86_64)",
					"x-request-id": "4f3c2b1a-0d9e-4c8b-a7f6-5e4d3c2b1a09",
					"cookie":       "octelium_auth=" + strings.Repeat("a", 600),
				},
				QueryParams: map[string]string{"limit": "20"},
			}},
		},
	}
}

func BenchmarkConvertToMap(b *testing.B) {
	reqCtx := newTestRequestContext()

	b.Run("reflect", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := ConvertToMap(reqCtx); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("json", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := convertToMapJSON(reqCtx); err != nil {
				b.Fatal(err)
			}
		}
	})
}
