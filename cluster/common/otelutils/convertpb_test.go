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

package otelutils

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
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
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
	"google.golang.org/protobuf/types/known/typepb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const testPackage = "octelium.otelutils.test"

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
		Name:    proto.String("otelutils_test_kinds.proto"),
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
		Name:    proto.String("otelutils_test_legacy.proto"),
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

func getLegacyAccessLogBody(in *corev1.AccessLog) attribute.Value {
	inMap, err := pbutils.ConvertToMap(in)
	if err != nil {
		in = pbutils.Clone(in).(*corev1.AccessLog)
		vutils.ReplaceInvalidUTF8(in)
		inMap, _ = pbutils.ConvertToMap(in)
	}

	return convertValue(inMap)
}

func requireSameProtoMessage(t testing.TB, in proto.Message) bool {
	got, ok := convertProtoMessage(in)
	want, err := pbutils.ConvertToMap(in)
	if ok {
		require.NoError(t, err)
		require.Equal(t, convertValue(want), got)
		return true
	}

	assert.Equal(t, attribute.Value{}, got)
	if err == nil {
		require.True(t, hasTestUnsupportedType(in.ProtoReflect(), true), "%v", in)
	}
	return false
}

func hasTestUnsupportedType(m protoreflect.Message, isRoot bool) bool {
	switch getWellKnownType(m.Descriptor().FullName()) {
	case wellKnownTypeUnsupported:
		return true
	case wellKnownTypeNone, wellKnownTypeStruct:
	default:
		if isRoot {
			return true
		}
	}

	ret := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList():
			if fd.Message() != nil {
				for i := range v.List().Len() {
					ret = ret || hasTestUnsupportedType(v.List().Get(i).Message(), false)
				}
			}
		case fd.IsMap():
			if fd.MapValue().Message() != nil {
				v.Map().Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
					ret = ret || hasTestUnsupportedType(v.Message(), false)
					return true
				})
			}
		case fd.Message() != nil:
			ret = ret || hasTestUnsupportedType(v.Message(), false)
		}
		return !ret
	})

	return ret
}

func TestConvertProtoMessage(t *testing.T) {
	createdAt := &timestamppb.Timestamp{Seconds: 1700000000, Nanos: 120000000}

	for _, tc := range []struct {
		in   *corev1.AccessLog
		want attribute.Value
	}{
		{
			in:   &corev1.AccessLog{},
			want: attribute.MapValue(),
		},
		{
			in: &corev1.AccessLog{
				ApiVersion: "core/v1",
				Kind:       "AccessLog",
				Metadata: &metav1.LogMetadata{
					Id:        "id-1",
					CreatedAt: createdAt,
					ActorRef:  &metav1.ObjectReference{Kind: "Session", Name: "s"},
				},
				Entry: &corev1.AccessLog_Entry{
					Common: &corev1.AccessLog_Entry_Common{
						StartedAt: &timestamppb.Timestamp{Seconds: -62135596800},
						EndedAt:   &timestamppb.Timestamp{Seconds: 253402300799, Nanos: 999999999},
						Status:    corev1.AccessLog_Entry_Common_ALLOWED,
						Mode:      corev1.Service_Spec_Mode(977),
						Sequence:  math.MinInt64,
						IsPublic:  true,
						Network: &corev1.AccessLog_Entry_Common_Network{
							Downstream: &corev1.AccessLog_Entry_Common_Network_Endpoint{},
						},
					},
					Info: &corev1.AccessLog_Entry_Info{
						Type: &corev1.AccessLog_Entry_Info_Http{
							Http: &corev1.AccessLog_Entry_Info_HTTP{
								Request: &corev1.AccessLog_Entry_Info_HTTP_Request{
									Path:      "/üñí/😀",
									BodyBytes: math.MaxUint64,
									Body:      []byte{0xff, 0x00, 0x7f},
									Headers:   map[string]string{"x-b": "", "x-a": "1"},
									BodyMap: &structpb.Struct{Fields: map[string]*structpb.Value{
										"null":   structpb.NewNullValue(),
										"number": structpb.NewNumberValue(math.Copysign(0, -1)),
										"string": structpb.NewStringValue("value"),
										"bool":   structpb.NewBoolValue(false),
										"list": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
											structpb.NewNumberValue(1e21), structpb.NewNullValue(),
										}}),
										"emptyList":   structpb.NewListValue(&structpb.ListValue{}),
										"emptyStruct": structpb.NewStructValue(&structpb.Struct{}),
									}},
								},
								Response: &corev1.AccessLog_Entry_Info_HTTP_Response{
									Code:      200,
									BodyBytes: 1 << 53,
								},
								HttpVersion: corev1.AccessLog_Entry_Info_HTTP_HTTP11,
							},
						},
					},
				},
			},
			want: attribute.MapValue(
				attribute.String("apiVersion", "core/v1"),
				attribute.String("kind", "AccessLog"),
				attribute.Map("metadata",
					attribute.String("id", "id-1"),
					attribute.String("createdAt", "2023-11-14T22:13:20.120Z"),
					attribute.Map("actorRef",
						attribute.String("kind", "Session"),
						attribute.String("name", "s"),
					),
				),
				attribute.Map("entry",
					attribute.Map("common",
						attribute.String("startedAt", "0001-01-01T00:00:00Z"),
						attribute.String("endedAt", "9999-12-31T23:59:59.999999999Z"),
						attribute.String("status", "ALLOWED"),
						attribute.Float64("mode", 977),
						attribute.String("sequence", "-9223372036854775808"),
						attribute.Bool("isPublic", true),
						attribute.Map("network",
							attribute.Map("downstream"),
						),
					),
					attribute.Map("info",
						attribute.Map("http",
							attribute.Map("request",
								attribute.String("path", "/üñí/😀"),
								attribute.String("bodyBytes", "18446744073709551615"),
								attribute.String("body", "/wB/"),
								attribute.Map("headers",
									attribute.String("x-a", "1"),
									attribute.String("x-b", ""),
								),
								attribute.Map("bodyMap",
									attribute.KeyValue{Key: "null"},
									attribute.Float64("number", math.Copysign(0, -1)),
									attribute.String("string", "value"),
									attribute.Bool("bool", false),
									attribute.Slice("list", attribute.Float64Value(1e21), attribute.Value{}),
									attribute.Slice("emptyList"),
									attribute.Map("emptyStruct"),
								),
							),
							attribute.Map("response",
								attribute.Float64("code", 200),
								attribute.String("bodyBytes", "9007199254740992"),
							),
							attribute.String("httpVersion", "HTTP11"),
						),
					),
				),
			),
		},
		{
			in: &corev1.AccessLog{
				Metadata: &metav1.LogMetadata{CreatedAt: createdAt},
				Entry: &corev1.AccessLog_Entry{
					Info: &corev1.AccessLog_Entry_Info{
						Type: &corev1.AccessLog_Entry_Info_Llm{
							Llm: &corev1.AccessLog_Entry_Info_LLM{
								Type:            corev1.AccessLog_Entry_Info_LLM_Type(0),
								Stream:          false,
								MaxOutputTokens: 0,
								InputItemCount:  math.MaxUint32,
								Tools: &corev1.AccessLog_Entry_Info_LLM_Tools{
									Count:       2,
									Names:       []string{"b", "a", ""},
									CalledNames: []string{},
								},
								Guardrails: []*corev1.AccessLog_Entry_Info_LLM_Guardrail{
									{}, {Plugin: "g"},
								},
								SemanticCache: &corev1.AccessLog_Entry_Info_LLM_SemanticCache{
									Similarity: 0.1,
									IsStored:   true,
								},
								TimeToFirstToken: &metav1.Duration{
									Type: &metav1.Duration_Milliseconds{Milliseconds: 0},
								},
							},
						},
					},
				},
			},
			want: attribute.MapValue(
				attribute.Map("metadata",
					attribute.String("createdAt", "2023-11-14T22:13:20.120Z"),
				),
				attribute.Map("entry",
					attribute.Map("info",
						attribute.Map("llm",
							attribute.Float64("inputItemCount", math.MaxUint32),
							attribute.Map("tools",
								attribute.Float64("count", 2),
								attribute.Slice("names",
									attribute.StringValue("b"), attribute.StringValue("a"), attribute.StringValue("")),
							),
							attribute.Slice("guardrails",
								attribute.MapValue(), attribute.MapValue(attribute.String("plugin", "g"))),
							attribute.Map("semanticCache",
								attribute.Float64("similarity", 0.1),
								attribute.Bool("isStored", true),
							),
							attribute.Map("timeToFirstToken",
								attribute.Float64("milliseconds", 0),
							),
						),
					),
				),
			),
		},
		{
			in: &corev1.AccessLog{
				Entry: &corev1.AccessLog_Entry{
					Info: &corev1.AccessLog_Entry_Info{
						Type: &corev1.AccessLog_Entry_Info_Grpc{
							Grpc: &corev1.AccessLog_Entry_Info_GRPC{
								Status: math.MinInt32,
								Http:   &corev1.AccessLog_Entry_Info_HTTP{},
							},
						},
					},
				},
			},
			want: attribute.MapValue(
				attribute.Map("entry",
					attribute.Map("info",
						attribute.Map("grpc",
							attribute.Float64("status", math.MinInt32),
							attribute.Map("http"),
						),
					),
				),
			),
		},
	} {
		got, ok := convertProtoMessage(tc.in)
		require.True(t, ok)
		assert.Equal(t, tc.want, got)
		assert.Equal(t, convertValue(pbutils.MustConvertToMap(tc.in)), got)
		assert.Equal(t, getLegacyAccessLogBody(tc.in), got)
	}
}

func TestConvertProtoMessageFloat(t *testing.T) {
	for _, tc := range []struct {
		value float32
		want  attribute.Value
	}{
		{0.1, attribute.Float64Value(0.1)},
		{float32(math.Copysign(0, -1)), attribute.Float64Value(math.Copysign(0, -1))},
		{math.MaxFloat32, attribute.Float64Value(3.4028235e+38)},
		{math.SmallestNonzeroFloat32, attribute.Float64Value(1e-45)},
		{float32(math.NaN()), attribute.StringValue("NaN")},
		{float32(math.Inf(1)), attribute.StringValue("Infinity")},
		{float32(math.Inf(-1)), attribute.StringValue("-Infinity")},
	} {
		in := &corev1.AccessLog_Entry_Info_LLM_SemanticCache{Similarity: tc.value}
		got, ok := convertProtoMessage(in)
		require.True(t, ok)
		assert.Equal(t, attribute.MapValue(attribute.KeyValue{Key: "similarity", Value: tc.want}), got)
		assert.Equal(t, convertValue(pbutils.MustConvertToMap(in)), got)
	}

	for _, tc := range []struct {
		value float64
		want  attribute.Value
	}{
		{0.1, attribute.Float64Value(0.1)},
		{math.MaxFloat64, attribute.Float64Value(math.MaxFloat64)},
		{math.NaN(), attribute.StringValue("NaN")},
		{math.Inf(1), attribute.StringValue("Infinity")},
		{math.Inf(-1), attribute.StringValue("-Infinity")},
	} {
		in := wrapperspb.Double(tc.value)
		got, ok := convertMessage(in.ProtoReflect())
		require.True(t, ok)
		assert.Equal(t, tc.want, got)
	}
}

func TestConvertProtoMessageWellKnownTypes(t *testing.T) {
	for _, tc := range []struct {
		in   proto.Message
		want attribute.Value
	}{
		{wrapperspb.Bool(true), attribute.BoolValue(true)},
		{wrapperspb.Int32(-3), attribute.Float64Value(-3)},
		{wrapperspb.Int64(-3), attribute.StringValue("-3")},
		{wrapperspb.UInt32(3), attribute.Float64Value(3)},
		{wrapperspb.UInt64(3), attribute.StringValue("3")},
		{wrapperspb.Float(1.5), attribute.Float64Value(1.5)},
		{wrapperspb.String("value"), attribute.StringValue("value")},
		{wrapperspb.Bytes([]byte("value")), attribute.StringValue("dmFsdWU=")},
		{&timestamppb.Timestamp{Seconds: 1, Nanos: 1000}, attribute.StringValue("1970-01-01T00:00:01.000001Z")},
		{&timestamppb.Timestamp{Seconds: 1, Nanos: 1}, attribute.StringValue("1970-01-01T00:00:01.000000001Z")},
		{durationpb.New(1500 * time.Millisecond), attribute.StringValue("1.500s")},
		{durationpb.New(-time.Nanosecond), attribute.StringValue("-0.000000001s")},
		{&durationpb.Duration{Seconds: 315576000000}, attribute.StringValue("315576000000s")},
		{structpb.NewNullValue(), attribute.Value{}},
		{structpb.NewListValue(&structpb.ListValue{}), attribute.SliceValue()},
	} {
		got, ok := convertMessage(tc.in.ProtoReflect())
		require.True(t, ok, "%v", tc.in)
		assert.Equal(t, tc.want, got, "%v", tc.in)
	}

	for _, in := range []proto.Message{
		&timestamppb.Timestamp{Seconds: 253402300800},
		&timestamppb.Timestamp{Seconds: -62135596801},
		&timestamppb.Timestamp{Nanos: -1},
		&timestamppb.Timestamp{Nanos: 1000000000},
		&durationpb.Duration{Seconds: 315576000001},
		&durationpb.Duration{Seconds: 1, Nanos: -1},
		&durationpb.Duration{Seconds: -1, Nanos: 1},
		&durationpb.Duration{Nanos: 1000000000},
		&structpb.Value{},
		structpb.NewNumberValue(math.NaN()),
		structpb.NewNumberValue(math.Inf(1)),
		structpb.NewNumberValue(math.Inf(-1)),
		&anypb.Any{},
		&fieldmaskpb.FieldMask{},
	} {
		got, ok := convertMessage(in.ProtoReflect())
		assert.False(t, ok, "%v", in)
		assert.Equal(t, attribute.Value{}, got)
	}
}

func TestConvertProtoMessageUnsupported(t *testing.T) {
	got, ok := convertProtoMessage(nil)
	assert.True(t, ok)
	assert.Equal(t, attribute.MapValue(), got)

	got, ok = convertProtoMessage((*corev1.AccessLog)(nil))
	assert.True(t, ok)
	assert.Equal(t, attribute.MapValue(), got)
	assert.Equal(t, getLegacyAccessLogBody(nil), got)

	got, ok = convertProtoMessage(&emptypb.Empty{})
	assert.True(t, ok)
	assert.Equal(t, attribute.MapValue(), got)
	requireSameProtoMessage(t, &emptypb.Empty{})

	in, err := structpb.NewStruct(map[string]any{"a": []any{1, "b", nil, map[string]any{}}})
	require.NoError(t, err)
	requireSameProtoMessage(t, in)
	got, ok = convertProtoMessage(in)
	assert.True(t, ok)
	assert.Equal(t, attribute.MapValue(attribute.Slice("a",
		attribute.Float64Value(1), attribute.StringValue("b"), attribute.Value{}, attribute.MapValue())), got)

	option, err := anypb.New(durationpb.New(time.Second))
	require.NoError(t, err)

	for _, in := range []proto.Message{
		&timestamppb.Timestamp{Seconds: 1},
		durationpb.New(time.Second),
		wrapperspb.String("value"),
		structpb.NewStructValue(&structpb.Struct{}),
		&structpb.ListValue{},
		option,
		&fieldmaskpb.FieldMask{Paths: []string{"a"}},
		&typepb.Option{Name: "option", Value: option},
		&descriptorpb.UninterpretedOption_NamePart{},
		&descriptorpb.FileDescriptorProto{
			Options: &descriptorpb.FileOptions{
				UninterpretedOption: []*descriptorpb.UninterpretedOption{{
					Name: []*descriptorpb.UninterpretedOption_NamePart{{}},
				}},
			},
		},
	} {
		got, ok := convertProtoMessage(in)
		assert.False(t, ok, "%v", in)
		assert.Equal(t, attribute.Value{}, got)
		assert.False(t, requireSameProtoMessage(t, in))
	}
}

func TestConvertProtoMessageInvalid(t *testing.T) {
	newAccessLog := func(req *corev1.AccessLog_Entry_Info_HTTP_Request) *corev1.AccessLog {
		return &corev1.AccessLog{
			Metadata: &metav1.LogMetadata{
				CreatedAt: pbutils.Timestamp(time.Unix(1700000000, 0)),
			},
			Entry: &corev1.AccessLog_Entry{
				Info: &corev1.AccessLog_Entry_Info{
					Type: &corev1.AccessLog_Entry_Info_Http{
						Http: &corev1.AccessLog_Entry_Info_HTTP{
							Request: req,
						},
					},
				},
			},
		}
	}

	newBodyMap := func(fields map[string]*structpb.Value) *corev1.AccessLog {
		return newAccessLog(&corev1.AccessLog_Entry_Info_HTTP_Request{
			Path:    "/",
			BodyMap: &structpb.Struct{Fields: fields},
		})
	}

	for _, tc := range []struct {
		in          *corev1.AccessLog
		isRecovered bool
	}{
		{newAccessLog(&corev1.AccessLog_Entry_Info_HTTP_Request{Path: "/\xff"}), true},
		{newAccessLog(&corev1.AccessLog_Entry_Info_HTTP_Request{Headers: map[string]string{"a\xff": "b"}}), true},
		{newAccessLog(&corev1.AccessLog_Entry_Info_HTTP_Request{Headers: map[string]string{"a": "b\xff"}}), true},
		{newBodyMap(map[string]*structpb.Value{"a\xff": structpb.NewNullValue()}), true},
		{newBodyMap(map[string]*structpb.Value{"a": structpb.NewStringValue("b\xff")}), true},
		{newBodyMap(map[string]*structpb.Value{"a": {}}), false},
		{newBodyMap(map[string]*structpb.Value{"a": structpb.NewNumberValue(math.NaN())}), false},
		{newBodyMap(map[string]*structpb.Value{"a": structpb.NewNumberValue(math.Inf(1))}), false},
		{newBodyMap(map[string]*structpb.Value{"a": structpb.NewNumberValue(math.Inf(-1))}), false},
		{newBodyMap(map[string]*structpb.Value{"a": structpb.NewListValue(&structpb.ListValue{
			Values: []*structpb.Value{structpb.NewNullValue(), {}},
		})}), false},
		{&corev1.AccessLog{Metadata: &metav1.LogMetadata{CreatedAt: &timestamppb.Timestamp{Seconds: 253402300800}}}, false},
		{&corev1.AccessLog{Metadata: &metav1.LogMetadata{CreatedAt: &timestamppb.Timestamp{Nanos: -1}}}, false},
		{&corev1.AccessLog{
			Metadata: &metav1.LogMetadata{CreatedAt: &timestamppb.Timestamp{Seconds: 1}},
			Entry: &corev1.AccessLog_Entry{
				Info: &corev1.AccessLog_Entry_Info{
					Type: &corev1.AccessLog_Entry_Info_Llm{
						Llm: &corev1.AccessLog_Entry_Info_LLM{
							Tools: &corev1.AccessLog_Entry_Info_LLM_Tools{Names: []string{"a", "\xfe"}},
						},
					},
				},
			},
		}, true},
	} {
		original := pbutils.Clone(tc.in)

		got, ok := convertProtoMessage(tc.in)
		assert.False(t, ok)
		assert.Equal(t, attribute.Value{}, got)

		_, err := pbutils.ConvertToMap(tc.in)
		assert.Error(t, err)

		recovered := pbutils.Clone(tc.in).(*corev1.AccessLog)
		vutils.ReplaceInvalidUTF8(recovered)
		_, ok = convertProtoMessage(recovered)
		assert.Equal(t, tc.isRecovered, ok)
		if tc.isRecovered {
			assert.Equal(t, getLegacyAccessLogBody(tc.in), convertValue(pbutils.MustConvertToMap(recovered)))
		} else {
			assert.Equal(t, attribute.MapValue(), getLegacyAccessLogBody(tc.in))
		}

		assert.True(t, pbutils.IsEqual(original, tc.in))
	}
}

func TestConvertProtoMessageStruct(t *testing.T) {
	newAccessLog := func(bodyMap *structpb.Struct) *corev1.AccessLog {
		return &corev1.AccessLog{
			Metadata: &metav1.LogMetadata{
				CreatedAt: pbutils.Timestamp(time.Unix(1700000000, 0)),
			},
			Entry: &corev1.AccessLog_Entry{
				Info: &corev1.AccessLog_Entry_Info{
					Type: &corev1.AccessLog_Entry_Info_Http{
						Http: &corev1.AccessLog_Entry_Info_HTTP{
							Request: &corev1.AccessLog_Entry_Info_HTTP_Request{
								BodyMap: bodyMap,
							},
						},
					},
				},
			},
		}
	}

	for _, tc := range []struct {
		in   *structpb.Value
		want attribute.Value
		ok   bool
	}{
		{in: structpb.NewNullValue(), want: attribute.Value{}, ok: true},
		{in: &structpb.Value{Kind: &structpb.Value_NullValue{NullValue: 977}}, want: attribute.Value{}, ok: true},
		{in: structpb.NewNumberValue(math.Copysign(0, -1)), want: attribute.Float64Value(math.Copysign(0, -1)), ok: true},
		{in: structpb.NewNumberValue(math.MaxFloat64), want: attribute.Float64Value(math.MaxFloat64), ok: true},
		{in: structpb.NewStringValue("üñí"), want: attribute.StringValue("üñí"), ok: true},
		{in: structpb.NewBoolValue(true), want: attribute.BoolValue(true), ok: true},
		{in: &structpb.Value{Kind: &structpb.Value_StructValue{}}, want: attribute.MapValue(), ok: true},
		{in: &structpb.Value{Kind: &structpb.Value_ListValue{}}, want: attribute.SliceValue(), ok: true},
		{
			in: structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
				structpb.NewNullValue(),
				structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
					"b": structpb.NewListValue(&structpb.ListValue{}),
				}}),
			}}),
			want: attribute.SliceValue(attribute.Value{}, attribute.MapValue(attribute.Slice("b"))),
			ok:   true,
		},
		{in: nil},
		{in: &structpb.Value{}},
		{in: &structpb.Value{Kind: (*structpb.Value_NullValue)(nil)}},
		{in: &structpb.Value{Kind: (*structpb.Value_NumberValue)(nil)}},
		{in: &structpb.Value{Kind: (*structpb.Value_StringValue)(nil)}},
		{in: &structpb.Value{Kind: (*structpb.Value_BoolValue)(nil)}},
		{in: &structpb.Value{Kind: (*structpb.Value_StructValue)(nil)}},
		{in: &structpb.Value{Kind: (*structpb.Value_ListValue)(nil)}},
		{in: structpb.NewNumberValue(math.NaN())},
		{in: structpb.NewNumberValue(math.Inf(1))},
		{in: structpb.NewNumberValue(math.Inf(-1))},
		{in: structpb.NewStringValue("a\xff")},
		{in: structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{nil}})},
		{in: structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{structpb.NewNullValue(), {}}})},
		{in: structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{"b": nil}})},
		{in: structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
			"b\xff": structpb.NewNullValue(),
		}})},
	} {
		in := &structpb.Struct{Fields: map[string]*structpb.Value{"a": tc.in}}

		got, ok := convertProtoMessage(in)
		assert.Equal(t, tc.ok, ok, "%v", tc.in)
		assert.Equal(t, tc.ok, requireSameProtoMessage(t, in), "%v", tc.in)
		if tc.ok {
			assert.Equal(t, attribute.MapValue(attribute.KeyValue{Key: "a", Value: tc.want}), got)
		}

		accessLog := newAccessLog(in)
		assert.Equal(t, tc.ok, requireSameProtoMessage(t, accessLog), "%v", tc.in)
		got, ok = convertProtoMessage(accessLog)
		if ok {
			assert.Equal(t, getLegacyAccessLogBody(accessLog), got)
		}
	}

	r := &testRandom{Rand: rand.New(rand.NewPCG(20261127, 3)), maxDepth: 8}
	var nOK int
	for i := range 2000 {
		r.invalid = i%4 == 3
		in := &structpb.Struct{}
		r.populate(in.ProtoReflect(), 0)

		dyn := dynamicpb.NewMessage(in.ProtoReflect().Descriptor())
		proto.Merge(dyn, in)

		got, ok := convertMessage(in.ProtoReflect())
		want, wantOK := convertMessage(dyn)
		require.Equal(t, wantOK, ok)
		require.Equal(t, want, got)
		require.Equal(t, ok, requireSameProtoMessage(t, in))
		if ok {
			nOK++
		}
	}
	assert.Greater(t, nOK, 1000)
}

func TestConvertProtoMessageStructAllocs(t *testing.T) {
	in, err := structpb.NewStruct(map[string]any{
		"a": 1,
		"b": "value",
		"c": []any{true, nil, "d"},
	})
	require.NoError(t, err)

	m := in.ProtoReflect()
	fd := m.Descriptor().Fields().ByNumber(1)

	want, ok := convertMap(m.Get(fd).Map(), fd)
	require.True(t, ok)
	got, ok := convertMessage(m)
	require.True(t, ok)
	assert.Equal(t, want, got)

	directAllocs := testing.AllocsPerRun(100, func() {
		convertMessage(m)
	})
	reflectAllocs := testing.AllocsPerRun(100, func() {
		convertMap(m.Get(fd).Map(), fd)
	})
	assert.Less(t, directAllocs, reflectAllocs)
}

type testRandom struct {
	*rand.Rand
	invalid  bool
	maxDepth int
}

var testStrings = []string{
	"", "a", "hello world", "üñíçødé ✓", "  ", "<>&\"'\\", "\x00\x1f\x7f", "line\nbreak\ttab", "😀", "1e3",
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

func newTestAccessLog(r *testRandom) *corev1.AccessLog {
	ret := &corev1.AccessLog{}
	r.populate(ret.ProtoReflect(), 0)
	if ret.Metadata == nil {
		ret.Metadata = &metav1.LogMetadata{}
	}
	return ret
}

func TestConvertProtoMessageRandom(t *testing.T) {
	d := newTestDescriptors(t)
	r := &testRandom{Rand: rand.New(rand.NewPCG(20261127, 1))}

	type messageType struct {
		newMsg   func() protoreflect.Message
		samples  int
		maxDepth int
	}

	messageTypes := []messageType{
		{newMsg: func() protoreflect.Message { return dynamicpb.NewMessage(d.kinds) }, samples: 300, maxDepth: 2},
		{newMsg: func() protoreflect.Message {
			ret := dynamicpb.NewMessage(d.legacy)
			if r.IntN(2) == 0 {
				ret.Set(d.extString.TypeDescriptor(), protoreflect.ValueOfString(r.string()))
			}
			return ret
		}, samples: 500, maxDepth: 3},
	}

	infoFields := (&corev1.AccessLog_Entry_Info{}).ProtoReflect().Descriptor().Oneofs().ByName("type").Fields()
	for i := range infoFields.Len() {
		fd := infoFields.Get(i)
		messageTypes = append(messageTypes, messageType{newMsg: func() protoreflect.Message {
			ret := &corev1.AccessLog{
				Entry: &corev1.AccessLog_Entry{
					Info: &corev1.AccessLog_Entry_Info{},
				},
			}
			r.populate(ret.Entry.Info.ProtoReflect().Mutable(fd).Message(), 3)
			return ret.ProtoReflect()
		}, samples: 200, maxDepth: 10})
	}

	var globalTypes []protoreflect.MessageType
	protoregistry.GlobalTypes.RangeMessages(func(mt protoreflect.MessageType) bool {
		globalTypes = append(globalTypes, mt)
		return true
	})
	slices.SortFunc(globalTypes, func(a, b protoreflect.MessageType) int {
		return strings.Compare(string(a.Descriptor().FullName()), string(b.Descriptor().FullName()))
	})

	accessLogName := (&corev1.AccessLog{}).ProtoReflect().Descriptor().FullName()
	for _, mt := range globalTypes {
		switch {
		case mt.Descriptor().FullName() == accessLogName:
			messageTypes = append(messageTypes, messageType{newMsg: mt.New, samples: 4000, maxDepth: 10})
		case strings.HasPrefix(string(mt.Descriptor().FullName()), string(accessLogName)):
			messageTypes = append(messageTypes, messageType{newMsg: mt.New, samples: 100, maxDepth: 6})
		default:
			messageTypes = append(messageTypes, messageType{newMsg: mt.New, samples: 20, maxDepth: 3})
		}
	}

	var nOK, nInvalid, nAccessLog int

	for _, itm := range messageTypes {
		r.maxDepth = itm.maxDepth
		for i := range itm.samples {
			r.invalid = i%4 == 3
			m := itm.newMsg()
			r.populate(m, 0)

			if requireSameProtoMessage(t, m.Interface()) {
				nOK++
			} else {
				nInvalid++
			}

			if in, ok := m.Interface().(*corev1.AccessLog); ok {
				nAccessLog++
				_, ok := convertProtoMessage(in)
				_, err := pbutils.ConvertToMap(in)
				require.Equal(t, ok, err == nil)
			}
		}
	}

	t.Logf("types: %d, identical values: %d, unsupported: %d", len(messageTypes), nOK, nInvalid)
	assert.Greater(t, nOK, 4*nInvalid)
	assert.Equal(t, 4000+200*infoFields.Len(), nAccessLog)
}

func FuzzConvertProtoMessage(f *testing.F) {
	r := &testRandom{Rand: rand.New(rand.NewPCG(1, 2)), maxDepth: 10}
	for range 8 {
		in, err := proto.Marshal(newTestAccessLog(r))
		require.NoError(f, err)
		f.Add(in)
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		m := &corev1.AccessLog{}
		if err := proto.Unmarshal(in, m); err != nil {
			return
		}

		requireSameProtoMessage(t, m)
		_, ok := convertProtoMessage(m)
		_, err := pbutils.ConvertToMap(m)
		require.Equal(t, ok, err == nil)
	})
}

func TestConvertProtoMessageJSONNames(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	var check func(md protoreflect.MessageDescriptor)
	check = func(md protoreflect.MessageDescriptor) {
		if seen[md.FullName()] {
			return
		}
		seen[md.FullName()] = true

		names := map[string]bool{}
		for i := range md.Fields().Len() {
			fd := md.Fields().Get(i)
			assert.False(t, names[fd.JSONName()], "%s", fd.FullName())
			names[fd.JSONName()] = true

			switch {
			case fd.IsMap():
				if fd.MapValue().Message() != nil {
					check(fd.MapValue().Message())
				}
			case fd.Message() != nil:
				check(fd.Message())
			}
		}
	}

	check((&corev1.AccessLog{}).ProtoReflect().Descriptor())
	assert.Greater(t, len(seen), 50)
}
