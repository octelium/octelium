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
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	minTimestampSeconds = -62135596800
	maxTimestampSeconds = 253402300799
	maxDurationSeconds  = 315576000000
	maxNanos            = 999999999
)

type wellKnownType int

const (
	wellKnownTypeNone wellKnownType = iota
	wellKnownTypeTimestamp
	wellKnownTypeDuration
	wellKnownTypeWrapper
	wellKnownTypeStruct
	wellKnownTypeListValue
	wellKnownTypeValue
	wellKnownTypeUnsupported
)

func getWellKnownType(name protoreflect.FullName) wellKnownType {
	if name.Parent() != "google.protobuf" {
		return wellKnownTypeNone
	}

	switch name.Name() {
	case "Timestamp":
		return wellKnownTypeTimestamp
	case "Duration":
		return wellKnownTypeDuration
	case "BoolValue", "Int32Value", "Int64Value", "UInt32Value", "UInt64Value",
		"FloatValue", "DoubleValue", "StringValue", "BytesValue":
		return wellKnownTypeWrapper
	case "Struct":
		return wellKnownTypeStruct
	case "ListValue":
		return wellKnownTypeListValue
	case "Value":
		return wellKnownTypeValue
	case "Any", "FieldMask":
		return wellKnownTypeUnsupported
	default:
		return wellKnownTypeNone
	}
}

func convertProtoMessage(in proto.Message) (attribute.Value, bool) {
	if in == nil {
		return attribute.MapValue(), true
	}

	m := in.ProtoReflect()

	switch getWellKnownType(m.Descriptor().FullName()) {
	case wellKnownTypeNone, wellKnownTypeStruct:
	default:
		return attribute.Value{}, false
	}

	if proto.CheckInitialized(in) != nil {
		return attribute.Value{}, false
	}

	return convertMessage(m)
}

func convertMessage(m protoreflect.Message) (attribute.Value, bool) {
	md := m.Descriptor()

	switch getWellKnownType(md.FullName()) {
	case wellKnownTypeTimestamp:
		return convertTimestamp(m)
	case wellKnownTypeDuration:
		return convertDuration(m)
	case wellKnownTypeWrapper:
		fd := md.Fields().ByNumber(1)
		return convertSingular(m.Get(fd), fd)
	case wellKnownTypeStruct:
		if s, ok := m.Interface().(*structpb.Struct); ok {
			return convertStruct(s)
		}
		fd := md.Fields().ByNumber(1)
		return convertMap(m.Get(fd).Map(), fd)
	case wellKnownTypeListValue:
		fd := md.Fields().ByNumber(1)
		return convertList(m.Get(fd).List(), fd)
	case wellKnownTypeValue:
		return convertStructValue(m)
	case wellKnownTypeUnsupported:
		return attribute.Value{}, false
	}

	kvs := make([]attribute.KeyValue, 0, md.Fields().Len())
	ok := true

	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		var val attribute.Value
		switch {
		case fd.IsList():
			val, ok = convertList(v.List(), fd)
		case fd.IsMap():
			val, ok = convertMap(v.Map(), fd)
		default:
			val, ok = convertSingular(v, fd)
		}

		if ok {
			kvs = append(kvs, attribute.KeyValue{
				Key:   attribute.Key(fd.JSONName()),
				Value: val,
			})
		}

		return ok
	})

	if !ok {
		return attribute.Value{}, false
	}

	return attribute.MapValue(kvs...), true
}

func convertList(l protoreflect.List, fd protoreflect.FieldDescriptor) (attribute.Value, bool) {
	ret := make([]attribute.Value, l.Len())

	for i := range ret {
		val, ok := convertSingular(l.Get(i), fd)
		if !ok {
			return attribute.Value{}, false
		}
		ret[i] = val
	}

	return attribute.SliceValue(ret...), true
}

func convertMap(mp protoreflect.Map, fd protoreflect.FieldDescriptor) (attribute.Value, bool) {
	kvs := make([]attribute.KeyValue, 0, mp.Len())
	valueFD := fd.MapValue()
	ok := true

	mp.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
		key := k.String()
		if !utf8.ValidString(key) {
			ok = false
			return false
		}

		var val attribute.Value
		if val, ok = convertSingular(v, valueFD); ok {
			kvs = append(kvs, attribute.KeyValue{
				Key:   attribute.Key(key),
				Value: val,
			})
		}

		return ok
	})

	if !ok {
		return attribute.Value{}, false
	}

	return attribute.MapValue(kvs...), true
}

func convertSingular(v protoreflect.Value, fd protoreflect.FieldDescriptor) (attribute.Value, bool) {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return attribute.BoolValue(v.Bool()), true
	case protoreflect.StringKind:
		ret := v.String()
		if !utf8.ValidString(ret) {
			return attribute.Value{}, false
		}
		return attribute.StringValue(ret), true
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return attribute.Float64Value(float64(v.Int())), true
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return attribute.Float64Value(float64(v.Uint())), true
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return attribute.StringValue(strconv.FormatInt(v.Int(), 10)), true
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return attribute.StringValue(strconv.FormatUint(v.Uint(), 10)), true
	case protoreflect.FloatKind:
		return convertFloat(v.Float(), 32), true
	case protoreflect.DoubleKind:
		return convertFloat(v.Float(), 64), true
	case protoreflect.BytesKind:
		return attribute.StringValue(base64.StdEncoding.EncodeToString(v.Bytes())), true
	case protoreflect.EnumKind:
		return convertEnum(v.Enum(), fd.Enum()), true
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return convertMessage(v.Message())
	default:
		return attribute.Value{}, false
	}
}

func convertEnum(n protoreflect.EnumNumber, ed protoreflect.EnumDescriptor) attribute.Value {
	if ed.FullName() == "google.protobuf.NullValue" {
		return attribute.Value{}
	}

	if vd := ed.Values().ByNumber(n); vd != nil {
		return attribute.StringValue(string(vd.Name()))
	}

	return attribute.Float64Value(float64(n))
}

func convertFloat(v float64, bitSize int) attribute.Value {
	switch {
	case math.IsNaN(v):
		return attribute.StringValue("NaN")
	case math.IsInf(v, 1):
		return attribute.StringValue("Infinity")
	case math.IsInf(v, -1):
		return attribute.StringValue("-Infinity")
	case bitSize == 32:
		ret, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'g', -1, 32), 64)
		return attribute.Float64Value(ret)
	default:
		return attribute.Float64Value(v)
	}
}

func convertStructValue(m protoreflect.Message) (attribute.Value, bool) {
	fd := m.WhichOneof(m.Descriptor().Oneofs().ByName("kind"))
	if fd == nil {
		return attribute.Value{}, false
	}

	v := m.Get(fd)
	if fd.Number() == 2 && (math.IsNaN(v.Float()) || math.IsInf(v.Float(), 0)) {
		return attribute.Value{}, false
	}

	return convertSingular(v, fd)
}

func convertStruct(s *structpb.Struct) (attribute.Value, bool) {
	kvs := make([]attribute.KeyValue, 0, len(s.GetFields()))

	for k, v := range s.GetFields() {
		if !utf8.ValidString(k) {
			return attribute.Value{}, false
		}

		val, ok := convertStructPBValue(v)
		if !ok {
			return attribute.Value{}, false
		}

		kvs = append(kvs, attribute.KeyValue{
			Key:   attribute.Key(k),
			Value: val,
		})
	}

	return attribute.MapValue(kvs...), true
}

func convertStructPBValue(v *structpb.Value) (attribute.Value, bool) {
	switch k := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		if k != nil {
			return attribute.Value{}, true
		}
	case *structpb.Value_NumberValue:
		if k != nil && !math.IsNaN(k.NumberValue) && !math.IsInf(k.NumberValue, 0) {
			return attribute.Float64Value(k.NumberValue), true
		}
	case *structpb.Value_StringValue:
		if k != nil && utf8.ValidString(k.StringValue) {
			return attribute.StringValue(k.StringValue), true
		}
	case *structpb.Value_BoolValue:
		if k != nil {
			return attribute.BoolValue(k.BoolValue), true
		}
	case *structpb.Value_StructValue:
		if k != nil {
			return convertStruct(k.StructValue)
		}
	case *structpb.Value_ListValue:
		if k != nil {
			ret := make([]attribute.Value, len(k.ListValue.GetValues()))
			for i, itm := range k.ListValue.GetValues() {
				val, ok := convertStructPBValue(itm)
				if !ok {
					return attribute.Value{}, false
				}
				ret[i] = val
			}
			return attribute.SliceValue(ret...), true
		}
	}

	return attribute.Value{}, false
}

func convertTimestamp(m protoreflect.Message) (attribute.Value, bool) {
	fds := m.Descriptor().Fields()
	secs := m.Get(fds.ByNumber(1)).Int()
	nanos := m.Get(fds.ByNumber(2)).Int()

	if secs < minTimestampSeconds || secs > maxTimestampSeconds || nanos < 0 || nanos > maxNanos {
		return attribute.Value{}, false
	}

	ret := time.Unix(secs, nanos).UTC().Format("2006-01-02T15:04:05.000000000")

	return attribute.StringValue(trimFraction(ret) + "Z"), true
}

func convertDuration(m protoreflect.Message) (attribute.Value, bool) {
	fds := m.Descriptor().Fields()
	secs := m.Get(fds.ByNumber(1)).Int()
	nanos := m.Get(fds.ByNumber(2)).Int()

	if secs < -maxDurationSeconds || secs > maxDurationSeconds ||
		nanos < -maxNanos || nanos > maxNanos ||
		(secs > 0 && nanos < 0) || (secs < 0 && nanos > 0) {
		return attribute.Value{}, false
	}

	var sign string
	if secs < 0 || nanos < 0 {
		sign, secs, nanos = "-", -secs, -nanos
	}

	return attribute.StringValue(trimFraction(fmt.Sprintf("%s%d.%09d", sign, secs, nanos)) + "s"), true
}

func trimFraction(in string) string {
	ret := strings.TrimSuffix(in, "000")
	ret = strings.TrimSuffix(ret, "000")
	return strings.TrimSuffix(ret, ".000")
}
