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
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
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

func convertToMap(in proto.Message) (map[string]any, bool) {
	if in == nil {
		return map[string]any{}, true
	}

	m := in.ProtoReflect()

	switch getWellKnownType(m.Descriptor().FullName()) {
	case wellKnownTypeNone, wellKnownTypeStruct:
	default:
		return nil, false
	}

	if proto.CheckInitialized(in) != nil {
		return nil, false
	}

	ret, ok := convertMessage(m)
	if !ok {
		return nil, false
	}

	return ret.(map[string]any), true
}

func convertMessage(m protoreflect.Message) (any, bool) {
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
		fd := md.Fields().ByNumber(1)
		return convertMap(m.Get(fd).Map(), fd)
	case wellKnownTypeListValue:
		fd := md.Fields().ByNumber(1)
		return convertList(m.Get(fd).List(), fd)
	case wellKnownTypeValue:
		return convertValue(m)
	case wellKnownTypeUnsupported:
		return nil, false
	}

	ret := make(map[string]any)
	ok := true

	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		var val any
		switch {
		case fd.IsList():
			val, ok = convertList(v.List(), fd)
		case fd.IsMap():
			val, ok = convertMap(v.Map(), fd)
		default:
			val, ok = convertSingular(v, fd)
		}

		if ok {
			ret[fd.JSONName()] = val
		}

		return ok
	})

	if !ok {
		return nil, false
	}

	return ret, true
}

func convertList(l protoreflect.List, fd protoreflect.FieldDescriptor) (any, bool) {
	ret := make([]any, l.Len())

	for i := range ret {
		val, ok := convertSingular(l.Get(i), fd)
		if !ok {
			return nil, false
		}
		ret[i] = val
	}

	return ret, true
}

func convertMap(mp protoreflect.Map, fd protoreflect.FieldDescriptor) (any, bool) {
	ret := make(map[string]any, mp.Len())
	valueFD := fd.MapValue()
	ok := true

	mp.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
		key := k.String()
		if !utf8.ValidString(key) {
			ok = false
			return false
		}

		var val any
		if val, ok = convertSingular(v, valueFD); ok {
			ret[key] = val
		}

		return ok
	})

	if !ok {
		return nil, false
	}

	return ret, true
}

func convertSingular(v protoreflect.Value, fd protoreflect.FieldDescriptor) (any, bool) {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return v.Bool(), true
	case protoreflect.StringKind:
		ret := v.String()
		if !utf8.ValidString(ret) {
			return nil, false
		}
		return ret, true
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return float64(v.Int()), true
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return float64(v.Uint()), true
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return strconv.FormatInt(v.Int(), 10), true
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return strconv.FormatUint(v.Uint(), 10), true
	case protoreflect.FloatKind:
		return convertFloat(v.Float(), 32), true
	case protoreflect.DoubleKind:
		return convertFloat(v.Float(), 64), true
	case protoreflect.BytesKind:
		return base64.StdEncoding.EncodeToString(v.Bytes()), true
	case protoreflect.EnumKind:
		return convertEnum(v.Enum(), fd.Enum()), true
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return convertMessage(v.Message())
	default:
		return nil, false
	}
}

func convertEnum(n protoreflect.EnumNumber, ed protoreflect.EnumDescriptor) any {
	if ed.FullName() == "google.protobuf.NullValue" {
		return nil
	}

	if vd := ed.Values().ByNumber(n); vd != nil {
		return string(vd.Name())
	}

	return float64(n)
}

func convertFloat(v float64, bitSize int) any {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "Infinity"
	case math.IsInf(v, -1):
		return "-Infinity"
	case bitSize == 32:
		ret, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'g', -1, 32), 64)
		return ret
	default:
		return v
	}
}

func convertValue(m protoreflect.Message) (any, bool) {
	fd := m.WhichOneof(m.Descriptor().Oneofs().ByName("kind"))
	if fd == nil {
		return nil, false
	}

	v := m.Get(fd)
	if fd.Number() == 2 && (math.IsNaN(v.Float()) || math.IsInf(v.Float(), 0)) {
		return nil, false
	}

	return convertSingular(v, fd)
}

func convertTimestamp(m protoreflect.Message) (any, bool) {
	fds := m.Descriptor().Fields()
	secs := m.Get(fds.ByNumber(1)).Int()
	nanos := m.Get(fds.ByNumber(2)).Int()

	if secs < minTimestampSeconds || secs > maxTimestampSeconds || nanos < 0 || nanos > maxNanos {
		return nil, false
	}

	ret := time.Unix(secs, nanos).UTC().Format("2006-01-02T15:04:05.000000000")

	return trimFraction(ret) + "Z", true
}

func convertDuration(m protoreflect.Message) (any, bool) {
	fds := m.Descriptor().Fields()
	secs := m.Get(fds.ByNumber(1)).Int()
	nanos := m.Get(fds.ByNumber(2)).Int()

	if secs < -maxDurationSeconds || secs > maxDurationSeconds ||
		nanos < -maxNanos || nanos > maxNanos ||
		(secs > 0 && nanos < 0) || (secs < 0 && nanos > 0) {
		return nil, false
	}

	var sign string
	if secs < 0 || nanos < 0 {
		sign, secs, nanos = "-", -secs, -nanos
	}

	return trimFraction(fmt.Sprintf("%s%d.%09d", sign, secs, nanos)) + "s", true
}

func trimFraction(in string) string {
	ret := strings.TrimSuffix(in, "000")
	ret = strings.TrimSuffix(ret, "000")
	return strings.TrimSuffix(ret, ".000")
}
