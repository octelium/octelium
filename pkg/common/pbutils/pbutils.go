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
	"time"

	"encoding/json"

	"github.com/ghodss/yaml"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Message = proto.Message
type Struct = structpb.Struct

func Unmarshal(b []byte, m proto.Message) error {
	return proto.Unmarshal(b, m)
}

func Marshal(m proto.Message) ([]byte, error) {
	return proto.Marshal(m)
}

func Clone(m proto.Message) proto.Message {
	return proto.Clone(m)
}

func MarshalMust(m proto.Message) []byte {
	ret, _ := proto.Marshal(m)

	return ret
}

func UnmarshalYAML(in []byte, out proto.Message) error {
	jsonBytes, err := yaml.YAMLToJSON(in)
	if err != nil {
		return err
	}
	return protojson.Unmarshal(jsonBytes, out)
}

func UnmarshalJSON(in []byte, out proto.Message) error {
	return protojson.Unmarshal(in, out)
}

func MarshalJSON(in proto.Message, indent bool) ([]byte, error) {

	m := protojson.MarshalOptions{}
	if indent {
		m.Indent = "    "
		m.Multiline = true
	}

	return m.Marshal(in)
}

func MarshalYAML(in proto.Message) ([]byte, error) {

	m := protojson.MarshalOptions{}
	jsonBytes, err := m.Marshal(in)
	if err != nil {
		return nil, err
	}

	return yaml.JSONToYAML(jsonBytes)
}

func MarshalInto(out proto.Message, in proto.Message) error {
	jsonBytes, err := MarshalJSON(in, false)
	if err != nil {
		return err
	}
	return UnmarshalJSON(jsonBytes, out)
}

func IsEqual(x proto.Message, y proto.Message) bool {
	return proto.Equal(x, y)
}

func ConvertToMap(in proto.Message) (map[string]any, error) {
	ret := make(map[string]any)
	jsonBytes, err := MarshalJSON(in, false)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(jsonBytes, &ret); err != nil {
		return nil, err
	}
	return ret, nil
}

func MustConvertToMap(in proto.Message) map[string]any {
	if in == nil {
		return nil
	}

	ret, _ := ConvertToMap(in)

	return ret
}

func UnmarshalFromMap(in map[string]any, out proto.Message) error {
	jsonBytes, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return UnmarshalJSON(jsonBytes, out)
}

func MessageToStruct(in proto.Message) (*structpb.Struct, error) {
	msgMap, err := ConvertToMap(in)
	if err != nil {
		return nil, err
	}
	return structpb.NewStruct(msgMap)
}

func MessageToStructMust(in proto.Message) *structpb.Struct {
	ret, _ := MessageToStruct(in)
	return ret
}

func StructToMessage(in *structpb.Struct, out proto.Message) error {
	msgMap, err := ConvertToMap(in)
	if err != nil {
		return err
	}
	if err := UnmarshalFromMap(msgMap, out); err != nil {
		return err
	}

	return nil
}

func MapToStruct(in map[string]any) (*structpb.Struct, error) {
	return structpb.NewStruct(in)
}

func MapToStructMust(in map[string]any) *structpb.Struct {
	out, _ := structpb.NewStruct(in)

	return out
}

func MessageToAny(in proto.Message) (*anypb.Any, error) {
	return anypb.New(in)
}

func MessageToAnyMust(in proto.Message) *anypb.Any {
	ret, _ := anypb.New(in)
	return ret
}

func AnyToMessage(in *anypb.Any, out proto.Message) error {
	if err := anypb.UnmarshalTo(in, out, proto.UnmarshalOptions{}); err != nil {
		return err
	}

	return nil
}

func Now() *timestamppb.Timestamp {
	return timestamppb.Now()
}

func Timestamp(t time.Time) *timestamppb.Timestamp {
	return timestamppb.New(t)
}
