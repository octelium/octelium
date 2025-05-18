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

package rcachev1

import (
	metav1 "github.com/octelium/octelium/apis/main/metav1"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SetCacheRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Key           []byte                 `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Data          []byte                 `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	Duration      *metav1.Duration       `protobuf:"bytes,3,opt,name=duration,proto3" json:"duration,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SetCacheRequest) Reset() {
	*x = SetCacheRequest{}
	mi := &file_rcachev1_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SetCacheRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SetCacheRequest) ProtoMessage() {}

func (x *SetCacheRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rcachev1_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SetCacheRequest.ProtoReflect.Descriptor instead.
func (*SetCacheRequest) Descriptor() ([]byte, []int) {
	return file_rcachev1_proto_rawDescGZIP(), []int{0}
}

func (x *SetCacheRequest) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *SetCacheRequest) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *SetCacheRequest) GetDuration() *metav1.Duration {
	if x != nil {
		return x.Duration
	}
	return nil
}

type SetCacheResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SetCacheResponse) Reset() {
	*x = SetCacheResponse{}
	mi := &file_rcachev1_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SetCacheResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SetCacheResponse) ProtoMessage() {}

func (x *SetCacheResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rcachev1_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SetCacheResponse.ProtoReflect.Descriptor instead.
func (*SetCacheResponse) Descriptor() ([]byte, []int) {
	return file_rcachev1_proto_rawDescGZIP(), []int{1}
}

type GetCacheRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Key           []byte                 `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	Delete        bool                   `protobuf:"varint,2,opt,name=delete,proto3" json:"delete,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetCacheRequest) Reset() {
	*x = GetCacheRequest{}
	mi := &file_rcachev1_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetCacheRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCacheRequest) ProtoMessage() {}

func (x *GetCacheRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rcachev1_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCacheRequest.ProtoReflect.Descriptor instead.
func (*GetCacheRequest) Descriptor() ([]byte, []int) {
	return file_rcachev1_proto_rawDescGZIP(), []int{2}
}

func (x *GetCacheRequest) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *GetCacheRequest) GetDelete() bool {
	if x != nil {
		return x.Delete
	}
	return false
}

type GetCacheResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Data          []byte                 `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GetCacheResponse) Reset() {
	*x = GetCacheResponse{}
	mi := &file_rcachev1_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GetCacheResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCacheResponse) ProtoMessage() {}

func (x *GetCacheResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rcachev1_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCacheResponse.ProtoReflect.Descriptor instead.
func (*GetCacheResponse) Descriptor() ([]byte, []int) {
	return file_rcachev1_proto_rawDescGZIP(), []int{3}
}

func (x *GetCacheResponse) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

type DeleteCacheRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Key           []byte                 `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DeleteCacheRequest) Reset() {
	*x = DeleteCacheRequest{}
	mi := &file_rcachev1_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DeleteCacheRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteCacheRequest) ProtoMessage() {}

func (x *DeleteCacheRequest) ProtoReflect() protoreflect.Message {
	mi := &file_rcachev1_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteCacheRequest.ProtoReflect.Descriptor instead.
func (*DeleteCacheRequest) Descriptor() ([]byte, []int) {
	return file_rcachev1_proto_rawDescGZIP(), []int{4}
}

func (x *DeleteCacheRequest) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

type DeleteCacheResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DeleteCacheResponse) Reset() {
	*x = DeleteCacheResponse{}
	mi := &file_rcachev1_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DeleteCacheResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteCacheResponse) ProtoMessage() {}

func (x *DeleteCacheResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rcachev1_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteCacheResponse.ProtoReflect.Descriptor instead.
func (*DeleteCacheResponse) Descriptor() ([]byte, []int) {
	return file_rcachev1_proto_rawDescGZIP(), []int{5}
}

var File_rcachev1_proto protoreflect.FileDescriptor

var file_rcachev1_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x72, 0x63, 0x61, 0x63, 0x68, 0x65, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x19, 0x6f, 0x63, 0x74, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72,
	0x73, 0x63, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x26, 0x61, 0x70, 0x69,
	0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x6d, 0x61, 0x69, 0x6e, 0x2f,
	0x6d, 0x65, 0x74, 0x61, 0x76, 0x31, 0x2f, 0x6d, 0x65, 0x74, 0x61, 0x76, 0x31, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x78, 0x0a, 0x0f, 0x53, 0x65, 0x74, 0x43, 0x61, 0x63, 0x68, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x3f, 0x0a, 0x08,
	0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x23,
	0x2e, 0x6f, 0x63, 0x74, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x6d, 0x61,
	0x69, 0x6e, 0x2e, 0x6d, 0x65, 0x74, 0x61, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x12, 0x0a,
	0x10, 0x53, 0x65, 0x74, 0x43, 0x61, 0x63, 0x68, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x3b, 0x0a, 0x0f, 0x47, 0x65, 0x74, 0x43, 0x61, 0x63, 0x68, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x16, 0x0a, 0x06, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x06, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x22, 0x26,
	0x0a, 0x10, 0x47, 0x65, 0x74, 0x43, 0x61, 0x63, 0x68, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0x26, 0x0a, 0x12, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x43, 0x61, 0x63, 0x68, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03,
	0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x22, 0x15,
	0x0a, 0x13, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x61, 0x63, 0x68, 0x65, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0xcb, 0x02, 0x0a, 0x0b, 0x4d, 0x61, 0x69, 0x6e, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x65, 0x0a, 0x08, 0x53, 0x65, 0x74, 0x43, 0x61, 0x63, 0x68,
	0x65, 0x12, 0x2a, 0x2e, 0x6f, 0x63, 0x74, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x72, 0x73, 0x63, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65,
	0x74, 0x43, 0x61, 0x63, 0x68, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2b, 0x2e,
	0x6f, 0x63, 0x74, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x73, 0x63,
	0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65, 0x74, 0x43, 0x61, 0x63,
	0x68, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x65, 0x0a, 0x08,
	0x47, 0x65, 0x74, 0x43, 0x61, 0x63, 0x68, 0x65, 0x12, 0x2a, 0x2e, 0x6f, 0x63, 0x74, 0x65, 0x6c,
	0x69, 0x75, 0x6d, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x72, 0x73, 0x63, 0x2e, 0x63, 0x61, 0x63, 0x68,
	0x65, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x61, 0x63, 0x68, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x2b, 0x2e, 0x6f, 0x63, 0x74, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x72, 0x73, 0x63, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x76, 0x31,
	0x2e, 0x47, 0x65, 0x74, 0x43, 0x61, 0x63, 0x68, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x00, 0x12, 0x6e, 0x0a, 0x0b, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x61, 0x63,
	0x68, 0x65, 0x12, 0x2d, 0x2e, 0x6f, 0x63, 0x74, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x72, 0x73, 0x63, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x44,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x61, 0x63, 0x68, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x2e, 0x2e, 0x6f, 0x63, 0x74, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2e, 0x61, 0x70, 0x69,
	0x2e, 0x72, 0x73, 0x63, 0x2e, 0x63, 0x61, 0x63, 0x68, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x43, 0x61, 0x63, 0x68, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x00, 0x42, 0x30, 0x5a, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x6f, 0x63, 0x74, 0x65, 0x6c, 0x69, 0x75, 0x6d, 0x2f, 0x6f, 0x63, 0x74, 0x65, 0x6c,
	0x69, 0x75, 0x6d, 0x2f, 0x61, 0x70, 0x69, 0x73, 0x2f, 0x72, 0x73, 0x63, 0x2f, 0x72, 0x63, 0x61,
	0x63, 0x68, 0x65, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_rcachev1_proto_rawDescOnce sync.Once
	file_rcachev1_proto_rawDescData = file_rcachev1_proto_rawDesc
)

func file_rcachev1_proto_rawDescGZIP() []byte {
	file_rcachev1_proto_rawDescOnce.Do(func() {
		file_rcachev1_proto_rawDescData = protoimpl.X.CompressGZIP(file_rcachev1_proto_rawDescData)
	})
	return file_rcachev1_proto_rawDescData
}

var file_rcachev1_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_rcachev1_proto_goTypes = []any{
	(*SetCacheRequest)(nil),     // 0: octelium.api.rsc.cache.v1.SetCacheRequest
	(*SetCacheResponse)(nil),    // 1: octelium.api.rsc.cache.v1.SetCacheResponse
	(*GetCacheRequest)(nil),     // 2: octelium.api.rsc.cache.v1.GetCacheRequest
	(*GetCacheResponse)(nil),    // 3: octelium.api.rsc.cache.v1.GetCacheResponse
	(*DeleteCacheRequest)(nil),  // 4: octelium.api.rsc.cache.v1.DeleteCacheRequest
	(*DeleteCacheResponse)(nil), // 5: octelium.api.rsc.cache.v1.DeleteCacheResponse
	(*metav1.Duration)(nil),     // 6: octelium.api.main.meta.v1.Duration
}
var file_rcachev1_proto_depIdxs = []int32{
	6, // 0: octelium.api.rsc.cache.v1.SetCacheRequest.duration:type_name -> octelium.api.main.meta.v1.Duration
	0, // 1: octelium.api.rsc.cache.v1.MainService.SetCache:input_type -> octelium.api.rsc.cache.v1.SetCacheRequest
	2, // 2: octelium.api.rsc.cache.v1.MainService.GetCache:input_type -> octelium.api.rsc.cache.v1.GetCacheRequest
	4, // 3: octelium.api.rsc.cache.v1.MainService.DeleteCache:input_type -> octelium.api.rsc.cache.v1.DeleteCacheRequest
	1, // 4: octelium.api.rsc.cache.v1.MainService.SetCache:output_type -> octelium.api.rsc.cache.v1.SetCacheResponse
	3, // 5: octelium.api.rsc.cache.v1.MainService.GetCache:output_type -> octelium.api.rsc.cache.v1.GetCacheResponse
	5, // 6: octelium.api.rsc.cache.v1.MainService.DeleteCache:output_type -> octelium.api.rsc.cache.v1.DeleteCacheResponse
	4, // [4:7] is the sub-list for method output_type
	1, // [1:4] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_rcachev1_proto_init() }
func file_rcachev1_proto_init() {
	if File_rcachev1_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_rcachev1_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_rcachev1_proto_goTypes,
		DependencyIndexes: file_rcachev1_proto_depIdxs,
		MessageInfos:      file_rcachev1_proto_msgTypes,
	}.Build()
	File_rcachev1_proto = out.File
	file_rcachev1_proto_rawDesc = nil
	file_rcachev1_proto_goTypes = nil
	file_rcachev1_proto_depIdxs = nil
}
