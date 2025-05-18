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
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	MainService_SetCache_FullMethodName    = "/octelium.api.rsc.cache.v1.MainService/SetCache"
	MainService_GetCache_FullMethodName    = "/octelium.api.rsc.cache.v1.MainService/GetCache"
	MainService_DeleteCache_FullMethodName = "/octelium.api.rsc.cache.v1.MainService/DeleteCache"
)

// MainServiceClient is the client API for MainService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MainServiceClient interface {
	SetCache(ctx context.Context, in *SetCacheRequest, opts ...grpc.CallOption) (*SetCacheResponse, error)
	GetCache(ctx context.Context, in *GetCacheRequest, opts ...grpc.CallOption) (*GetCacheResponse, error)
	DeleteCache(ctx context.Context, in *DeleteCacheRequest, opts ...grpc.CallOption) (*DeleteCacheResponse, error)
}

type mainServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewMainServiceClient(cc grpc.ClientConnInterface) MainServiceClient {
	return &mainServiceClient{cc}
}

func (c *mainServiceClient) SetCache(ctx context.Context, in *SetCacheRequest, opts ...grpc.CallOption) (*SetCacheResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SetCacheResponse)
	err := c.cc.Invoke(ctx, MainService_SetCache_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mainServiceClient) GetCache(ctx context.Context, in *GetCacheRequest, opts ...grpc.CallOption) (*GetCacheResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetCacheResponse)
	err := c.cc.Invoke(ctx, MainService_GetCache_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mainServiceClient) DeleteCache(ctx context.Context, in *DeleteCacheRequest, opts ...grpc.CallOption) (*DeleteCacheResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeleteCacheResponse)
	err := c.cc.Invoke(ctx, MainService_DeleteCache_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MainServiceServer is the server API for MainService service.
// All implementations must embed UnimplementedMainServiceServer
// for forward compatibility.
type MainServiceServer interface {
	SetCache(context.Context, *SetCacheRequest) (*SetCacheResponse, error)
	GetCache(context.Context, *GetCacheRequest) (*GetCacheResponse, error)
	DeleteCache(context.Context, *DeleteCacheRequest) (*DeleteCacheResponse, error)
	mustEmbedUnimplementedMainServiceServer()
}

// UnimplementedMainServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedMainServiceServer struct{}

func (UnimplementedMainServiceServer) SetCache(context.Context, *SetCacheRequest) (*SetCacheResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetCache not implemented")
}
func (UnimplementedMainServiceServer) GetCache(context.Context, *GetCacheRequest) (*GetCacheResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetCache not implemented")
}
func (UnimplementedMainServiceServer) DeleteCache(context.Context, *DeleteCacheRequest) (*DeleteCacheResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteCache not implemented")
}
func (UnimplementedMainServiceServer) mustEmbedUnimplementedMainServiceServer() {}
func (UnimplementedMainServiceServer) testEmbeddedByValue()                     {}

// UnsafeMainServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to MainServiceServer will
// result in compilation errors.
type UnsafeMainServiceServer interface {
	mustEmbedUnimplementedMainServiceServer()
}

func RegisterMainServiceServer(s grpc.ServiceRegistrar, srv MainServiceServer) {
	// If the following call pancis, it indicates UnimplementedMainServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&MainService_ServiceDesc, srv)
}

func _MainService_SetCache_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetCacheRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MainServiceServer).SetCache(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MainService_SetCache_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MainServiceServer).SetCache(ctx, req.(*SetCacheRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MainService_GetCache_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetCacheRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MainServiceServer).GetCache(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MainService_GetCache_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MainServiceServer).GetCache(ctx, req.(*GetCacheRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MainService_DeleteCache_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteCacheRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MainServiceServer).DeleteCache(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MainService_DeleteCache_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MainServiceServer).DeleteCache(ctx, req.(*DeleteCacheRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// MainService_ServiceDesc is the grpc.ServiceDesc for MainService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var MainService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "octelium.api.rsc.cache.v1.MainService",
	HandlerType: (*MainServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SetCache",
			Handler:    _MainService_SetCache_Handler,
		},
		{
			MethodName: "GetCache",
			Handler:    _MainService_GetCache_Handler,
		},
		{
			MethodName: "DeleteCache",
			Handler:    _MainService_DeleteCache_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "rcachev1.proto",
}
