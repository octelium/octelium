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

package rratelimitv1

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
	MainService_CheckSlidingWindow_FullMethodName = "/octelium.api.rsc.ratelimit.v1.MainService/CheckSlidingWindow"
)

// MainServiceClient is the client API for MainService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MainServiceClient interface {
	CheckSlidingWindow(ctx context.Context, in *CheckSlidingWindowRequest, opts ...grpc.CallOption) (*CheckSlidingWindowResponse, error)
}

type mainServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewMainServiceClient(cc grpc.ClientConnInterface) MainServiceClient {
	return &mainServiceClient{cc}
}

func (c *mainServiceClient) CheckSlidingWindow(ctx context.Context, in *CheckSlidingWindowRequest, opts ...grpc.CallOption) (*CheckSlidingWindowResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CheckSlidingWindowResponse)
	err := c.cc.Invoke(ctx, MainService_CheckSlidingWindow_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MainServiceServer is the server API for MainService service.
// All implementations must embed UnimplementedMainServiceServer
// for forward compatibility.
type MainServiceServer interface {
	CheckSlidingWindow(context.Context, *CheckSlidingWindowRequest) (*CheckSlidingWindowResponse, error)
	mustEmbedUnimplementedMainServiceServer()
}

// UnimplementedMainServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedMainServiceServer struct{}

func (UnimplementedMainServiceServer) CheckSlidingWindow(context.Context, *CheckSlidingWindowRequest) (*CheckSlidingWindowResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckSlidingWindow not implemented")
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

func _MainService_CheckSlidingWindow_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CheckSlidingWindowRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MainServiceServer).CheckSlidingWindow(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MainService_CheckSlidingWindow_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MainServiceServer).CheckSlidingWindow(ctx, req.(*CheckSlidingWindowRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// MainService_ServiceDesc is the grpc.ServiceDesc for MainService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var MainService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "octelium.api.rsc.ratelimit.v1.MainService",
	HandlerType: (*MainServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CheckSlidingWindow",
			Handler:    _MainService_CheckSlidingWindow_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "rratelimitv1.proto",
}
