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

package register

import (
	"context"
	"net"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils/deviceinfo"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGetOSType(t *testing.T) {
	switch runtime.GOOS {
	case "linux":
		assert.Equal(t, authv1.RegisterDeviceRequest_Info_LINUX, getOSType())
	case "darwin":
		assert.Equal(t, authv1.RegisterDeviceRequest_Info_MAC, getOSType())
	case "windows":
		assert.Equal(t, authv1.RegisterDeviceRequest_Info_WINDOWS, getOSType())
	case "android":
		assert.Equal(t, authv1.RegisterDeviceRequest_Info_ANDROID, getOSType())
	case "ios":
		assert.Equal(t, authv1.RegisterDeviceRequest_Info_IOS, getOSType())
	}
}

func TestGetHostname(t *testing.T) {
	tests := []struct {
		arg      string
		expected string
	}{
		{"", ""},
		{"  Pixel 8 Pro ", "Pixel 8 Pro"},
		{strings.Repeat("a", 32), strings.Repeat("a", 32)},
		{strings.Repeat("a", 40), strings.Repeat("a", 32)},
		{strings.Repeat("a", 31) + "é", strings.Repeat("a", 31)},
		{strings.Repeat("a", 30) + "é" + "b", strings.Repeat("a", 30) + "é"},
		{strings.Repeat("a", 31) + " " + "bbbb", strings.Repeat("a", 31)},
		{strings.Repeat("日本", 10), strings.Repeat("日本", 5)},
	}

	for _, tc := range tests {
		ret := getHostname(tc.arg)
		assert.Equal(t, tc.expected, ret, "arg: %q", tc.arg)
		assert.LessOrEqual(t, len(ret), maxHostnameLen)
		assert.True(t, utf8.ValidString(ret))
	}
}

type fakeAuthClient struct {
	authv1.MainServiceClient

	registerErr error
	beginErr    error
	finishErr   error

	registerReq   *authv1.RegisterDeviceRequest
	beginReq      *authv1.RegisterDeviceBeginRequest
	finishReq     *authv1.RegisterDeviceFinishRequest
	probeBeginReq *authv1.RunDeviceProbeBeginRequest
}

func (c *fakeAuthClient) RegisterDevice(ctx context.Context,
	in *authv1.RegisterDeviceRequest, opts ...grpc.CallOption) (*authv1.RegisterDeviceResponse, error) {
	c.registerReq = in
	if c.registerErr != nil {
		return nil, c.registerErr
	}
	return &authv1.RegisterDeviceResponse{}, nil
}

func (c *fakeAuthClient) RegisterDeviceBegin(ctx context.Context,
	in *authv1.RegisterDeviceBeginRequest, opts ...grpc.CallOption) (*authv1.RegisterDeviceBeginResponse, error) {
	c.beginReq = in
	if c.beginErr != nil {
		return nil, c.beginErr
	}
	return &authv1.RegisterDeviceBeginResponse{
		Uid: "uid",
	}, nil
}

func (c *fakeAuthClient) RegisterDeviceFinish(ctx context.Context,
	in *authv1.RegisterDeviceFinishRequest, opts ...grpc.CallOption) (*authv1.RegisterDeviceFinishResponse, error) {
	c.finishReq = in
	if c.finishErr != nil {
		return nil, c.finishErr
	}
	return &authv1.RegisterDeviceFinishResponse{}, nil
}

func (c *fakeAuthClient) RunDeviceProbeBegin(ctx context.Context,
	in *authv1.RunDeviceProbeBeginRequest, opts ...grpc.CallOption) (*authv1.RunDeviceProbeBeginResponse, error) {
	c.probeBeginReq = in
	return &authv1.RunDeviceProbeBeginResponse{}, nil
}

func TestGetRegisterDeviceRequest(t *testing.T) {
	info := &deviceinfo.DeviceInfo{
		ID:           strings.Repeat("a", 64),
		SerialNumber: "C02XK1ABJHD3",
		Hostname:     "  host  ",
		MacAddresses: []string{"00:1a:2b:3c:4d:5e"},
	}

	req := getRegisterDeviceRequest(info)
	assert.Equal(t, info.ID, req.Info.Id)
	assert.Equal(t, "host", req.Info.Hostname)
	assert.Equal(t, info.SerialNumber, req.Info.SerialNumber)
	assert.Equal(t, info.MacAddresses, req.Info.MacAddresses)
	assert.Equal(t, getOSType(), req.Info.OsType)
}

func TestDoRegisterDevice(t *testing.T) {
	ctx := context.Background()

	info := &deviceinfo.DeviceInfo{
		ID:           strings.Repeat("a", 64),
		SerialNumber: "C02XK1ABJHD3",
		Hostname:     "host",
	}

	unimplemented := status.Error(codes.Unimplemented, "unknown method RegisterDevice")

	{
		c := &fakeAuthClient{}
		err := doRegisterDevice(ctx, c, info)
		assert.Nil(t, err)
		assert.Equal(t, info.ID, c.registerReq.Info.Id)
		assert.Nil(t, c.beginReq)
		assert.Nil(t, c.finishReq)
		assert.NotNil(t, c.probeBeginReq, "a newly registered Device must be probed")
	}

	{
		c := &fakeAuthClient{
			registerErr: status.Error(codes.AlreadyExists, "This Device is already registered"),
		}
		err := doRegisterDevice(ctx, c, info)
		assert.Nil(t, err)
		assert.Nil(t, c.beginReq)
		assert.NotNil(t, c.probeBeginReq, "an already registered Device must be probed")
	}

	for _, code := range []codes.Code{
		codes.PermissionDenied, codes.InvalidArgument, codes.Unavailable, codes.NotFound,
	} {
		c := &fakeAuthClient{
			registerErr: status.Error(code, "error"),
		}
		err := doRegisterDevice(ctx, c, info)
		assert.NotNil(t, err)
		assert.Nil(t, c.beginReq, "only an Unimplemented error must fall back to the legacy registration")
		assert.Nil(t, c.probeBeginReq)
	}

	{
		c := &fakeAuthClient{
			registerErr: unimplemented,
		}
		err := doRegisterDevice(ctx, c, info)
		assert.Nil(t, err)
		assert.True(t, pbutils.IsEqual(c.registerReq.Info, c.beginReq.Info))
		assert.Equal(t, "uid", c.finishReq.Uid)
		assert.Nil(t, c.probeBeginReq, "a legacy Cluster must not be probed")
	}

	{
		c := &fakeAuthClient{
			registerErr: unimplemented,
			beginErr:    status.Error(codes.AlreadyExists, "Device is already registered"),
		}
		err := doRegisterDevice(ctx, c, info)
		assert.Nil(t, err)
		assert.NotNil(t, c.beginReq)
		assert.Nil(t, c.finishReq)
		assert.Nil(t, c.probeBeginReq)
	}

	{
		c := &fakeAuthClient{
			registerErr: unimplemented,
			beginErr:    status.Error(codes.PermissionDenied, "Limit of Devices has been exceeded"),
		}
		err := doRegisterDevice(ctx, c, info)
		assert.NotNil(t, err)
		assert.Nil(t, c.finishReq)
		assert.Nil(t, c.probeBeginReq)
	}

	{
		c := &fakeAuthClient{
			registerErr: unimplemented,
			finishErr:   status.Error(codes.InvalidArgument, "Invalid Session"),
		}
		err := doRegisterDevice(ctx, c, info)
		assert.NotNil(t, err)
		assert.Equal(t, "uid", c.finishReq.Uid)
		assert.Nil(t, c.probeBeginReq)
	}
}

type testAuthServer struct {
	authv1.UnimplementedMainServiceServer

	registerReq   *authv1.RegisterDeviceRequest
	beginReq      *authv1.RegisterDeviceBeginRequest
	finishReq     *authv1.RegisterDeviceFinishRequest
	probeBeginReq *authv1.RunDeviceProbeBeginRequest
}

func (s *testAuthServer) RegisterDevice(ctx context.Context,
	req *authv1.RegisterDeviceRequest) (*authv1.RegisterDeviceResponse, error) {
	s.registerReq = req
	return &authv1.RegisterDeviceResponse{}, nil
}

func (s *testAuthServer) RegisterDeviceBegin(ctx context.Context,
	req *authv1.RegisterDeviceBeginRequest) (*authv1.RegisterDeviceBeginResponse, error) {
	s.beginReq = req
	return &authv1.RegisterDeviceBeginResponse{
		Uid: "abcdefghij",
	}, nil
}

func (s *testAuthServer) RegisterDeviceFinish(ctx context.Context,
	req *authv1.RegisterDeviceFinishRequest) (*authv1.RegisterDeviceFinishResponse, error) {
	s.finishReq = req
	return &authv1.RegisterDeviceFinishResponse{}, nil
}

func (s *testAuthServer) RunDeviceProbeBegin(ctx context.Context,
	req *authv1.RunDeviceProbeBeginRequest) (*authv1.RunDeviceProbeBeginResponse, error) {
	s.probeBeginReq = req
	return &authv1.RunDeviceProbeBeginResponse{}, nil
}

func newTestAuthClient(t *testing.T, srv *testAuthServer, withoutMethods ...string) authv1.MainServiceClient {
	lis := bufconn.Listen(1 << 20)

	desc := authv1.MainService_ServiceDesc
	desc.Methods = slices.DeleteFunc(slices.Clone(desc.Methods), func(m grpc.MethodDesc) bool {
		return slices.Contains(withoutMethods, m.MethodName)
	})

	grpcSrv := grpc.NewServer()
	grpcSrv.RegisterService(&desc, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))
	assert.Nil(t, err)
	t.Cleanup(func() {
		conn.Close()
	})

	return authv1.NewMainServiceClient(conn)
}

func TestDoRegisterDeviceGRPC(t *testing.T) {
	ctx := context.Background()

	info := &deviceinfo.DeviceInfo{
		ID:           strings.Repeat("a", 64),
		SerialNumber: "C02XK1ABJHD3",
		Hostname:     "host",
		MacAddresses: []string{"00:1a:2b:3c:4d:5e"},
	}

	{
		srv := &testAuthServer{}
		c := newTestAuthClient(t, srv)

		assert.Nil(t, doRegisterDevice(ctx, c, info))
		assert.Equal(t, info.ID, srv.registerReq.Info.Id)
		assert.Equal(t, info.MacAddresses, srv.registerReq.Info.MacAddresses)
		assert.Nil(t, srv.beginReq)
		assert.Nil(t, srv.finishReq)
		assert.NotNil(t, srv.probeBeginReq)
	}

	{
		srv := &testAuthServer{}
		c := newTestAuthClient(t, srv, "RegisterDevice")

		_, err := c.RegisterDevice(ctx, getRegisterDeviceRequest(info))
		assert.True(t, grpcerr.IsUnimplemented(err), "a legacy Cluster must return Unimplemented: %+v", err)

		assert.Nil(t, doRegisterDevice(ctx, c, info))
		assert.Nil(t, srv.registerReq)
		assert.Equal(t, info.ID, srv.beginReq.Info.Id)
		assert.Equal(t, info.SerialNumber, srv.beginReq.Info.SerialNumber)
		assert.Equal(t, getOSType(), srv.beginReq.Info.OsType)
		assert.Equal(t, "abcdefghij", srv.finishReq.Uid)
		assert.Nil(t, srv.probeBeginReq, "a legacy Cluster must not be probed")
	}
}
