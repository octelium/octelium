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

package service

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type testServiceAPI struct {
	userv1.UnimplementedMainServiceServer
	reqs []*userv1.ListServiceOptions
}

func (s *testServiceAPI) ListService(ctx context.Context, req *userv1.ListServiceOptions) (*userv1.ServiceList, error) {
	s.reqs = append(s.reqs, req)
	return &userv1.ServiceList{}, nil
}

func startTestServiceAPI(t *testing.T) *testServiceAPI {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the authentication proxy transport uses Unix domain sockets")
	}
	dir, err := os.MkdirTemp("", "oct-cli-")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "api.sock")
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	srv := &testServiceAPI{}
	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", socket)
	return srv
}

func executeCmd(t *testing.T, cmdLineArgs ...string) error {
	t.Helper()
	t.Cleanup(func() {
		cmdArgs = args{}
		assert.NoError(t, Cmd.PersistentFlags().Set("type", ""))
	})
	Cmd.SetArgs(cmdLineArgs)
	return Cmd.ExecuteContext(t.Context())
}

func TestParseServiceType(t *testing.T) {
	for _, tc := range []struct {
		arg string
		typ userv1.Service_Spec_Type
	}{
		{"", userv1.Service_Spec_UNSET},
		{"tcp", userv1.Service_Spec_TCP},
		{"TCP", userv1.Service_Spec_TCP},
		{"Postgres", userv1.Service_Spec_POSTGRES},
		{"ssh", userv1.Service_Spec_SSH},
		{"rdp_web", userv1.Service_Spec_RDP_WEB},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			typ, err := parseServiceType(tc.arg)
			require.NoError(t, err)
			assert.Equal(t, tc.typ, typ)
		})
	}

	for name, val := range userv1.Service_Spec_Type_value {
		if userv1.Service_Spec_Type(val) == userv1.Service_Spec_UNSET {
			continue
		}
		typ, err := parseServiceType(strings.ToLower(name))
		require.NoError(t, err)
		assert.Equal(t, userv1.Service_Spec_Type(val), typ)
	}

	for _, arg := range []string{"unset", "UNSET", "invalid", "6", " tcp", "tcp,udp", "rdp-web", "MODE_UNSET"} {
		t.Run(arg, func(t *testing.T) {
			typ, err := parseServiceType(arg)
			require.Error(t, err)
			assert.Equal(t, userv1.Service_Spec_UNSET, typ)
			assert.Contains(t, err.Error(), arg)
			assert.Contains(t, err.Error(), "tcp, udp, http")
			assert.NotContains(t, err.Error(), ", unset")
		})
	}
}

func TestGetServiceTypes(t *testing.T) {
	ret := getServiceTypes()
	assert.Len(t, ret, len(userv1.Service_Spec_Type_value)-1)
	assert.Equal(t, "tcp", ret[0])
	assert.NotContains(t, ret, "unset")
	assert.Contains(t, ret, "postgres")
	assert.Contains(t, ret, "rdp_web")
}

func TestListServiceType(t *testing.T) {
	t.Setenv("OCTELIUM_DOMAIN", "example.com")
	t.Run("Set", func(t *testing.T) {
		srv := startTestServiceAPI(t)
		require.NoError(t, executeCmd(t, "--type", "POSTGRES"))
		require.Len(t, srv.reqs, 1)
		assert.Equal(t, userv1.Service_Spec_POSTGRES, srv.reqs[0].Type)
	})
	t.Run("Unset", func(t *testing.T) {
		srv := startTestServiceAPI(t)
		require.NoError(t, executeCmd(t))
		require.Len(t, srv.reqs, 1)
		assert.Equal(t, userv1.Service_Spec_UNSET, srv.reqs[0].Type)
	})
	t.Run("Invalid", func(t *testing.T) {
		srv := startTestServiceAPI(t)
		Cmd.SilenceUsage = true
		t.Cleanup(func() { Cmd.SilenceUsage = false })
		err := executeCmd(t, "--type", "invalid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid Service type: invalid")
		assert.Empty(t, srv.reqs)
	})
}
