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

package grpcconn

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func newTestAuthProxySocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "oct-grpcconn-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "proxy.sock")
}

func startTestAuthProxy(t *testing.T, socket string) {
	t.Helper()
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	srv := grpc.NewServer()
	healthSrv := health.NewServer()
	healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(srv, healthSrv)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
}

func newTestAuthProxyClient(t *testing.T, socket string) grpc_health_v1.HealthClient {
	t.Helper()
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", socket)
	conn, err := DoGetGRPCClientConn("example.invalid")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return grpc_health_v1.NewHealthClient(conn)
}

func TestDoGetGRPCClientConnAuthProxy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix socket transport")
	}
	t.Run("AbsolutePath", func(t *testing.T) {
		socket := newTestAuthProxySocket(t)
		startTestAuthProxy(t, socket)
		c := newTestAuthProxyClient(t, socket)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		resp, err := c.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})
	t.Run("RelativePath", func(t *testing.T) {
		t.Chdir(filepath.Dir(newTestAuthProxySocket(t)))
		startTestAuthProxy(t, "proxy.sock")
		c := newTestAuthProxyClient(t, "proxy.sock")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		resp, err := c.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		require.NoError(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status)
	})
	t.Run("MissingSocketCanceledContext", func(t *testing.T) {
		c := newTestAuthProxyClient(t, newTestAuthProxySocket(t))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := c.Check(ctx, &grpc_health_v1.HealthCheckRequest{}, grpc.WaitForReady(true))
		assert.Equal(t, codes.Canceled, status.Code(err))
	})
	t.Run("MissingSocketDeadline", func(t *testing.T) {
		c := newTestAuthProxyClient(t, newTestAuthProxySocket(t))
		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := c.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
		assert.Less(t, time.Since(start), 3*time.Second)
	})
	t.Run("MissingSocketCancelWhileWaiting", func(t *testing.T) {
		c := newTestAuthProxyClient(t, newTestAuthProxySocket(t))
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			_, err := c.Check(ctx, &grpc_health_v1.HealthCheckRequest{}, grpc.WaitForReady(true))
			done <- err
		}()
		time.Sleep(200 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			assert.Equal(t, codes.Canceled, status.Code(err))
		case <-time.After(3 * time.Second):
			require.Fail(t, "the call did not return after its context was canceled")
		}
	})
	t.Run("LateSocket", func(t *testing.T) {
		socket := newTestAuthProxySocket(t)
		c := newTestAuthProxyClient(t, socket)
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := c.Check(ctx, &grpc_health_v1.HealthCheckRequest{}, grpc.WaitForReady(true))
			done <- err
		}()
		time.Sleep(200 * time.Millisecond)
		startTestAuthProxy(t, socket)
		assert.NoError(t, <-done)
	})
}
