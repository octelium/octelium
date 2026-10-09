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

package connect

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGetSuspendDuration(t *testing.T) {
	now := time.Now()

	assert.Equal(t, time.Duration(0), getSuspendDuration(now, now))
	assert.Equal(t, time.Duration(0), getSuspendDuration(now, now.Add(suspendCheckInterval)))
	assert.Equal(t, time.Duration(0),
		getSuspendDuration(now, now.Add(suspendCheckInterval+suspendMinDuration-time.Second)))
	assert.Equal(t, suspendMinDuration,
		getSuspendDuration(now, now.Add(suspendCheckInterval+suspendMinDuration)))
	assert.Equal(t, 20*time.Minute,
		getSuspendDuration(now, now.Add(suspendCheckInterval+20*time.Minute)))

	wall := now.Round(0)
	assert.Equal(t, 20*time.Minute,
		getSuspendDuration(wall, wall.Add(suspendCheckInterval+20*time.Minute)))
	assert.Equal(t, time.Duration(0), getSuspendDuration(wall, wall.Add(-time.Hour)))
}

func TestWatchSuspend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tickCh := make(chan time.Time)
	nowCh := make(chan time.Time)
	resumeCh := make(chan time.Duration, 1)

	clock := time.Now().Round(0)

	nowFn := func() time.Time {
		return <-nowCh
	}

	tick := func(d time.Duration) {
		clock = clock.Add(d)
		tickCh <- clock
		nowCh <- clock
	}

	getResumed := func() time.Duration {
		tick(suspendCheckInterval)

		select {
		case ret := <-resumeCh:
			return ret
		default:
			return 0
		}
	}

	doneCh := make(chan struct{})
	go func() {
		watchSuspend(ctx, tickCh, nowFn, resumeCh)
		close(doneCh)
	}()

	nowCh <- clock

	tick(suspendCheckInterval)
	assert.Equal(t, time.Duration(0), getResumed())

	tick(suspendCheckInterval + 3*time.Second)
	assert.Equal(t, time.Duration(0), getResumed())

	tick(suspendCheckInterval + 20*time.Minute)
	assert.Equal(t, 20*time.Minute, getResumed())

	tick(suspendCheckInterval + time.Hour)
	tick(suspendCheckInterval + 2*time.Hour)
	assert.Equal(t, time.Hour, getResumed())
	assert.Equal(t, time.Duration(0), getResumed())

	cancel()

	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("watchSuspend did not exit after the context was canceled")
	}
}

type testUserServer struct {
	userv1.UnimplementedMainServiceServer

	calls       atomic.Int32
	getStatusFn func(ctx context.Context) (*userv1.GetStatusResponse, error)
}

func (s *testUserServer) GetStatus(ctx context.Context,
	req *userv1.GetStatusRequest) (*userv1.GetStatusResponse, error) {
	s.calls.Add(1)
	return s.getStatusFn(ctx)
}

func newTestUserClient(t *testing.T, srv *testUserServer) (userv1.MainServiceClient, *grpc.Server) {
	lis := bufconn.Listen(1 << 20)

	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithChainUnaryInterceptor(grpc_retry.UnaryClientInterceptor(
			grpc_retry.WithMax(16),
			grpc_retry.WithBackoff(grpc_retry.BackoffLinear(100*time.Millisecond)),
			grpc_retry.WithCodes(codes.Unavailable, codes.DeadlineExceeded))))
	assert.Nil(t, err)
	t.Cleanup(func() {
		conn.Close()
	})

	return userv1.NewMainServiceClient(conn), grpcSrv
}

func TestProbeConnection(t *testing.T) {
	ctx := context.Background()

	t.Run("Alive", func(t *testing.T) {
		srv := &testUserServer{
			getStatusFn: func(ctx context.Context) (*userv1.GetStatusResponse, error) {
				return &userv1.GetStatusResponse{}, nil
			},
		}
		cl, _ := newTestUserClient(t, srv)

		assert.Nil(t, probeConnection(ctx, cl))
		assert.Equal(t, int32(1), srv.calls.Load())
	})

	t.Run("ClusterError", func(t *testing.T) {
		srv := &testUserServer{
			getStatusFn: func(ctx context.Context) (*userv1.GetStatusResponse, error) {
				return nil, status.Error(codes.Unauthenticated, "Octelium: Unauthenticated")
			},
		}
		cl, _ := newTestUserClient(t, srv)

		assert.Nil(t, probeConnection(ctx, cl))
		assert.Equal(t, int32(1), srv.calls.Load())
	})

	t.Run("Unavailable", func(t *testing.T) {
		srv := &testUserServer{
			getStatusFn: func(ctx context.Context) (*userv1.GetStatusResponse, error) {
				return nil, status.Error(codes.Unavailable, "no healthy upstream")
			},
		}
		cl, _ := newTestUserClient(t, srv)

		assert.NotNil(t, probeConnection(ctx, cl))
		assert.Equal(t, int32(1), srv.calls.Load())
	})

	t.Run("DeadlineExceeded", func(t *testing.T) {
		srv := &testUserServer{
			getStatusFn: func(ctx context.Context) (*userv1.GetStatusResponse, error) {
				return nil, status.Error(codes.DeadlineExceeded, "deadline exceeded")
			},
		}
		cl, _ := newTestUserClient(t, srv)

		err := probeConnection(ctx, cl)
		assert.NotNil(t, err)
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
		assert.Nil(t, ctx.Err())
		assert.Equal(t, int32(1), srv.calls.Load())
	})

	t.Run("NoResponse", func(t *testing.T) {
		srv := &testUserServer{
			getStatusFn: func(ctx context.Context) (*userv1.GetStatusResponse, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}
		cl, _ := newTestUserClient(t, srv)

		ctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer cancel()

		startedAt := time.Now()
		assert.NotNil(t, probeConnection(ctx, cl))
		assert.Less(t, time.Since(startedAt), resumeProbeTimeout)
		assert.Equal(t, int32(1), srv.calls.Load())
	})

	t.Run("Closed", func(t *testing.T) {
		srv := &testUserServer{
			getStatusFn: func(ctx context.Context) (*userv1.GetStatusResponse, error) {
				return &userv1.GetStatusResponse{}, nil
			},
		}
		cl, grpcSrv := newTestUserClient(t, srv)

		assert.Nil(t, probeConnection(ctx, cl))

		grpcSrv.Stop()

		assert.NotNil(t, probeConnection(ctx, cl))
		assert.Equal(t, int32(1), srv.calls.Load())
	})
}

func newTestStateController() *stateController {
	return &stateController{
		getConnErrCh:          make(chan error, 1),
		apiserverDisconnectCh: make(chan struct{}),
		resumeCh:              make(chan time.Duration, 1),
	}
}

func TestWaitDisconnected(t *testing.T) {
	ctx := context.Background()

	t.Run("ConnectionError", func(t *testing.T) {
		c := newTestStateController()
		c.getConnErrCh <- errors.New("stream closed")

		ret := c.waitDisconnected(ctx, func(ctx context.Context) error {
			t.Fatal("the Connection must not be probed")
			return nil
		})

		assert.NotNil(t, ret.err)
		assert.True(t, ret.needsReconnect)
		assert.True(t, ret.isConnected)
		assert.False(t, ret.isResumed)
	})

	t.Run("Disconnected", func(t *testing.T) {
		c := newTestStateController()
		close(c.apiserverDisconnectCh)

		ret := c.waitDisconnected(ctx, func(ctx context.Context) error {
			return nil
		})

		assert.Nil(t, ret.err)
		assert.False(t, ret.needsReconnect)
		assert.True(t, ret.isConnected)
		assert.False(t, ret.isResumed)
	})

	t.Run("Canceled", func(t *testing.T) {
		c := newTestStateController()

		ctx, cancel := context.WithCancel(ctx)
		cancel()

		ret := c.waitDisconnected(ctx, func(ctx context.Context) error {
			return nil
		})

		assert.Nil(t, ret.err)
		assert.False(t, ret.needsReconnect)
		assert.False(t, ret.isResumed)
	})

	t.Run("ResumedAlive", func(t *testing.T) {
		c := newTestStateController()
		c.resumeCh <- 20 * time.Minute

		var probes int
		ret := c.waitDisconnected(ctx, func(ctx context.Context) error {
			probes++
			c.getConnErrCh <- errors.New("stream closed")
			return nil
		})

		assert.Equal(t, 1, probes)
		assert.True(t, ret.needsReconnect)
		assert.False(t, ret.isResumed)
	})

	t.Run("ResumedLost", func(t *testing.T) {
		c := newTestStateController()
		c.resumeCh <- 20 * time.Minute

		ret := c.waitDisconnected(ctx, func(ctx context.Context) error {
			return status.Error(codes.DeadlineExceeded, "context deadline exceeded")
		})

		assert.NotNil(t, ret.err)
		assert.True(t, ret.needsReconnect)
		assert.True(t, ret.isConnected)
		assert.True(t, ret.isResumed)
	})

	t.Run("CanceledWhileProbing", func(t *testing.T) {
		c := newTestStateController()
		c.resumeCh <- 20 * time.Minute

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		ret := c.waitDisconnected(ctx, func(ctx context.Context) error {
			cancel()
			return ctx.Err()
		})

		assert.Nil(t, ret.err)
		assert.False(t, ret.needsReconnect)
		assert.False(t, ret.isResumed)
	})
}
