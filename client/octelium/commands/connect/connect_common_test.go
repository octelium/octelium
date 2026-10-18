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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestParsePublishService(t *testing.T) {

	{
		_, err := parsePublishedService("svc1")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1:")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1::")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1.ns1")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("1.2.3.4")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1:0.0.0.0")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1:localhost")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1:9999999")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1:0")
		assert.NotNil(t, err)
	}
	{
		_, err := parsePublishedService("svc1::8080")
		assert.NotNil(t, err)
	}
	{
		res, err := parsePublishedService("svc1:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1", res.svc)
		assert.Equal(t, "localhost", res.addr)
		assert.Equal(t, 9090, res.port)
	}
	{
		res, err := parsePublishedService("svc1.ns1:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1.ns1", res.svc)
		assert.Equal(t, "localhost", res.addr)
		assert.Equal(t, 9090, res.port)
	}
	{
		res, err := parsePublishedService("svc1:0.0.0.0:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1", res.svc)
		assert.Equal(t, "0.0.0.0", res.addr)
		assert.Equal(t, 9090, res.port)
	}
	{
		res, err := parsePublishedService("svc1:[::1]:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1", res.svc)
		assert.Equal(t, "::1", res.addr)
		assert.Equal(t, 9090, res.port)
	}
	{
		res, err := parsePublishedService("svc1.ns1:0.0.0.0:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1.ns1", res.svc)
		assert.Equal(t, "0.0.0.0", res.addr)
		assert.Equal(t, 9090, res.port)
	}
	{
		res, err := parsePublishedService("svc1.ns1:[::1]:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1.ns1", res.svc)
		assert.Equal(t, "::1", res.addr)
		assert.Equal(t, 9090, res.port)
	}

	{
		res, err := parsePublishedService("svc1:localhost:9090")
		assert.Nil(t, err)

		assert.Equal(t, "svc1", res.svc)
		assert.Equal(t, "localhost", res.addr)
		assert.Equal(t, 9090, res.port)
	}
}

func TestGetReconnectBackoff(t *testing.T) {
	for range 100 {
		var prev time.Duration

		for attempt := 1; attempt < 20; attempt++ {
			ret := getReconnectBackoff(attempt)

			assert.GreaterOrEqual(t, ret, reconnectBackoffMin)
			assert.LessOrEqual(t, ret, reconnectBackoffMax)
			assert.GreaterOrEqual(t, ret, prev)

			prev = ret
		}
	}

	assert.Equal(t, reconnectBackoffMax, getReconnectBackoff(20))
}

var allCodes = []codes.Code{
	codes.Canceled, codes.Unknown, codes.InvalidArgument, codes.DeadlineExceeded,
	codes.NotFound, codes.AlreadyExists, codes.PermissionDenied, codes.ResourceExhausted,
	codes.FailedPrecondition, codes.Aborted, codes.OutOfRange, codes.Unimplemented,
	codes.Internal, codes.Unavailable, codes.DataLoss, codes.Unauthenticated,
}

func TestIsRejectedErr(t *testing.T) {
	for _, code := range allCodes {
		want := code == codes.InvalidArgument || code == codes.PermissionDenied || code == codes.NotFound

		err := status.Error(code, "err")
		assert.Equal(t, want, isRejectedErr(err), code.String())
		assert.Equal(t, want, isRejectedErr(errors.Wrap(err, "Could not connect to API Server")), code.String())
	}

	assert.False(t, isRejectedErr(nil))
	assert.False(t, isRejectedErr(errors.New("Could not get initial state message after a timeout")))
}

func TestShouldReconnect(t *testing.T) {
	errs := []error{
		nil,
		errors.New("Could not initialize controller"),
	}
	for _, code := range allCodes {
		errs = append(errs, status.Error(code, "err"))
	}

	for _, err := range errs {
		assert.False(t, shouldReconnect(tryConnectRet{err: err}, false),
			"%+v: a stop requested by the Cluster, the user or a failed cleanup is final", err)
		assert.False(t, shouldReconnect(tryConnectRet{err: err}, true),
			"%+v: a stop requested by the Cluster, the user or a failed cleanup is final", err)

		assert.True(t, shouldReconnect(tryConnectRet{err: err, needsReconnect: true}, true),
			"%+v: a client that has connected before must never give up", err)

		assert.Equal(t, !isRejectedErr(err),
			shouldReconnect(tryConnectRet{err: err, needsReconnect: true}, false),
			"%+v: only a rejected request stops a client that has never connected", err)
	}
}

type fakeConnectServer struct {
	userv1.UnimplementedMainServiceServer

	mu       sync.Mutex
	errs     []error
	attempts int
}

func (s *fakeConnectServer) Connect(stream userv1.MainService_ConnectServer) error {
	s.mu.Lock()
	err := s.errs[min(s.attempts, len(s.errs)-1)]
	s.attempts++
	s.mu.Unlock()

	if _, recvErr := stream.Recv(); recvErr != nil {
		return recvErr
	}

	return err
}

func (s *fakeConnectServer) getAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

func runFakeConnect(t *testing.T, errs ...error) (*fakeConnectServer, *Connector, *[]*Event) {
	t.Helper()

	t.Setenv("OCTELIUM_DEV", "false")
	t.Setenv("OCTELIUM_PRODUCTION", "true")

	socketPath := filepath.Join(t.TempDir(), "proxy.sock")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", socketPath)

	lis, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	srv := &fakeConnectServer{errs: errs}
	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)

	var mu sync.Mutex
	var events []*Event

	c, err := NewConnector("example.com", &Opts{
		L3Mode: "v4",
		OnEvent: func(ev *Event) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		},
	})
	require.NoError(t, err)

	return srv, c, &events
}

func TestRunStopsOnRejectionBeforeConnecting(t *testing.T) {
	for _, code := range []codes.Code{codes.InvalidArgument, codes.PermissionDenied, codes.NotFound} {
		t.Run(code.String(), func(t *testing.T) {
			srv, c, events := runFakeConnect(t, status.Error(code, "rejected"))

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			err := c.Run(ctx)
			assert.Equal(t, code, status.Code(err))
			assert.True(t, isRejectedErr(err))
			assert.Equal(t, 1, srv.getAttempts())

			require.NotEmpty(t, *events)
			last := (*events)[len(*events)-1]
			assert.Equal(t, EventTypeDisconnected, last.Type)
			assert.Equal(t, code, status.Code(last.Err))
		})
	}
}

func TestRunRetriesBeforeConnecting(t *testing.T) {
	for _, code := range []codes.Code{codes.Unauthenticated, codes.Unavailable} {
		t.Run(code.String(), func(t *testing.T) {
			srv, c, events := runFakeConnect(t,
				status.Error(code, "transient"), status.Error(codes.NotFound, "rejected"))

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			err := c.Run(ctx)
			assert.Equal(t, codes.NotFound, status.Code(err))
			assert.Equal(t, 2, srv.getAttempts())

			var retried bool
			for _, ev := range *events {
				if ev.Type == EventTypeConnecting && status.Code(ev.Err) == code {
					retried = true
				}
			}
			assert.True(t, retried, "the client must keep connecting after %s", code)
		})
	}
}
