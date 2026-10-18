/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package apiserver

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

type userCtxStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *userCtxStream) Context() context.Context {
	return s.ctx
}

func TestStopDisconnectsConnections(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	usrSrv := user.NewServer(tst.C.OcteliumC)
	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})

	getActiveIndexes := func() []uint32 {
		cfg, err := tst.C.OcteliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: "sys:conn-info"})
		assert.Nil(t, err, "%+v", err)

		ret := &cclusterv1.ClusterConnInfo{}
		err = pbutils.StructToMessage(cfg.Data.GetAttrs(), ret)
		assert.Nil(t, err, "%+v", err)
		return append(ret.ActiveIndexesWG, ret.ActiveIndexesQUIC...)
	}

	var usrs []*tstuser.User
	userCtxs := make(map[string]*userctx.UserCtx)
	for range 3 {
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)

		i, err := userctx.GetUserCtx(usrT.Ctx())
		assert.Nil(t, err, "%+v", err)

		usrs = append(usrs, usrT)
		userCtxs[usrT.Session.Metadata.Uid] = i
	}

	s := newGRPCServer(grpc.ChainStreamInterceptor(
		func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			md, _ := metadata.FromIncomingContext(ss.Context())
			return handler(srv, &userCtxStream{
				ServerStream: ss,
				ctx: context.WithValue(ss.Context(), "octelium-user-ctx",
					userCtxs[md.Get("x-test-session-uid")[0]]),
			})
		}))
	userv1.RegisterMainServiceServer(s, usrSrv)

	lis := bufconn.Listen(1024 * 1024)
	go s.Serve(lis)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		conn.Close()
	})

	for _, usrT := range usrs {
		stream, err := userv1.NewMainServiceClient(conn).Connect(
			metadata.AppendToOutgoingContext(ctx, "x-test-session-uid", usrT.Session.Metadata.Uid))
		assert.Nil(t, err, "%+v", err)

		err = stream.Send(&userv1.ConnectRequest{
			Type: &userv1.ConnectRequest_Initialize_{
				Initialize: &userv1.ConnectRequest_Initialize{},
			},
		})
		assert.Nil(t, err, "%+v", err)

		resp, err := stream.Recv()
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, resp.GetState())
	}

	assert.Equal(t, len(usrs), len(getActiveIndexes()))

	for _, usrT := range usrs {
		usrT.Resync()
		assert.True(t, usrT.Session.Status.IsConnected)
		assert.NotNil(t, usrT.Session.Status.Connection)
	}

	assert.Nil(t, stopGRPCServer(s, shutdownTimeout))

	for _, usrT := range usrs {
		usrT.Resync()
		assert.False(t, usrT.Session.Status.IsConnected)
		assert.Nil(t, usrT.Session.Status.Connection)
		assert.Equal(t, 1, len(usrT.Session.Status.LastConnections))
	}

	assert.Equal(t, 0, len(getActiveIndexes()))
}

type shutdownTestServer struct {
	userv1.UnimplementedMainServiceServer
	connectFn func(userv1.MainService_ConnectServer) error
}

func (s *shutdownTestServer) Connect(stream userv1.MainService_ConnectServer) error {
	return s.connectFn(stream)
}

func newShutdownTestServer(t *testing.T, srv *shutdownTestServer,
	opts ...grpc.ServerOption) (*grpc.Server, userv1.MainServiceClient) {
	t.Helper()

	s := newGRPCServer(opts...)
	userv1.RegisterMainServiceServer(s, srv)
	lis := bufconn.Listen(1024 * 1024)
	go s.Serve(lis)

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStaticStreamWindowSize(64*1024),
		grpc.WithStaticConnWindowSize(64*1024))
	if !assert.Nil(t, err, "%+v", err) {
		t.FailNow()
	}
	t.Cleanup(func() {
		conn.Close()
		s.Stop()
	})

	return s, userv1.NewMainServiceClient(conn)
}

func waitForShutdownEvent(t *testing.T, ch <-chan struct{}) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("Timed out waiting for shutdown event")
	}
}

func TestStopGRPCServer(t *testing.T) {
	s := newGRPCServer()

	startedAt := time.Now()
	assert.Nil(t, stopGRPCServer(s, shutdownTimeout))
	assert.True(t, time.Since(startedAt) < time.Second)
}

func TestStopGRPCServerWaitsForCleanup(t *testing.T) {
	canceledCh := make(chan struct{})
	releaseCh := make(chan struct{})
	s, client := newShutdownTestServer(t, &shutdownTestServer{
		connectFn: func(stream userv1.MainService_ConnectServer) error {
			if err := stream.Send(&userv1.ConnectResponse{}); err != nil {
				return err
			}
			<-stream.Context().Done()
			close(canceledCh)
			<-releaseCh
			return nil
		},
	})
	defer close(releaseCh)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	stream, err := client.Connect(ctx)
	assert.Nil(t, err, "%+v", err)
	_, err = stream.Recv()
	assert.Nil(t, err, "%+v", err)

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- stopGRPCServer(s, shutdownTimeout)
	}()
	waitForShutdownEvent(t, canceledCh)

	_, err = stream.Recv()
	assert.NotNil(t, err)
	select {
	case err := <-doneCh:
		t.Fatalf("Shutdown returned before cleanup finished: %+v", err)
	default:
	}

	releaseCh <- struct{}{}
	select {
	case err := <-doneCh:
		assert.Nil(t, err, "%+v", err)
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not finish after cleanup completed")
	}
}

func TestStopGRPCServerTimeout(t *testing.T) {
	for _, unary := range []bool{false, true} {
		name := "stream"
		if unary {
			name = "unary"
		}
		t.Run(name, func(t *testing.T) {
			ctxCh := make(chan context.Context, 1)
			releaseCh := make(chan struct{})
			var opts []grpc.ServerOption
			if unary {
				opts = append(opts, grpc.ChainUnaryInterceptor(func(ctx context.Context,
					req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
					ctxCh <- ctx
					<-releaseCh
					return handler(ctx, req)
				}))
			}
			s, client := newShutdownTestServer(t, &shutdownTestServer{
				connectFn: func(stream userv1.MainService_ConnectServer) error {
					ctxCh <- stream.Context()
					<-releaseCh
					return nil
				},
			}, opts...)
			defer close(releaseCh)

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			rpcErrCh := make(chan error, 1)
			go func() {
				if unary {
					_, err := client.GetStatus(ctx, &userv1.GetStatusRequest{})
					rpcErrCh <- err
					return
				}
				stream, err := client.Connect(ctx)
				if err == nil {
					_, err = stream.Recv()
				}
				rpcErrCh <- err
			}()

			var handlerCtx context.Context
			select {
			case handlerCtx = <-ctxCh:
			case <-ctx.Done():
				t.Fatal("Handler did not start")
			}

			startedAt := time.Now()
			err := stopGRPCServer(s, 50*time.Millisecond)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
			assert.True(t, time.Since(startedAt) < time.Second)
			assert.ErrorIs(t, handlerCtx.Err(), context.Canceled)
			select {
			case err := <-rpcErrCh:
				assert.NotNil(t, err)
			case <-ctx.Done():
				t.Fatal("Client RPC did not disconnect during shutdown")
			}
		})
	}
}

func TestStopGRPCServerBlockedRecv(t *testing.T) {
	startedCh := make(chan struct{})
	s, client := newShutdownTestServer(t, &shutdownTestServer{
		connectFn: func(stream userv1.MainService_ConnectServer) error {
			close(startedCh)
			_, err := stream.Recv()
			return err
		},
	})
	stream, err := client.Connect(t.Context())
	assert.Nil(t, err, "%+v", err)
	waitForShutdownEvent(t, startedCh)

	assert.Nil(t, stopGRPCServer(s, time.Second))
	_, err = stream.Recv()
	assert.NotNil(t, err)
}

func TestStopGRPCServerBlockedSend(t *testing.T) {
	startedCh := make(chan struct{})
	returnedCh := make(chan struct{})
	s, client := newShutdownTestServer(t, &shutdownTestServer{
		connectFn: func(stream userv1.MainService_ConnectServer) error {
			defer close(returnedCh)
			msg := &userv1.ConnectResponse{
				Event: &userv1.ConnectResponse_Message_{
					Message: &userv1.ConnectResponse_Message{
						Message: strings.Repeat("a", 1024*1024),
					},
				},
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
			close(startedCh)
			return stream.Send(msg)
		},
	})
	_, err := client.Connect(t.Context())
	assert.Nil(t, err, "%+v", err)
	waitForShutdownEvent(t, startedCh)
	select {
	case <-returnedCh:
		t.Fatal("Send returned before shutdown")
	case <-time.After(50 * time.Millisecond):
	}

	assert.Nil(t, stopGRPCServer(s, time.Second))
	waitForShutdownEvent(t, returnedCh)
}

func TestStopGRPCServerIncompleteHandshake(t *testing.T) {
	s := newGRPCServer()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.Nil(t, err, "%+v", err) {
		return
	}
	go s.Serve(lis)
	conn, err := net.DialTimeout("tcp", lis.Addr().String(), time.Second)
	if !assert.Nil(t, err, "%+v", err) {
		s.Stop()
		return
	}
	t.Cleanup(func() {
		conn.Close()
		s.Stop()
	})
	assert.Nil(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = http2.NewFramer(io.Discard, conn).ReadFrame()
	if !assert.Nil(t, err, "%+v", err) {
		return
	}

	startedAt := time.Now()
	assert.ErrorIs(t, stopGRPCServer(s, 50*time.Millisecond), context.DeadlineExceeded)
	assert.True(t, time.Since(startedAt) < time.Second)
}

func TestStopGRPCServerProcess(t *testing.T) {
	const envKey = "OCTELIUM_TEST_APISERVER_SHUTDOWN"
	if mode := os.Getenv(envKey); mode != "" {
		components.RunComponent(func(ctx context.Context) error {
			s := newGRPCServer()
			userv1.RegisterMainServiceServer(s, &shutdownTestServer{
				connectFn: func(stream userv1.MainService_ConnectServer) error {
					if err := stream.Send(&userv1.ConnectResponse{}); err != nil {
						return err
					}
					if mode == "handler" {
						<-make(chan struct{})
					}
					<-stream.Context().Done()
					return nil
				},
			})
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return err
			}
			go s.Serve(lis)
			fmt.Fprintln(os.Stdout, lis.Addr().String())
			<-ctx.Done()
			assert.ErrorIs(t, stopGRPCServer(s, shutdownTimeout), context.DeadlineExceeded)
			return nil
		}, &components.RunComponentOpts{CancelOnSIGTERM: true})
		return
	}

	for _, mode := range []string{"handler", "handshake"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*shutdownTimeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestStopGRPCServerProcess$")
			cmd.Env = append(os.Environ(), envKey+"="+mode)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			stdout, err := cmd.StdoutPipe()
			if !assert.Nil(t, err, "%+v", err) {
				return
			}
			if !assert.Nil(t, cmd.Start()) {
				return
			}
			t.Cleanup(func() {
				if cmd.ProcessState == nil {
					cmd.Process.Kill()
					cmd.Wait()
				}
			})

			addr, err := bufio.NewReader(stdout).ReadString('\n')
			if !assert.Nil(t, err, "%+v", err) {
				return
			}
			addr = strings.TrimSpace(addr)
			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if !assert.Nil(t, err, "%+v", err) {
				return
			}
			t.Cleanup(func() { conn.Close() })
			client := userv1.NewMainServiceClient(conn)
			stream, err := client.Connect(ctx)
			if !assert.Nil(t, err, "%+v", err) {
				return
			}
			_, err = stream.Recv()
			if !assert.Nil(t, err, "%+v", err) {
				return
			}

			if mode == "handshake" {
				rawConn, err := net.DialTimeout("tcp", addr, time.Second)
				if !assert.Nil(t, err, "%+v", err) {
					return
				}
				t.Cleanup(func() { rawConn.Close() })
				assert.Nil(t, rawConn.SetReadDeadline(time.Now().Add(time.Second)))
				_, err = http2.NewFramer(io.Discard, rawConn).ReadFrame()
				if !assert.Nil(t, err, "%+v", err) {
					return
				}
			}

			startedAt := time.Now()
			assert.Nil(t, cmd.Process.Signal(syscall.SIGTERM))
			_, err = stream.Recv()
			assert.NotNil(t, err)
			assert.Nil(t, cmd.Wait(), "%s", stderr.String())
			elapsed := time.Since(startedAt)
			assert.True(t, elapsed >= shutdownTimeout)
			assert.True(t, elapsed < shutdownTimeout+3*time.Second)

			s := newGRPCServer()
			userv1.RegisterMainServiceServer(s, &shutdownTestServer{
				connectFn: func(stream userv1.MainService_ConnectServer) error {
					if err := stream.Send(&userv1.ConnectResponse{}); err != nil {
						return err
					}
					<-stream.Context().Done()
					return nil
				},
			})
			lis, err := net.Listen("tcp", addr)
			if !assert.Nil(t, err, "%+v", err) {
				return
			}
			go s.Serve(lis)
			t.Cleanup(s.Stop)

			reconnectCtx, reconnectCancel := context.WithTimeout(ctx, 3*time.Second)
			defer reconnectCancel()
			stream, err = client.Connect(reconnectCtx, grpc.WaitForReady(true))
			if !assert.Nil(t, err, "%+v", err) {
				return
			}
			_, err = stream.Recv()
			assert.Nil(t, err, "%+v", err)
		})
	}
}
