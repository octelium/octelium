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

package extproc

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocsvc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type tstSrv struct {
	reqHeader string
	rspHeader string
	rspBody   string
	reqBody   string

	timeout time.Duration
}

func (s *tstSrv) Process(srv extprocsvc.ExternalProcessor_ProcessServer) error {
	ctx := srv.Context()

	for {

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		req, err := srv.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Unknown, "%v", err)
		}

		zap.L().Debug("___________Received REQ", zap.Any("req", req))
		switch req.Request.(type) {
		case *extprocsvc.ProcessingRequest_RequestBody:
			time.Sleep(s.timeout)
			if err := srv.Send(&extprocsvc.ProcessingResponse{
				Response: &extprocsvc.ProcessingResponse_RequestBody{
					RequestBody: &extprocsvc.BodyResponse{
						Response: &extprocsvc.CommonResponse{
							BodyMutation: &extprocsvc.BodyMutation{
								Mutation: &extprocsvc.BodyMutation_Body{
									Body: []byte(s.reqBody),
								},
							},
						},
					},
				},
			}); err != nil {
				return err
			}
		case *extprocsvc.ProcessingRequest_RequestHeaders:
			time.Sleep(s.timeout)
			if err := srv.Send(&extprocsvc.ProcessingResponse{
				Response: &extprocsvc.ProcessingResponse_RequestHeaders{
					RequestHeaders: &extprocsvc.HeadersResponse{
						Response: &extprocsvc.CommonResponse{
							HeaderMutation: &extprocsvc.HeaderMutation{
								SetHeaders: []*envoycore.HeaderValueOption{
									{
										Header: &envoycore.HeaderValue{
											Key:   "X-Octelium-Custom-1",
											Value: s.reqHeader,
										},
									},
								},
							},
						},
					},
				},
			}); err != nil {
				return err
			}
			zap.L().Debug("Sent resp", zap.Error(err))
		case *extprocsvc.ProcessingRequest_ResponseBody:
			time.Sleep(s.timeout)
			if err := srv.Send(&extprocsvc.ProcessingResponse{
				Response: &extprocsvc.ProcessingResponse_ResponseBody{
					ResponseBody: &extprocsvc.BodyResponse{
						Response: &extprocsvc.CommonResponse{
							BodyMutation: &extprocsvc.BodyMutation{
								Mutation: &extprocsvc.BodyMutation_Body{
									Body: []byte(s.rspBody),
								},
							},
						},
					},
				},
			}); err != nil {
				return err
			}
		case *extprocsvc.ProcessingRequest_ResponseHeaders:
			time.Sleep(s.timeout)
			if err := srv.Send(&extprocsvc.ProcessingResponse{
				Response: &extprocsvc.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &extprocsvc.HeadersResponse{
						Response: &extprocsvc.CommonResponse{
							HeaderMutation: &extprocsvc.HeaderMutation{
								SetHeaders: []*envoycore.HeaderValueOption{
									{
										Header: &envoycore.HeaderValue{
											Key:   "X-Octelium-Custom-1",
											Value: s.rspHeader,
										},
									},
								},
							},
						},
					},
				},
			}); err != nil {
				return err
			}
			zap.L().Debug("Sent resp", zap.Error(err))
		default:
			zap.L().Debug("Unknown req type")
		}
	}
}

func TestMiddleware(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	port := tests.GetPort()

	grpcSrv := grpc.NewServer(
		grpc.MaxConcurrentStreams(100*1000),
		grpc.ConnectionTimeout(10000*time.Second),
		grpc.MaxRecvMsgSize(200*1024),
		grpc.ReadBufferSize(32*1024),
	)

	tstSrv := &tstSrv{
		reqHeader: utilrand.GetRandomString(32),
		rspHeader: utilrand.GetRandomString(32),
		rspBody:   utilrand.GetRandomString(32),
		reqBody:   utilrand.GetRandomString(32),
	}

	extprocsvc.RegisterExternalProcessorServer(grpcSrv, tstSrv)

	lisGRPC, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	assert.Nil(t, err)

	go func() {
		zap.S().Debug("running gRPC server...")
		if err := grpcSrv.Serve(lisGRPC); err != nil {
			zap.S().Infof("gRPC server closed: %+v", err)
		}
	}()

	time.Sleep(2 * time.Second)

	var rReq *http.Request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rReq = r
	})

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)
	mdlwr, err := New(ctx, next, celEngine, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
	assert.Nil(t, err)

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),

				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_{
										ExtProc: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc{
											Type: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_Address{
												Address: fmt.Sprintf("localhost:%d", port),
											},
											ProcessingMode: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode{
												ResponseBodyMode: corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_BUFFERED,
												RequestBodyMode:  corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_BUFFERED,
											},
										},
									},
								},
							},
						},
					},
				},
			}))

		rw := httptest.NewRecorder()

		mdlwr.ServeHTTP(rw, req)

		defer rReq.Body.Close()
		reqBody, err := io.ReadAll(rReq.Body)
		assert.Nil(t, err)

		assert.Equal(t, tstSrv.reqHeader, rReq.Header.Get("X-Octelium-Custom-1"))
		assert.Equal(t, tstSrv.rspHeader, rw.Header().Get("X-Octelium-Custom-1"))

		assert.Equal(t, tstSrv.rspBody, rw.Body.String())
		assert.Equal(t, tstSrv.reqBody, string(reqBody))
	}

	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),
			}))

		rw := httptest.NewRecorder()

		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, "", rReq.Header.Get("X-Octelium-Custom-1"))
		assert.Equal(t, "", rw.Header().Get("X-Octelium-Custom-1"))

		assert.Equal(t, "", rw.Body.String())
	}

}

func TestMiddlewareTimeout(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	port := tests.GetPort()

	grpcSrv := grpc.NewServer(
		grpc.MaxConcurrentStreams(100*1000),
		grpc.ConnectionTimeout(10000*time.Second),
		grpc.MaxRecvMsgSize(200*1024),
		grpc.ReadBufferSize(32*1024),
	)

	tstSrv := &tstSrv{
		reqHeader: utilrand.GetRandomString(32),
		rspHeader: utilrand.GetRandomString(32),
		rspBody:   utilrand.GetRandomString(32),
		timeout:   1000 * time.Millisecond,
	}

	extprocsvc.RegisterExternalProcessorServer(grpcSrv, tstSrv)

	lisGRPC, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	assert.Nil(t, err)

	go func() {
		zap.S().Debug("running gRPC server...")
		if err := grpcSrv.Serve(lisGRPC); err != nil {
			zap.S().Infof("gRPC server closed: %+v", err)
		}
	}()

	time.Sleep(2 * time.Second)

	var rReq *http.Request
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rReq = r
	})
	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)
	mdlwr, err := New(ctx, next, celEngine, corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)
	assert.Nil(t, err)
	{
		req := httptest.NewRequest(http.MethodGet, "http://localhost/prefix/v1", nil)

		req = req.WithContext(context.WithValue(context.Background(),
			middlewares.CtxRequestContext,
			&middlewares.RequestContext{
				CreatedAt: time.Now(),

				ServiceConfig: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
								{
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
									Type: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_{
										ExtProc: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc{
											Type: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_Address{
												Address: fmt.Sprintf("localhost:%d", port),
											},
											ProcessingMode: &corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode{
												ResponseBodyMode: corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_BUFFERED,
											},
										},
									},
								},
							},
						},
					},
				},
			}))

		rw := httptest.NewRecorder()

		mdlwr.ServeHTTP(rw, req)

		assert.Equal(t, "", rReq.Header.Get("X-Octelium-Custom-1"))
		assert.Equal(t, "", rw.Header().Get("X-Octelium-Custom-1"))

		assert.Equal(t, "", rw.Body.String())
	}
}
