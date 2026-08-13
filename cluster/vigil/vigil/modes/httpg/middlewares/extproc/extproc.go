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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocsvc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/commonplugin"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

type middleware struct {
	next http.Handler
	sync.RWMutex
	cMap      map[string]*extProcClient
	phase     corev1.Service_Spec_Config_HTTP_Plugin_Phase
	celEngine *celengine.CELEngine
}

func New(ctx context.Context, next http.Handler, celEngine *celengine.CELEngine, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) (http.Handler, error) {
	ret := &middleware{
		next:      next,
		cMap:      make(map[string]*extProcClient),
		phase:     phase,
		celEngine: celEngine,
	}

	go func() {
		<-ctx.Done()

		ret.Lock()
		defer ret.Unlock()

		for host, c := range ret.cMap {
			c.conn.Close()
			delete(ret.cMap, host)
		}
	}()

	return ret, nil
}

type extProcClient struct {
	c    extprocsvc.ExternalProcessorClient
	conn *grpc.ClientConn
}

type clientInfo struct {
	c        extprocsvc.ExternalProcessor_ProcessClient
	plugin   *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc
	duration time.Duration
	cancelFn context.CancelFunc
}

const maxBodySize = 32 * 1024 * 1024
const maxClients = 64

var errBodyTooLarge = errors.Errorf("body size exceeds the maximum allowed size")

func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	ctx := req.Context()

	reqCtx := middlewares.GetCtxRequestContext(ctx)
	cfg := reqCtx.ServiceConfig

	if cfg == nil || cfg.GetHttp() == nil || len(cfg.GetHttp().Plugins) == 0 {
		m.next.ServeHTTP(rw, req)
		return
	}

	var clientInfos []*clientInfo
	closeGRPC := func() {
		for _, c := range clientInfos {
			c.cancelFn()
		}
	}
	defer closeGRPC()

	for _, plugin := range cfg.GetHttp().Plugins {
		switch plugin.Type.(type) {
		case *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_:

			if !commonplugin.ShouldEnforcePlugin(ctx, &commonplugin.ShouldEnforcePluginOpts{
				Plugin:    plugin,
				CELEngine: m.celEngine,
				Phase:     m.phase,
			}) {
				continue
			}

			c, err := m.getClient(plugin.GetExtProc())
			if err != nil {
				m.handleError(rw, err)
				return
			}

			streamCtx, cancelFn := context.WithCancel(ctx)
			client, err := c.Process(streamCtx)
			if err != nil {
				cancelFn()
				m.handleError(rw, err)
				return
			}

			duration := 800 * time.Millisecond

			confDuration := umetav1.ToDuration(plugin.GetExtProc().MessageTimeout).ToGo()
			if confDuration > 0 && confDuration < 6000*time.Millisecond {
				duration = confDuration
			}

			clientInfos = append(clientInfos, &clientInfo{
				c:        client,
				plugin:   plugin.GetExtProc(),
				duration: duration,
				cancelFn: cancelFn,
			})
		default:
			continue
		}
	}

	if len(clientInfos) == 0 {
		m.next.ServeHTTP(rw, req)
		return
	}

	headers := &envoycore.HeaderMap{}
	for k, v := range req.Header {
		if len(v) < 1 {
			continue
		}
		headers.Headers = append(headers.Headers, &envoycore.HeaderValue{
			Key:   k,
			Value: v[0],
		})
	}

	metadataContext := &envoycore.Metadata{
		FilterMetadata: map[string]*structpb.Struct{
			"ctx": pbutils.MessageToStructMust(reqCtx.DownstreamInfo),
		},
	}

	for _, c := range clientInfos {
		if c.plugin.ProcessingMode == nil ||
			c.plugin.ProcessingMode.RequestHeaderMode ==
				corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_HEADER_SEND_MODE_UNSET ||
			c.plugin.ProcessingMode.RequestHeaderMode ==
				corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_SEND {

			msg, err := c.process(ctx, &extprocsvc.ProcessingRequest{
				MetadataContext: metadataContext,
				Request: &extprocsvc.ProcessingRequest_RequestHeaders{
					RequestHeaders: &extprocsvc.HttpHeaders{
						Headers: headers,
					},
				},
			})
			if err != nil {
				m.handleError(rw, err)
				return
			}

			switch msg.Response.(type) {
			case *extprocsvc.ProcessingResponse_RequestHeaders:
				resp := msg.GetRequestHeaders()
				if resp == nil {
					m.handleError(rw, errors.Errorf("nil extProc response"))
					return
				}
				if resp != nil && resp.Response != nil && resp.Response.HeaderMutation != nil {
					mut := resp.Response.HeaderMutation
					for _, hdr := range mut.RemoveHeaders {
						req.Header.Del(hdr)
					}

					for _, hdr := range mut.SetHeaders {
						if hdr == nil || hdr.Header == nil {
							continue
						}
						req.Header.Set(hdr.Header.Key, hdr.Header.Value)
					}
				}
			case *extprocsvc.ProcessingResponse_ImmediateResponse:
				writeImmediateResponse(rw, msg.GetImmediateResponse())
				return
			default:
				m.handleError(rw, errors.Errorf("unexpected extProc response"))
				return
			}
		}

		if c.plugin.ProcessingMode != nil &&
			c.plugin.ProcessingMode.RequestBodyMode ==
				corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_BUFFERED {
			msg, err := c.process(ctx, &extprocsvc.ProcessingRequest{
				MetadataContext: metadataContext,
				Request: &extprocsvc.ProcessingRequest_RequestBody{
					RequestBody: &extprocsvc.HttpBody{
						Body:        reqCtx.Body,
						EndOfStream: true,
					},
				},
			})
			if err != nil {
				m.handleError(rw, err)
				return
			}

			switch msg.Response.(type) {
			case *extprocsvc.ProcessingResponse_RequestBody:
				resp := msg.GetRequestBody()
				if resp == nil {
					m.handleError(rw, errors.Errorf("nil extProc response"))
					return
				}
				if resp != nil && resp.Response != nil && resp.Response.BodyMutation != nil {
					mut := resp.Response.BodyMutation
					switch mut.Mutation.(type) {
					case *extprocsvc.BodyMutation_Body:
						if req.Body != nil {
							req.Body.Close()
						}
						reqCtx.Body = mut.GetBody()
						reqCtx.BodyJSONMap = nil
						req.Body = io.NopCloser(bytes.NewReader(mut.GetBody()))
						req.ContentLength = int64(len(mut.GetBody()))
						req.TransferEncoding = nil
					case *extprocsvc.BodyMutation_ClearBody:
						if req.Body != nil {
							req.Body.Close()
						}
						reqCtx.Body = nil
						reqCtx.BodyJSONMap = nil
						req.Body = io.NopCloser(bytes.NewReader(nil))
						req.ContentLength = 0
						req.TransferEncoding = nil
					default:
					}
				}
			case *extprocsvc.ProcessingResponse_ImmediateResponse:
				writeImmediateResponse(rw, msg.GetImmediateResponse())
				return
			default:
				m.handleError(rw, errors.Errorf("unexpected extProc response"))
				return
			}
		}

	}

	responseCtx, cancelFn := context.WithCancel(ctx)
	defer cancelFn()
	crw := newResponseWriter(rw, isResponseBodyBuffered(clientInfos), cancelFn)
	crw.processHeaders = func() bool {
		resp, err := processResponseHeaders(responseCtx, clientInfos,
			metadataContext, crw.Header())
		if err != nil {
			m.handleError(rw, err)
			return false
		}
		if resp != nil {
			writeImmediateResponse(rw, resp)
			return false
		}
		return true
	}
	crw.closeFn = closeGRPC
	m.next.ServeHTTP(crw, req.WithContext(responseCtx))
	if crw.err != nil {
		m.handleError(rw, crw.err)
		return
	}
	if !crw.buffering {
		crw.sendHeaders()
		return
	}
	if !crw.processResponseHeaders() {
		return
	}

	for _, c := range clientInfos {
		if c.plugin.ProcessingMode != nil &&
			c.plugin.ProcessingMode.ResponseBodyMode ==
				corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_BUFFERED {
			msg, err := c.process(ctx, &extprocsvc.ProcessingRequest{
				MetadataContext: metadataContext,
				Request: &extprocsvc.ProcessingRequest_ResponseBody{
					ResponseBody: &extprocsvc.HttpBody{
						Body:        crw.body.Bytes(),
						EndOfStream: true,
					},
				},
			})
			if err != nil {
				m.handleError(rw, err)
				return
			}

			switch msg.Response.(type) {
			case *extprocsvc.ProcessingResponse_ResponseBody:
				resp := msg.GetResponseBody()
				if resp == nil {
					m.handleError(rw, errors.Errorf("nil extProc response"))
					return
				}

				if resp != nil && resp.Response != nil && resp.Response.HeaderMutation != nil {
					mut := resp.Response.HeaderMutation
					for _, hdr := range mut.RemoveHeaders {
						crw.Header().Del(hdr)
					}

					for _, hdr := range mut.SetHeaders {
						if hdr == nil || hdr.Header == nil {
							continue
						}
						crw.Header().Set(hdr.Header.Key, hdr.Header.Value)
					}
				}

				if resp != nil && resp.Response != nil && resp.Response.BodyMutation != nil {
					mut := resp.Response.BodyMutation
					switch mut.Mutation.(type) {
					case *extprocsvc.BodyMutation_Body:
						if len(mut.GetBody()) > maxBodySize {
							m.handleError(rw, errBodyTooLarge)
							return
						}
						crw.body.Reset()
						crw.body.Write(mut.GetBody())
						crw.isSet = true
					case *extprocsvc.BodyMutation_ClearBody:
						crw.body.Reset()
						crw.isSet = true
					default:
					}
				}
			case *extprocsvc.ProcessingResponse_ImmediateResponse:
				writeImmediateResponse(rw, msg.GetImmediateResponse())
				return
			default:
				m.handleError(rw, errors.Errorf("unexpected extProc response"))
				return
			}
		}

	}

	{
		if req.Method != http.MethodHead {
			crw.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(crw.body.Len()))
		}
		if crw.statusCode != 0 {
			crw.ResponseWriter.WriteHeader(crw.statusCode)
		}
		crw.ResponseWriter.Write(crw.body.Bytes())
	}

}

func (m *middleware) getClient(p *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc) (extprocsvc.ExternalProcessorClient, error) {
	m.RLock()
	host, err := m.getHost(p)
	if err != nil {
		m.RUnlock()
		return nil, err
	}

	c, ok := m.cMap[host]
	if ok {
		m.RUnlock()
		return c.c, nil
	}
	if len(m.cMap) >= maxClients {
		m.RUnlock()
		return nil, errors.Errorf("extProc client cache is full")
	}
	m.RUnlock()

	return m.setAndGetClient(p)
}

func (m *middleware) setAndGetClient(p *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc) (extprocsvc.ExternalProcessorClient, error) {

	host, err := m.getHost(p)
	if err != nil {
		return nil, err
	}

	grpcConn, err := getGRPCConn(host)
	if err != nil {
		return nil, err
	}
	client := extprocsvc.NewExternalProcessorClient(grpcConn)

	m.Lock()
	if c, ok := m.cMap[host]; ok {
		m.Unlock()
		grpcConn.Close()
		return c.c, nil
	}
	if len(m.cMap) >= maxClients {
		m.Unlock()
		grpcConn.Close()
		return nil, errors.Errorf("extProc client cache is full")
	}
	m.cMap[host] = &extProcClient{
		c:    client,
		conn: grpcConn,
	}
	m.Unlock()
	return client, nil
}

func (m *middleware) getHost(p *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc) (string, error) {
	switch p.Type.(type) {
	case *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_Address:
		return p.GetAddress(), nil
	case *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_Container_:
		return net.JoinHostPort("localhost", fmt.Sprintf("%d", p.GetContainer().Port)), nil
	default:
		return "", errors.Errorf("Unset extProc type")
	}
}

func getGRPCConn(host string) (*grpc.ClientConn, error) {

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxBodySize+1024*1024),
			grpc.MaxCallSendMsgSize(maxBodySize+1024*1024),
		),
	}
	return grpc.NewClient(host, opts...)
}

type readResp struct {
	res *extprocsvc.ProcessingResponse
	err error
}

func (c *clientInfo) process(ctx context.Context, req *extprocsvc.ProcessingRequest) (*extprocsvc.ProcessingResponse, error) {
	errCh := make(chan error, 1)

	go func() {
		errCh <- c.c.Send(req)
	}()

	select {
	case <-ctx.Done():
		c.cancelFn()
		return nil, ctx.Err()
	case err := <-errCh:
		if err != nil {
			c.cancelFn()
			return nil, err
		}
	case <-time.After(c.duration):
		c.cancelFn()
		return nil, errors.Errorf("send msg timeout")
	}

	res, err := doReadResponse(ctx, c.c, c.duration)
	if err != nil {
		c.cancelFn()
		return nil, err
	}
	return res, nil
}

func doReadResponse(ctx context.Context, c extprocsvc.ExternalProcessor_ProcessClient, duration time.Duration) (*extprocsvc.ProcessingResponse, error) {

	resCh := make(chan *readResp, 1)

	go func() {
		res, err := c.Recv()
		resCh <- &readResp{
			res: res,
			err: err,
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		return res.res, res.err
	case <-time.After(duration):
		return nil, errors.Errorf("read msg timeout")
	}
}

func (m *middleware) handleError(rw http.ResponseWriter, err error) {
	zap.L().Warn("Could not process extProc request", zap.Error(err))
	for k := range rw.Header() {
		rw.Header().Del(k)
	}
	rw.Header().Set("Server", "octelium")
	http.Error(rw, "Octelium: external processor error", http.StatusBadGateway)
}

func writeImmediateResponse(rw http.ResponseWriter, resp *extprocsvc.ImmediateResponse) {
	for k := range rw.Header() {
		rw.Header().Del(k)
	}
	if resp == nil {
		http.Error(rw, "Octelium: external processor error", http.StatusBadGateway)
		return
	}
	if resp.Headers != nil {
		for _, hdr := range resp.Headers.SetHeaders {
			if hdr == nil || hdr.Header == nil {
				continue
			}
			rw.Header().Set(hdr.Header.Key, hdr.Header.Value)
		}

		for _, hdr := range resp.Headers.RemoveHeaders {
			rw.Header().Del(hdr)
		}
	}
	rw.Header().Set("Server", "octelium")
	if resp.Status != nil && resp.Status.Code >= 200 && resp.Status.Code < 600 {
		rw.WriteHeader(int(resp.Status.Code))
	} else {
		rw.WriteHeader(http.StatusForbidden)
	}
	rw.Write(resp.Body)
}

func isResponseBodyBuffered(clientInfos []*clientInfo) bool {
	for _, c := range clientInfos {
		if c.plugin.ProcessingMode != nil &&
			c.plugin.ProcessingMode.ResponseBodyMode ==
				corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_BUFFERED {
			return true
		}
	}
	return false
}

func processResponseHeaders(ctx context.Context, clientInfos []*clientInfo,
	metadataContext *envoycore.Metadata, headers http.Header) (*extprocsvc.ImmediateResponse, error) {
	for _, c := range clientInfos {
		if c.plugin.ProcessingMode != nil &&
			c.plugin.ProcessingMode.ResponseHeaderMode !=
				corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_HEADER_SEND_MODE_UNSET &&
			c.plugin.ProcessingMode.ResponseHeaderMode !=
				corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_SEND {
			continue
		}

		headerMap := &envoycore.HeaderMap{}
		for k, v := range headers {
			if len(v) < 1 {
				continue
			}
			headerMap.Headers = append(headerMap.Headers, &envoycore.HeaderValue{
				Key:   k,
				Value: v[0],
			})
		}

		msg, err := c.process(ctx, &extprocsvc.ProcessingRequest{
			MetadataContext: metadataContext,
			Request: &extprocsvc.ProcessingRequest_ResponseHeaders{
				ResponseHeaders: &extprocsvc.HttpHeaders{
					Headers: headerMap,
				},
			},
		})
		if err != nil {
			return nil, err
		}

		switch msg.Response.(type) {
		case *extprocsvc.ProcessingResponse_ResponseHeaders:
			resp := msg.GetResponseHeaders()
			if resp == nil {
				return nil, errors.Errorf("nil extProc response")
			}
			if resp != nil && resp.Response != nil && resp.Response.HeaderMutation != nil {
				mut := resp.Response.HeaderMutation
				for _, hdr := range mut.RemoveHeaders {
					headers.Del(hdr)
				}

				for _, hdr := range mut.SetHeaders {
					if hdr == nil || hdr.Header == nil {
						continue
					}
					headers.Set(hdr.Header.Key, hdr.Header.Value)
				}
			}
		case *extprocsvc.ProcessingResponse_ImmediateResponse:
			return msg.GetImmediateResponse(), nil
		default:
			return nil, errors.Errorf("unexpected extProc response")
		}
	}
	return nil, nil
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	// headers    http.Header
	body         *bytes.Buffer
	isSet        bool
	err          error
	buffering    bool
	wroteHeader  bool
	headersSent  bool
	responseSent bool
	stopped      bool
	hijacked     bool

	processHeaders func() bool
	closeFn        func()
	cancelFn       context.CancelFunc
}

func newResponseWriter(w http.ResponseWriter, buffering bool, cancelFn context.CancelFunc) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		// headers:        make(http.Header),
		body:       new(bytes.Buffer),
		statusCode: http.StatusOK,
		buffering:  buffering,
		cancelFn:   cancelFn,
	}
}

/*
func (rw *responseWriter) Header() http.Header {
	return rw.headers
}
*/

func (rw *responseWriter) WriteHeader(code int) {
	if rw.wroteHeader || rw.stopped || rw.hijacked {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		rw.ResponseWriter.WriteHeader(code)
		return
	}
	rw.statusCode = code
	rw.wroteHeader = true
	if !rw.buffering {
		rw.sendHeaders()
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	if rw.stopped {
		return 0, errors.Errorf("extProc response is stopped")
	}
	if !rw.buffering {
		rw.sendHeaders()
		if rw.stopped {
			return 0, errors.Errorf("extProc response is stopped")
		}
		return rw.ResponseWriter.Write(b)
	}
	if len(b) > maxBodySize-rw.body.Len() {
		rw.err = errBodyTooLarge
		rw.cancelFn()
		return 0, rw.err
	}
	return rw.body.Write(b)
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if rw.buffering {
		rw.err = errors.Errorf("Cannot hijack a buffered response")
		rw.cancelFn()
		return nil, nil, rw.err
	}
	hj, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}
	rw.hijacked = true
	rw.closeFn()
	return hj.Hijack()
}

func (rw *responseWriter) Flush() {
	if rw.buffering {
		return
	}
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	if !rw.stopped {
		if f, ok := rw.ResponseWriter.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func (p *responseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := p.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func (rw *responseWriter) processResponseHeaders() bool {
	if rw.headersSent {
		return !rw.stopped
	}
	rw.headersSent = true
	if rw.processHeaders != nil && !rw.processHeaders() {
		rw.stopped = true
		rw.cancelFn()
		rw.closeFn()
		return false
	}
	return true
}

func (rw *responseWriter) sendHeaders() bool {
	if rw.responseSent || rw.hijacked {
		return !rw.stopped
	}
	if !rw.processResponseHeaders() {
		return false
	}
	rw.responseSent = true
	rw.ResponseWriter.WriteHeader(rw.statusCode)
	return true
}
