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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

type middleware struct {
	next http.Handler
	sync.RWMutex
	cMap      map[string]extprocsvc.ExternalProcessorClient
	phase     corev1.Service_Spec_Config_HTTP_Plugin_Phase
	celEngine *celengine.CELEngine
}

func New(ctx context.Context, next http.Handler, celEngine *celengine.CELEngine, phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) (http.Handler, error) {
	return &middleware{
		next:      next,
		cMap:      make(map[string]extprocsvc.ExternalProcessorClient),
		phase:     phase,
		celEngine: celEngine,
	}, nil
}

type clientInfo struct {
	c        extprocsvc.ExternalProcessor_ProcessClient
	plugin   *corev1.Service_Spec_Config_HTTP_Plugin_ExtProc
	duration time.Duration
}

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
			c.c.CloseSend()
		}
	}

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
				continue
			}

			client, err := c.Process(ctx)
			if err != nil {
				continue
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

			if err := c.c.Send(&extprocsvc.ProcessingRequest{
				MetadataContext: metadataContext,
				Request: &extprocsvc.ProcessingRequest_RequestHeaders{
					RequestHeaders: &extprocsvc.HttpHeaders{
						Headers: headers,
					},
				},
			}); err != nil {
				continue
			}
			msg, err := doReadResponse(ctx, c.c, c.duration)
			if err != nil {
				continue
			}

			switch msg.Response.(type) {
			case *extprocsvc.ProcessingResponse_RequestHeaders:
				resp := msg.GetRequestHeaders()
				if resp != nil && resp.Response != nil && resp.Response.HeaderMutation != nil {
					mut := resp.Response.HeaderMutation
					for _, hdr := range mut.RemoveHeaders {
						req.Header.Del(hdr)
					}

					for _, hdr := range mut.SetHeaders {
						req.Header.Set(hdr.Header.Key, hdr.Header.Value)
					}
				}
			}
		}

		if c.plugin.ProcessingMode != nil &&
			c.plugin.ProcessingMode.RequestBodyMode ==
				corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_BUFFERED {
			if err := c.c.Send(&extprocsvc.ProcessingRequest{
				MetadataContext: metadataContext,
				Request: &extprocsvc.ProcessingRequest_RequestBody{
					RequestBody: &extprocsvc.HttpBody{
						Body:        reqCtx.Body,
						EndOfStream: true,
					},
				},
			}); err != nil {
				continue
			}
			msg, err := doReadResponse(ctx, c.c, c.duration)
			if err != nil {
				continue
			}

			switch msg.Response.(type) {
			case *extprocsvc.ProcessingResponse_RequestBody:
				resp := msg.GetRequestBody()
				if resp != nil && resp.Response != nil && resp.Response.BodyMutation != nil {
					mut := resp.Response.BodyMutation
					switch mut.Mutation.(type) {
					case *extprocsvc.BodyMutation_Body:
						defer req.Body.Close()
						req.Body = io.NopCloser(bytes.NewReader(mut.GetBody()))
						req.ContentLength = int64(len(mut.GetBody()))
					case *extprocsvc.BodyMutation_ClearBody:
						defer req.Body.Close()
						req.Body = io.NopCloser(bytes.NewReader(nil))
						req.ContentLength = 0
					default:
					}
				}
			case *extprocsvc.ProcessingResponse_ImmediateResponse:
				resp := msg.GetImmediateResponse()
				if resp.Headers != nil {
					for _, hdr := range resp.Headers.SetHeaders {
						rw.Header().Set(hdr.Header.Key, hdr.Header.Value)
					}

					for _, hdr := range resp.Headers.RemoveHeaders {
						rw.Header().Del(hdr)
					}
				}
				rw.Header().Set("Server", "octelium")
				if resp.Status != nil && resp.Status.Code >= 200 && resp.Status.Code < 600 {
					rw.WriteHeader(int(resp.Status.Code))
				}
				rw.Write(resp.Body)

				closeGRPC()
				return
			}
		}

	}

	crw := newResponseWriter(rw)
	m.next.ServeHTTP(crw, req)

	headers = &envoycore.HeaderMap{}
	for k, v := range crw.Header() {
		if len(v) < 1 {
			continue
		}
		headers.Headers = append(headers.Headers, &envoycore.HeaderValue{
			Key:   k,
			Value: v[0],
		})
	}

	for _, c := range clientInfos {
		if c.plugin.ProcessingMode == nil ||
			c.plugin.ProcessingMode.ResponseHeaderMode ==
				corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_HEADER_SEND_MODE_UNSET ||
			c.plugin.ProcessingMode.ResponseHeaderMode ==
				corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_SEND {

			if err := c.c.Send(&extprocsvc.ProcessingRequest{
				MetadataContext: metadataContext,
				Request: &extprocsvc.ProcessingRequest_ResponseHeaders{
					ResponseHeaders: &extprocsvc.HttpHeaders{
						Headers: headers,
					},
				},
			}); err != nil {
				continue
			}
			msg, err := doReadResponse(ctx, c.c, c.duration)
			if err != nil {
				continue
			}

			switch msg.Response.(type) {
			case *extprocsvc.ProcessingResponse_ResponseHeaders:
				resp := msg.GetResponseHeaders()
				if resp != nil && resp.Response != nil && resp.Response.HeaderMutation != nil {
					mut := resp.Response.HeaderMutation
					for _, hdr := range mut.RemoveHeaders {
						crw.Header().Del(hdr)
					}

					for _, hdr := range mut.SetHeaders {
						crw.Header().Set(hdr.Header.Key, hdr.Header.Value)
					}
				}
			}
		}

		if c.plugin.ProcessingMode != nil &&
			c.plugin.ProcessingMode.ResponseBodyMode ==
				corev1.Service_Spec_Config_HTTP_Plugin_ExtProc_ProcessingMode_BUFFERED {
			if err := c.c.Send(&extprocsvc.ProcessingRequest{
				MetadataContext: metadataContext,
				Request: &extprocsvc.ProcessingRequest_ResponseBody{
					ResponseBody: &extprocsvc.HttpBody{
						Body:        crw.body.Bytes(),
						EndOfStream: true,
					},
				},
			}); err != nil {
				continue
			}
			msg, err := doReadResponse(ctx, c.c, c.duration)
			if err != nil {
				continue
			}

			switch msg.Response.(type) {
			case *extprocsvc.ProcessingResponse_ResponseBody:
				resp := msg.GetResponseBody()

				if resp != nil && resp.Response != nil && resp.Response.HeaderMutation != nil {
					mut := resp.Response.HeaderMutation
					for _, hdr := range mut.RemoveHeaders {
						crw.Header().Del(hdr)
					}

					for _, hdr := range mut.SetHeaders {
						crw.Header().Set(hdr.Header.Key, hdr.Header.Value)
					}
				}

				if resp != nil && resp.Response != nil && resp.Response.BodyMutation != nil {
					mut := resp.Response.BodyMutation
					switch mut.Mutation.(type) {
					case *extprocsvc.BodyMutation_Body:
						crw.body.Reset()
						crw.body.Write(mut.GetBody())
						crw.isSet = true
					case *extprocsvc.BodyMutation_ClearBody:
						crw.body.Reset()
						crw.isSet = true
					default:
					}
				}
			}
		}

	}

	/*
		if len(crw.headers) > 0 {
			for k, v := range crw.headers {
				if len(v) > 0 {
					crw.ResponseWriter.Header().Set(k, v[0])
				}
			}
		}
	*/

	{
		crw.ResponseWriter.Header().Set("Content-Length", fmt.Sprintf("%d", len(crw.body.Bytes())))
		crw.ResponseWriter.Write(crw.body.Bytes())
	}

	closeGRPC()
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
		return c, nil
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
	m.cMap[host] = client
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
	}
	return grpc.NewClient(host, opts...)
}

type readResp struct {
	res *extprocsvc.ProcessingResponse
	err error
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

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	// headers    http.Header
	body  *bytes.Buffer
	isSet bool
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		// headers:        make(http.Header),
		body: new(bytes.Buffer),
	}
}

/*
func (rw *responseWriter) Header() http.Header {
	return rw.headers
}
*/

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	return rw.body.Write(b)
}

func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.Errorf("ResponseWriter is not a Hijacker")
	}

	return hj.Hijack()
}

func (w *responseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (p *responseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := p.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
