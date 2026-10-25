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

package octovigilc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

type tstInternalC struct {
	coctovigilv1.InternalServiceClient
	sentBody []byte
}

type tstInternalErrC struct {
	coctovigilv1.InternalServiceClient
	authenticate func(context.Context, *coctovigilv1.AuthenticateAndAuthorizeRequest) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error)
	authorize    func(context.Context, *coctovigilv1.AuthorizeRequest) (*coctovigilv1.AuthorizeResponse, error)
}

func (c *tstInternalErrC) AuthenticateAndAuthorize(ctx context.Context,
	in *coctovigilv1.AuthenticateAndAuthorizeRequest,
	opts ...grpc.CallOption) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
	return c.authenticate(ctx, in)
}

func (c *tstInternalErrC) Authorize(ctx context.Context,
	in *coctovigilv1.AuthorizeRequest,
	opts ...grpc.CallOption) (*coctovigilv1.AuthorizeResponse, error) {
	return c.authorize(ctx, in)
}

func TestRemoteBodyRestoredOnError(t *testing.T) {
	for _, tc := range []struct {
		name string
		wrap func(*corev1.RequestContext_Request_HTTP) *corev1.RequestContext_Request
	}{
		{"HTTP", func(h *corev1.RequestContext_Request_HTTP) *corev1.RequestContext_Request {
			return &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{Http: h}}
		}},
		{"Kubernetes", func(h *corev1.RequestContext_Request_HTTP) *corev1.RequestContext_Request {
			return &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Kubernetes_{
				Kubernetes: &corev1.RequestContext_Request_Kubernetes{Http: h},
			}}
		}},
		{"gRPC", func(h *corev1.RequestContext_Request_HTTP) *corev1.RequestContext_Request {
			return &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Grpc{Grpc: &corev1.RequestContext_Request_GRPC{Http: h}}}
		}},
		{"MCP", func(h *corev1.RequestContext_Request_HTTP) *corev1.RequestContext_Request {
			return &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Mcp{Mcp: &corev1.RequestContext_Request_MCP{Http: h}}}
		}},
		{"LLM", func(h *corev1.RequestContext_Request_HTTP) *corev1.RequestContext_Request {
			return &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Llm{Llm: &corev1.RequestContext_Request_LLM{Http: h}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, code := range []codes.Code{codes.Canceled, codes.DeadlineExceeded, codes.Unavailable, codes.Internal, codes.PermissionDenied} {
				body := []byte(`{"key":"value"}`)
				h := &corev1.RequestContext_Request_HTTP{Body: body, BodyMap: pbutils.MapToStructMust(map[string]any{"key": "value"})}
				internal := &tstInternalErrC{authenticate: func(ctx context.Context, in *coctovigilv1.AuthenticateAndAuthorizeRequest) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
					assert.Equal(t, "service", in.ServiceUID)
					assert.Empty(t, ucorev1.GetRequestHTTP(in.Request.Request).Body)
					deadline, ok := ctx.Deadline()
					assert.True(t, ok)
					assert.LessOrEqual(t, time.Until(deadline), requestTimeout)
					return nil, status.Error(code, "unavailable decision")
				}}
				c := &Client{svcUID: "service", remoteC: &tstRemoteC{internalC: internal}}
				resp, err := c.AuthenticateAndAuthorize(t.Context(), &AuthenticateAndAuthorizeRequest{
					Request: &coctovigilv1.DownstreamRequest{Request: tc.wrap(h)},
				})
				assert.Equal(t, code, status.Code(err))
				assert.Nil(t, resp)
				assert.Equal(t, body, h.Body)
				require.NotNil(t, h.BodyMap)
				assert.Equal(t, "value", h.BodyMap.Fields["key"].GetStringValue())
			}
		})
	}
}

func TestRemoteAuthorizeServiceBinding(t *testing.T) {
	request := &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Postgres_{
		Postgres: &corev1.RequestContext_Request_Postgres{},
	}}
	internal := &tstInternalErrC{authorize: func(ctx context.Context, in *coctovigilv1.AuthorizeRequest) (*coctovigilv1.AuthorizeResponse, error) {
		assert.Equal(t, "service", in.ServiceUID)
		assert.Equal(t, "session", in.SessionUID)
		assert.Equal(t, request, in.Request)
		return &coctovigilv1.AuthorizeResponse{IsAuthorized: false}, nil
	}}
	c := &Client{svcUID: "service", remoteC: &tstRemoteC{internalC: internal}}
	resp, err := c.Authorize(t.Context(), &coctovigilv1.AuthorizeRequest{
		ServiceUID: "other-service", SessionUID: "session", Request: request,
	})
	require.Nil(t, err)
	assert.False(t, resp.IsAuthorized)
}

func TestConcurrentRemoteRequests(t *testing.T) {
	internal := &tstInternalErrC{authenticate: func(ctx context.Context, in *coctovigilv1.AuthenticateAndAuthorizeRequest) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
		h := ucorev1.GetRequestHTTP(in.Request.Request)
		assert.Empty(t, h.Body)
		return &coctovigilv1.AuthenticateAndAuthorizeResponse{RequestContext: &corev1.RequestContext{
			Request: pbutils.Clone(in.Request.Request).(*corev1.RequestContext_Request),
		}}, nil
	}}
	c := &Client{svcUID: "service", remoteC: &tstRemoteC{internalC: internal}}
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			body := []byte{byte(i)}
			h := &corev1.RequestContext_Request_HTTP{Body: body, BodyMap: &structpb.Struct{}}
			resp, err := c.AuthenticateAndAuthorize(t.Context(), &AuthenticateAndAuthorizeRequest{
				Request: &coctovigilv1.DownstreamRequest{Request: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Http{Http: h},
				}},
			})
			if !assert.Nil(t, err) {
				return
			}
			assert.Equal(t, body, h.Body)
			assert.Equal(t, body, resp.RequestContext.Request.GetHttp().Body)
		})
	}
	wg.Wait()
}

func (c *tstInternalC) AuthenticateAndAuthorize(ctx context.Context,
	in *coctovigilv1.AuthenticateAndAuthorizeRequest,
	opts ...grpc.CallOption) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {

	c.sentBody = ucorev1.GetRequestHTTP(in.Request.GetRequest()).GetBody()

	return &coctovigilv1.AuthenticateAndAuthorizeResponse{
		IsAuthorized: true,
		RequestContext: &corev1.RequestContext{
			Request: pbutils.Clone(in.Request.GetRequest()).(*corev1.RequestContext_Request),
		},
	}, nil
}

type tstRemoteC struct {
	internalC coctovigilv1.InternalServiceClient
}

func (c *tstRemoteC) InternalC() coctovigilv1.InternalServiceClient {
	return c.internalC
}

func TestRequestBodyIsNotSentToOctovigil(t *testing.T) {

	ctx := context.Background()

	body := []byte(`{"model": "gpt"}`)

	newReq := func(bodyMap *structpb.Struct) *AuthenticateAndAuthorizeRequest {
		return &AuthenticateAndAuthorizeRequest{
			Request: &coctovigilv1.DownstreamRequest{
				Request: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Http{
						Http: &corev1.RequestContext_Request_HTTP{
							Body:    body,
							BodyMap: bodyMap,
						},
					},
				},
			},
		}
	}

	{
		internalC := &tstInternalC{}
		c := &Client{remoteC: &tstRemoteC{internalC: internalC}}

		req := newReq(pbutils.MapToStructMust(map[string]any{"model": "gpt"}))

		resp, err := c.AuthenticateAndAuthorize(ctx, req)
		assert.Nil(t, err)

		assert.Nil(t, internalC.sentBody)
		assert.Equal(t, body,
			ucorev1.GetRequestHTTP(req.Request.GetRequest()).GetBody())
		assert.Equal(t, body,
			ucorev1.GetRequestHTTP(resp.GetRequestContext().GetRequest()).GetBody())
		assert.NotNil(t,
			ucorev1.GetRequestHTTP(resp.GetRequestContext().GetRequest()).GetBodyMap())
	}

	{
		internalC := &tstInternalC{}
		c := &Client{remoteC: &tstRemoteC{internalC: internalC}}

		req := newReq(nil)

		resp, err := c.AuthenticateAndAuthorize(ctx, req)
		assert.Nil(t, err)

		assert.Equal(t, body, internalC.sentBody)
		assert.Equal(t, body,
			ucorev1.GetRequestHTTP(req.Request.GetRequest()).GetBody())
		assert.Equal(t, body,
			ucorev1.GetRequestHTTP(resp.GetRequestContext().GetRequest()).GetBody())
	}
}
