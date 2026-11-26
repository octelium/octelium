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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
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

func TestNewClientMissingOptions(t *testing.T) {
	for _, opts := range []*Opts{nil, {}} {
		c, err := NewClient(t.Context(), opts)
		assert.NotNil(t, err)
		assert.Nil(t, c)
	}
}

func TestRemotePreservesParentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	want, ok := ctx.Deadline()
	require.True(t, ok)
	internal := &tstInternalErrC{
		authenticate: func(ctx context.Context, req *coctovigilv1.AuthenticateAndAuthorizeRequest) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
			got, ok := ctx.Deadline()
			assert.True(t, ok)
			assert.Equal(t, want, got)
			assert.Nil(t, req.Request.Request)
			return &coctovigilv1.AuthenticateAndAuthorizeResponse{IsAuthorized: true}, nil
		},
		authorize: func(ctx context.Context, req *coctovigilv1.AuthorizeRequest) (*coctovigilv1.AuthorizeResponse, error) {
			got, ok := ctx.Deadline()
			assert.True(t, ok)
			assert.Equal(t, want, got)
			return &coctovigilv1.AuthorizeResponse{IsAuthorized: true}, nil
		},
	}
	c := &Client{svcUID: "service", remoteC: &tstRemoteC{internalC: internal}}
	resp, err := c.AuthenticateAndAuthorize(ctx, &AuthenticateAndAuthorizeRequest{Request: &coctovigilv1.DownstreamRequest{}})
	require.Nil(t, err)
	assert.True(t, resp.IsAuthorized)
	result, err := c.Authorize(ctx, &coctovigilv1.AuthorizeRequest{SessionUID: "session"})
	require.Nil(t, err)
	assert.True(t, result.IsAuthorized)
	assert.Nil(t, c.GetCache())
}

func TestRemoteUnparsedBodyIsPreserved(t *testing.T) {
	body := []byte("non-json payload")
	h := &corev1.RequestContext_Request_HTTP{Body: body}
	internal := &tstInternalErrC{authenticate: func(ctx context.Context, req *coctovigilv1.AuthenticateAndAuthorizeRequest) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
		assert.Equal(t, body, req.Request.Request.GetHttp().Body)
		return &coctovigilv1.AuthenticateAndAuthorizeResponse{RequestContext: &corev1.RequestContext{
			Request: pbutils.Clone(req.Request.Request).(*corev1.RequestContext_Request),
		}}, nil
	}}
	c := &Client{svcUID: "service", remoteC: &tstRemoteC{internalC: internal}}
	resp, err := c.AuthenticateAndAuthorize(t.Context(), &AuthenticateAndAuthorizeRequest{Request: &coctovigilv1.DownstreamRequest{
		Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{Http: h}},
	}})
	require.Nil(t, err)
	assert.Equal(t, body, h.Body)
	assert.Equal(t, body, resp.RequestContext.Request.GetHttp().Body)
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

func TestRemoteOmittedRequestContext(t *testing.T) {
	newRequest := func(typ string) *corev1.RequestContext_Request {
		switch typ {
		case "Nil":
			return nil
		case "BodyMap":
			return &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{Http: &corev1.RequestContext_Request_HTTP{
				Path: "/private", Headers: map[string]string{"x-tenant": "tenant"},
				Body: []byte(`{"key":"value"}`), BodyMap: pbutils.MapToStructMust(map[string]any{"key": "value"}),
			}}}
		case "Body":
			return &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{Http: &corev1.RequestContext_Request_HTTP{
				Path: "/private", Body: []byte("raw"),
			}}}
		default:
			return &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Postgres_{
				Postgres: &corev1.RequestContext_Request_Postgres{},
			}}
		}
	}
	newService := func(resourceVersion string) *corev1.Service {
		return &corev1.Service{
			Metadata: &metav1.Metadata{Uid: "service", Name: "service.default", ResourceVersion: resourceVersion},
			Spec: &corev1.Service_Spec{Config: &corev1.Service_Spec_Config{Upstream: &corev1.Service_Spec_Config_Upstream{
				Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "http://" + resourceVersion},
			}}},
		}
	}
	user := &corev1.User{Metadata: &metav1.Metadata{Uid: "user", Name: "user"}}

	for _, typ := range []string{"Nil", "BodyMap", "Body", "Postgres"} {
		for _, resourceVersion := range []string{"None", "", "rv"} {
			for _, octovigil := range []string{"Legacy", "Current", "Stale"} {
				for _, isAuthenticated := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/%t", typ, resourceVersion, octovigil, isAuthenticated), func(t *testing.T) {
						var svc *corev1.Service
						if resourceVersion != "None" {
							svc = newService(resourceVersion)
						}
						octovigilSvc := newService("rv")
						if octovigil == "Stale" {
							octovigilSvc = newService("stale")
						}

						request := newRequest(typ)
						origRequest := pbutils.Clone(&coctovigilv1.DownstreamRequest{Request: request}).(*coctovigilv1.DownstreamRequest).Request
						origService := pbutils.Clone(&corev1.RequestContext{Service: svc}).(*corev1.RequestContext).Service

						var sent *coctovigilv1.AuthenticateAndAuthorizeRequest
						internal := &tstInternalErrC{authenticate: func(ctx context.Context, in *coctovigilv1.AuthenticateAndAuthorizeRequest) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
							sent = pbutils.Clone(in).(*coctovigilv1.AuthenticateAndAuthorizeRequest)
							ret := &coctovigilv1.AuthenticateAndAuthorizeResponse{}
							if !isAuthenticated {
								return ret, nil
							}
							ret.IsAuthenticated = true
							ret.IsAuthorized = true
							ret.ServiceConfigName = "named"
							ret.RequestContext = &corev1.RequestContext{
								Request: sent.Request.GetRequest(),
								Service: octovigilSvc,
								User:    user,
							}
							if octovigil != "Legacy" {
								if sent.OmitRequest {
									ret.RequestContext.Request = nil
								}
								if sent.ServiceResourceVersion != "" &&
									sent.ServiceResourceVersion == octovigilSvc.Metadata.ResourceVersion {
									ret.RequestContext.Service = nil
								}
							}
							return pbutils.Clone(ret).(*coctovigilv1.AuthenticateAndAuthorizeResponse), nil
						}}
						c := &Client{svcUID: "service", remoteC: &tstRemoteC{internalC: internal}}
						resp, err := c.AuthenticateAndAuthorize(t.Context(), &AuthenticateAndAuthorizeRequest{
							Request: &coctovigilv1.DownstreamRequest{Request: request},
							Service: svc,
						})
						require.Nil(t, err)
						require.NotNil(t, sent)

						assert.True(t, sent.OmitRequest)
						assert.Equal(t, svc.GetMetadata().GetResourceVersion(), sent.ServiceResourceVersion)
						assert.Equal(t, "service", sent.ServiceUID)
						if typ == "BodyMap" {
							assert.Empty(t, sent.Request.Request.GetHttp().Body)
						} else {
							assert.True(t, pbutils.IsEqual(origRequest, sent.Request.GetRequest()))
						}
						assert.True(t, pbutils.IsEqual(origRequest, request))
						assert.True(t, pbutils.IsEqual(origService, svc))

						want := &coctovigilv1.AuthenticateAndAuthorizeResponse{}
						if isAuthenticated {
							want.IsAuthenticated = true
							want.IsAuthorized = true
							want.ServiceConfigName = "named"
							want.RequestContext = &corev1.RequestContext{
								Request: origRequest,
								Service: octovigilSvc,
								User:    user,
							}
						}
						assert.True(t, pbutils.IsEqual(want, resp))

						if !isAuthenticated {
							assert.Nil(t, resp.RequestContext)
							return
						}

						switch {
						case request == nil:
							assert.Nil(t, resp.RequestContext.Request)
						case octovigil == "Legacy":
							assert.NotSame(t, request, resp.RequestContext.Request)
						default:
							assert.Same(t, request, resp.RequestContext.Request)
						}
						if octovigil == "Current" && resourceVersion == "rv" {
							assert.Same(t, svc, resp.RequestContext.Service)
						} else {
							assert.NotSame(t, svc, resp.RequestContext.Service)
						}
					})
				}
			}
		}
	}
}

func TestEmbeddedRequestContext(t *testing.T) {
	ctx := t.Context()

	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  tst.C.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(tst.C.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	require.Nil(t, err)
	require.NotEmpty(t, svc.Metadata.ResourceVersion)

	vCache, err := vcache.NewCache(ctx)
	require.Nil(t, err)
	vCache.SetService(svc)

	c, err := NewClient(ctx, &Opts{
		OcteliumC: tst.C.OcteliumC,
		VCache:    vCache,
	})
	require.Nil(t, err)

	usr, err := tstuser.NewUserWorkloadClientless(tst.C.OcteliumC, adminSrv, usrSrv, nil)
	require.Nil(t, err)
	require.Nil(t, c.GetCache().SetSession(usr.Session))

	stale := vCache.GetService()
	stale.Metadata.ResourceVersion = vutils.UUIDv7()
	empty := vCache.GetService()
	empty.Metadata.ResourceVersion = ""

	for _, tc := range []struct {
		name   string
		svc    *corev1.Service
		isSame bool
	}{
		{"None", nil, false},
		{"Current", vCache.GetService(), true},
		{"Stale", stale, false},
		{"Empty", empty, false},
	} {
		for _, isAuthenticated := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%t", tc.name, isAuthenticated), func(t *testing.T) {
				headers := map[string]string{}
				if isAuthenticated {
					headers["x-octelium-auth"] = usr.GetAccessToken().AccessToken
				}
				request := &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
					Http: &corev1.RequestContext_Request_HTTP{Path: "/", Method: "GET", Headers: headers},
				}}
				resp, err := c.AuthenticateAndAuthorize(ctx, &AuthenticateAndAuthorizeRequest{
					Request: &coctovigilv1.DownstreamRequest{
						Source:  &coctovigilv1.DownstreamRequest_Source{Address: "192.0.2.1", Port: 12345},
						Request: request,
					},
					Service: tc.svc,
				})
				require.Nil(t, err)

				if !isAuthenticated {
					assert.False(t, resp.IsAuthenticated)
					assert.Nil(t, resp.RequestContext)
					return
				}

				assert.True(t, resp.IsAuthenticated)
				assert.True(t, resp.IsAuthorized)
				require.NotNil(t, resp.RequestContext)
				assert.Same(t, request, resp.RequestContext.Request)
				assert.Equal(t, usr.Session.Metadata.Uid, resp.RequestContext.Session.Metadata.Uid)
				if tc.isSame {
					assert.Same(t, tc.svc, resp.RequestContext.Service)
				} else {
					assert.NotSame(t, tc.svc, resp.RequestContext.Service)
					assert.True(t, pbutils.IsEqual(vCache.GetService(), resp.RequestContext.Service))
				}
			})
		}
	}

	vCache.SetService(empty)
	request := &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
		Http: &corev1.RequestContext_Request_HTTP{Path: "/", Method: "GET", Headers: map[string]string{
			"x-octelium-auth": usr.GetAccessToken().AccessToken,
		}},
	}}
	resp, err := c.AuthenticateAndAuthorize(ctx, &AuthenticateAndAuthorizeRequest{
		Request: &coctovigilv1.DownstreamRequest{
			Source:  &coctovigilv1.DownstreamRequest_Source{Address: "192.0.2.1", Port: 12345},
			Request: request,
		},
		Service: empty,
	})
	require.Nil(t, err)
	assert.True(t, resp.IsAuthorized)
	require.NotNil(t, resp.RequestContext)
	assert.NotSame(t, empty, resp.RequestContext.Service)
	assert.True(t, pbutils.IsEqual(empty, resp.RequestContext.Service))
}
