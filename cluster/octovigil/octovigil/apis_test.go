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

package octovigil

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/octovigil/octovigil/acache"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type downstreamCoreC struct {
	rcorev1.ResourceServiceClient
	session    *corev1.Session
	user       *corev1.User
	device     *corev1.Device
	groups     []*corev1.Group
	calls      []string
	errs       map[string]error
	getSession func()
}

func (c *downstreamCoreC) GetSession(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Session, error) {
	c.calls = append(c.calls, "session:"+in.Uid)
	if c.getSession != nil {
		c.getSession()
	}
	return c.session, c.errs["session"]
}

func (c *downstreamCoreC) GetUser(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.User, error) {
	c.calls = append(c.calls, "user:"+in.Uid)
	return c.user, c.errs["user"]
}

func (c *downstreamCoreC) GetDevice(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Device, error) {
	c.calls = append(c.calls, "device:"+in.Uid)
	return c.device, c.errs["device"]
}

func (c *downstreamCoreC) GetGroup(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Group, error) {
	c.calls = append(c.calls, "group:"+in.Name)
	if err := c.errs["group"]; err != nil {
		return nil, err
	}
	for _, grp := range c.groups {
		if grp.Metadata.Name == in.Name {
			return grp, nil
		}
	}
	return nil, status.Error(codes.NotFound, "Group not found")
}

type downstreamOcteliumC struct {
	octeliumc.ClientInterface
	coreC *downstreamCoreC
}

func (c *downstreamOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

func newDownstreamService(t *testing.T) (*internalService, *downstreamCoreC) {
	t.Helper()

	cache, err := acache.NewCache()
	assert.Nil(t, err)
	t.Cleanup(func() {
		cache.Close()
	})

	coreC := &downstreamCoreC{
		session: &corev1.Session{
			Metadata: &metav1.Metadata{Uid: vutils.UUIDv4(), Name: "session"},
			Status: &corev1.Session_Status{
				UserRef:   &metav1.ObjectReference{Uid: "user"},
				DeviceRef: &metav1.ObjectReference{Uid: "device"},
			},
		},
		user: &corev1.User{
			Metadata: &metav1.Metadata{Uid: "user", Name: "user"},
			Spec:     &corev1.User_Spec{Groups: []string{"group1", "group2"}},
		},
		device: &corev1.Device{
			Metadata: &metav1.Metadata{Uid: "device", Name: "device"},
			Status: &corev1.Device_Status{
				ProbeAttempt: &corev1.Device_Status_ProbeAttempt{Uid: "attempt"},
				Posture: &corev1.Device_Status_Posture{
					ExpiresAt: timestamppb.New(time.Now().Add(-time.Hour)),
				},
			},
		},
		groups: []*corev1.Group{
			{Metadata: &metav1.Metadata{Uid: "group1", Name: "group1"}},
			{Metadata: &metav1.Metadata{Uid: "group2", Name: "group2"}},
		},
		errs: make(map[string]error),
	}

	return &internalService{s: &Server{
		cache:     cache,
		octeliumC: &downstreamOcteliumC{coreC: coreC},
	}}, coreC
}

func TestGetDownstreamFromSessionUID(t *testing.T) {
	for _, mode := range []string{"cold", "session", "dependencies", "partial groups", "warm"} {
		t.Run(mode, func(t *testing.T) {
			srv, coreC := newDownstreamService(t)
			cache := srv.s.cache
			sessUID := coreC.session.Metadata.Uid

			if mode != "cold" && mode != "dependencies" {
				assert.Nil(t, cache.SetSession(coreC.session))
			}
			if mode == "dependencies" || mode == "partial groups" || mode == "warm" {
				assert.Nil(t, cache.SetUser(coreC.user))
				assert.Nil(t, cache.SetDevice(coreC.device))
				assert.Nil(t, cache.SetGroup(coreC.groups[0]))
				if mode != "partial groups" {
					assert.Nil(t, cache.SetGroup(coreC.groups[1]))
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			resp, err := srv.GetDownstreamFromSessionUID(ctx,
				&coctovigilv1.GetDownstreamFromSessionUIDRequest{SessionUID: sessUID})
			if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
				return
			}

			assert.True(t, pbutils.IsEqual(coreC.session, resp.Session))
			assert.True(t, pbutils.IsEqual(coreC.user, resp.User))
			assert.Equal(t, coreC.groups, resp.Groups)
			if !assert.NotNil(t, resp.Device) {
				return
			}
			assert.Nil(t, resp.Device.Status.ProbeAttempt)
			assert.Nil(t, resp.Device.Status.Posture)
			assert.NotNil(t, coreC.device.Status.ProbeAttempt)
			assert.NotNil(t, coreC.device.Status.Posture)

			switch mode {
			case "cold":
				assert.Equal(t, []string{"session:" + sessUID, "user:user", "device:device", "group:group1", "group:group2"}, coreC.calls)
			case "session":
				assert.Equal(t, []string{"user:user", "device:device", "group:group1", "group:group2"}, coreC.calls)
			case "dependencies":
				assert.Equal(t, []string{"session:" + sessUID}, coreC.calls)
			case "partial groups":
				assert.Equal(t, []string{"group:group2"}, coreC.calls)
			case "warm":
				assert.Empty(t, coreC.calls)
			}

			_, err = cache.GetSession(sessUID)
			assert.Equal(t, mode != "cold" && mode != "dependencies", err == nil)
			_, err = cache.GetUser("user")
			assert.Equal(t, mode != "cold" && mode != "session", err == nil)
		})
	}
}

func TestGetDownstreamFromSessionUIDMissingGroup(t *testing.T) {
	srv, coreC := newDownstreamService(t)
	coreC.user.Spec.Groups = append(coreC.user.Spec.Groups, "group3")
	assert.Nil(t, srv.s.cache.SetSession(coreC.session))
	assert.Nil(t, srv.s.cache.SetUser(coreC.user))
	assert.Nil(t, srv.s.cache.SetDevice(coreC.device))
	assert.Nil(t, srv.s.cache.SetGroup(coreC.groups[0]))
	assert.Nil(t, srv.s.cache.SetGroup(coreC.groups[1]))

	resp, err := srv.GetDownstreamFromSessionUID(context.Background(),
		&coctovigilv1.GetDownstreamFromSessionUIDRequest{SessionUID: coreC.session.Metadata.Uid})
	if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
		return
	}
	assert.Equal(t, coreC.groups, resp.Groups)
	assert.Equal(t, []string{"group:group3"}, coreC.calls)
}

func TestGetDownstreamFromSessionUIDErrors(t *testing.T) {
	for _, resource := range []string{"session", "user", "device", "group"} {
		for _, code := range []codes.Code{codes.NotFound, codes.Unavailable, codes.DeadlineExceeded} {
			t.Run(resource+"/"+code.String(), func(t *testing.T) {
				srv, coreC := newDownstreamService(t)
				coreC.errs[resource] = status.Error(code, "Lookup failed")

				resp, err := srv.GetDownstreamFromSessionUID(context.Background(),
					&coctovigilv1.GetDownstreamFromSessionUIDRequest{SessionUID: coreC.session.Metadata.Uid})
				if resource == "group" && code == codes.NotFound {
					assert.Nil(t, err)
					if assert.NotNil(t, resp) {
						assert.Empty(t, resp.Groups)
					}
					return
				}
				assert.Nil(t, resp)
				assert.Equal(t, code, status.Code(err))
				if resource == "session" && code == codes.NotFound {
					assert.Equal(t, "Session UID not Found", status.Convert(err).Message())
				}
			})
		}
	}

	for _, identifier := range []string{"", "session", "10.0.0.1", "fd00::1", "not-a-uid"} {
		t.Run("identifier "+identifier, func(t *testing.T) {
			srv, coreC := newDownstreamService(t)
			resp, err := srv.GetDownstreamFromSessionUID(context.Background(),
				&coctovigilv1.GetDownstreamFromSessionUIDRequest{SessionUID: identifier})
			assert.Nil(t, resp)
			assert.Equal(t, codes.NotFound, status.Code(err))
			assert.Empty(t, coreC.calls)
		})
	}
}

func TestGetDownstreamFromSessionUIDWatchUpdate(t *testing.T) {
	srv, coreC := newDownstreamService(t)
	sessUID := coreC.session.Metadata.Uid
	newSession := pbutils.Clone(coreC.session).(*corev1.Session)
	newSession.Status.IsConnected = true
	coreC.getSession = func() {
		assert.Nil(t, srv.s.cache.SetSession(newSession))
	}

	resp, err := srv.GetDownstreamFromSessionUID(context.Background(),
		&coctovigilv1.GetDownstreamFromSessionUIDRequest{SessionUID: sessUID})
	assert.Nil(t, err)
	assert.NotNil(t, resp)
	sess, err := srv.s.cache.GetSession(sessUID)
	assert.Nil(t, err)
	assert.True(t, pbutils.IsEqual(newSession, sess))
}

type authorizationCoreC struct {
	rcorev1.ResourceServiceClient
	mu        sync.Mutex
	service   *corev1.Service
	namespace *corev1.Namespace
	policies  map[string]*corev1.Policy
	errs      map[string]error
	calls     []string
}

func (c *authorizationCoreC) GetService(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Service, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "service:"+in.Uid)
	if err := c.errs["service"]; err != nil {
		return nil, err
	}
	if c.service == nil || c.service.Metadata.Uid != in.Uid {
		return nil, status.Error(codes.NotFound, "Service not found")
	}
	return c.service, nil
}

func (c *authorizationCoreC) GetPolicy(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Policy, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "policy:"+in.Name)
	if err := c.errs["policy:"+in.Name]; err != nil {
		return nil, err
	}
	if policy := c.policies[in.Name]; policy != nil {
		return policy, nil
	}
	return nil, status.Error(codes.NotFound, "Policy not found")
}

func (c *authorizationCoreC) GetNamespace(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Namespace, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, "namespace:"+in.Name)
	if err := c.errs["namespace"]; err != nil {
		return nil, err
	}
	if c.namespace == nil || c.namespace.Metadata.Name != in.Name {
		return nil, status.Error(codes.NotFound, "Namespace not found")
	}
	return c.namespace, nil
}

type authorizationOcteliumC struct {
	octeliumc.ClientInterface
	coreC rcorev1.ResourceServiceClient
}

func (c *authorizationOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

func newAuthorizationService(t *testing.T) (*internalService, *authorizationCoreC) {
	t.Helper()
	srv, downstream := newDownstreamService(t)
	downstream.session.Spec = &corev1.Session_Spec{State: corev1.Session_Spec_ACTIVE}
	downstream.session.Status.Type = corev1.Session_Status_CLIENT
	downstream.session.Status.Authentication = &corev1.Session_Status_Authentication{TokenID: "token"}
	downstream.session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{{V4: "100.64.0.2/32", V6: "fd00::2/128"}},
	}
	downstream.user.Status = &corev1.User_Status{}
	downstream.device.Spec = &corev1.Device_Spec{State: corev1.Device_Spec_ACTIVE}
	for _, group := range downstream.groups {
		group.Spec = &corev1.Group_Spec{}
		assert.Nil(t, srv.s.cache.SetGroup(group))
	}
	assert.Nil(t, srv.s.cache.SetUser(downstream.user))
	assert.Nil(t, srv.s.cache.SetDevice(downstream.device))
	assert.Nil(t, srv.s.cache.SetSession(downstream.session))
	coreC := &authorizationCoreC{
		ResourceServiceClient: downstream,
		service: &corev1.Service{
			Metadata: &metav1.Metadata{Uid: "service", Name: "service.namespace"},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "http://127.0.0.1:8080"},
				}},
				Authorization: &corev1.Service_Spec_Authorization{InlinePolicies: []*corev1.InlinePolicy{{
					Name: "allow",
					Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{
						Name: "allow", Effect: corev1.Policy_Spec_Rule_ALLOW,
						Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
					}}},
				}}},
			},
			Status: &corev1.Service_Status{NamespaceRef: &metav1.ObjectReference{Uid: "namespace", Name: "namespace"}},
		},
		namespace: &corev1.Namespace{Metadata: &metav1.Metadata{Uid: "namespace", Name: "namespace"}, Spec: &corev1.Namespace_Spec{}},
		policies:  make(map[string]*corev1.Policy),
		errs:      make(map[string]error),
	}
	srv.s.octeliumC = &authorizationOcteliumC{coreC: coreC}
	assert.Nil(t, srv.s.cache.SetService(coreC.service))
	assert.Nil(t, srv.s.cache.SetNamespace(coreC.namespace))
	var err error
	srv.s.celEngine, err = celengine.New(t.Context(), &celengine.Opts{})
	assert.Nil(t, err)
	srv.s.commonMetrics, err = newCommonMetrics(t.Context())
	assert.Nil(t, err)
	srv.s.coreSrv = admin.NewServer(&admin.Opts{OcteliumC: srv.s.octeliumC, IsEmbedded: true})
	srv.s.policyTriggerCtl = &policyTriggerCtl{ptMap: make(map[string]*corev1.PolicyTrigger)}
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	v6 := netip.MustParsePrefix("fd00::/64")
	srv.s.v4Prefix, srv.s.v6Prefix = &v4, &v6
	return srv, coreC
}

func TestAuthenticateAndAuthorizeRPC(t *testing.T) {
	for _, cold := range []bool{false, true} {
		for _, address := range []string{"100.64.0.2", "fd00::2"} {
			t.Run(fmt.Sprintf("%s/Cold%t", address, cold), func(t *testing.T) {
				srv, coreC := newAuthorizationService(t)
				if cold {
					assert.Nil(t, srv.s.cache.DeleteService(coreC.service))
				}
				request := &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
					Http: &corev1.RequestContext_Request_HTTP{Path: "/private", Method: "GET"},
				}}
				for range 2 {
					resp, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
						ServiceUID: coreC.service.Metadata.Uid,
						Request: &coctovigilv1.DownstreamRequest{
							Source: &coctovigilv1.DownstreamRequest_Source{Address: address}, Request: request,
						},
					})
					if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
						return
					}
					assert.True(t, resp.IsAuthenticated)
					assert.True(t, resp.IsAuthorized)
					assert.Equal(t, corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH, resp.AuthorizationDecisionReason.Type)
					assert.Equal(t, request, resp.RequestContext.Request)
					assert.Equal(t, coreC.namespace, resp.RequestContext.Namespace)
					assert.Equal(t, coreC.service, resp.RequestContext.Service)
					assert.NotNil(t, resp.RequestContext.User)
					assert.NotNil(t, resp.RequestContext.Session)
					assert.Len(t, resp.RequestContext.Groups, 2)
					assert.Nil(t, resp.RequestContext.Device.Status.Posture)
					assert.Nil(t, resp.RequestContext.Device.Status.ProbeAttempt)
				}
				if cold {
					assert.Equal(t, []string{"service:service"}, coreC.calls)
				} else {
					assert.Empty(t, coreC.calls)
				}
			})
		}
	}
}

func TestAuthorizationRPCServiceErrors(t *testing.T) {
	for _, code := range []codes.Code{codes.NotFound, codes.Unavailable, codes.PermissionDenied, codes.Canceled, codes.DeadlineExceeded} {
		for _, method := range []string{"AuthenticateAndAuthorize", "Authorize"} {
			t.Run(method+"/"+code.String(), func(t *testing.T) {
				srv, coreC := newAuthorizationService(t)
				assert.Nil(t, srv.s.cache.DeleteService(coreC.service))
				coreC.errs["service"] = status.Error(code, "lookup failed")
				if method == "AuthenticateAndAuthorize" {
					resp, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{ServiceUID: "service"})
					assert.Nil(t, resp)
					assert.Equal(t, code, status.Code(err))
				} else {
					resp, err := srv.Authorize(t.Context(), &coctovigilv1.AuthorizeRequest{ServiceUID: "service"})
					assert.Nil(t, resp)
					assert.Equal(t, code, status.Code(err))
				}
				_, err := srv.s.cache.GetService("service")
				assert.ErrorIs(t, err, acache.ErrNotFound)
			})
		}
	}
}

func TestAuthenticateAndAuthorizeRPCUnauthenticated(t *testing.T) {
	for _, request := range []*coctovigilv1.DownstreamRequest{
		nil, {}, {Source: &coctovigilv1.DownstreamRequest_Source{}},
		{Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.99"}},
		{Source: &coctovigilv1.DownstreamRequest_Source{Address: "192.0.2.1"}},
		{Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2:1234"}},
		{Source: &coctovigilv1.DownstreamRequest_Source{Address: "malicious\x00address"}},
	} {
		srv, coreC := newAuthorizationService(t)
		resp, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
			ServiceUID: coreC.service.Metadata.Uid, Request: request,
		})
		if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
			continue
		}
		assert.False(t, resp.IsAuthenticated)
		assert.False(t, resp.IsAuthorized)
		assert.Nil(t, resp.RequestContext)
		assert.Nil(t, resp.Config)
		assert.Empty(t, resp.ServiceConfigName)
		assert.Empty(t, coreC.calls)
	}
}

func TestAuthorizeRPC(t *testing.T) {
	for _, cold := range []bool{false, true} {
		srv, coreC := newAuthorizationService(t)
		if cold {
			assert.Nil(t, srv.s.cache.DeleteService(coreC.service))
		}
		downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
		for range 2 {
			resp, err := srv.Authorize(t.Context(), &coctovigilv1.AuthorizeRequest{
				ServiceUID: "service", SessionUID: downstream.session.Metadata.Uid,
			})
			if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
				return
			}
			assert.True(t, resp.IsAuthorized)
			assert.Equal(t, corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH, resp.Reason.Type)
		}
		if cold {
			assert.Equal(t, []string{"service:service"}, coreC.calls)
		} else {
			assert.Empty(t, coreC.calls)
		}
		resp, err := srv.Authorize(t.Context(), &coctovigilv1.AuthorizeRequest{ServiceUID: "service", SessionUID: "missing"})
		assert.Nil(t, resp)
		assert.ErrorIs(t, err, acache.SessionNotFound)
		downstream.errs["user"] = status.Error(codes.Unavailable, "user unavailable")
		assert.Nil(t, srv.s.cache.DeleteUser(downstream.user))
		resp, err = srv.Authorize(t.Context(), &coctovigilv1.AuthorizeRequest{ServiceUID: "service", SessionUID: downstream.session.Metadata.Uid})
		assert.Nil(t, resp)
		assert.Equal(t, codes.Unavailable, status.Code(err))
	}
}

func TestEvaluateRPC(t *testing.T) {
	for _, tc := range []struct {
		name      string
		condition string
		effect    corev1.Policy_Spec_Rule_Effect
		want      corev1.Policy_Spec_Rule_Effect
		code      codes.Code
	}{
		{"Allow", `ctx.user == "alice"`, corev1.Policy_Spec_Rule_ALLOW, corev1.Policy_Spec_Rule_ALLOW, codes.OK},
		{"Deny", `ctx.user == "alice"`, corev1.Policy_Spec_Rule_DENY, corev1.Policy_Spec_Rule_DENY, codes.OK},
		{"NoMatch", `ctx.user == "bob"`, corev1.Policy_Spec_Rule_ALLOW, corev1.Policy_Spec_Rule_DENY, codes.OK},
		{"MissingField", `ctx.missing == true`, corev1.Policy_Spec_Rule_ALLOW, corev1.Policy_Spec_Rule_DENY, codes.OK},
		{"MalformedExpression", `ctx.user ==`, corev1.Policy_Spec_Rule_ALLOW, 0, codes.Internal},
		{"WrongResultType", `42`, corev1.Policy_Spec_Rule_ALLOW, 0, codes.Internal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newAuthorizationService(t)
			input, err := structpb.NewStruct(map[string]any{"user": "alice"})
			assert.Nil(t, err)
			resp, err := srv.Evaluate(t.Context(), &coctovigilv1.EvaluateRequest{
				Ctx: input,
				InlinePolicies: []*coctovigilv1.EvaluateRequest_InlinePolicy{{
					Policy: &corev1.InlinePolicy{Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{
						Effect: tc.effect, Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: tc.condition}},
					}}}},
				}},
			})
			assert.Equal(t, tc.code, status.Code(err))
			if tc.code == codes.OK {
				if assert.NotNil(t, resp) {
					assert.Equal(t, tc.want, resp.Effect)
				}
			} else {
				assert.Nil(t, resp)
			}
		})
	}
	for _, req := range []*coctovigilv1.EvaluateRequest{{}, {Ctx: &structpb.Struct{}}, {Policies: []string{"missing"}}} {
		srv, _ := newAuthorizationService(t)
		resp, err := srv.Evaluate(t.Context(), req)
		assert.Nil(t, err)
		if assert.NotNil(t, resp) {
			assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.Effect)
		}
	}
}

func TestInternalRPCConcurrentIdentities(t *testing.T) {
	srv, coreC := newAuthorizationService(t)
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	srv.s.grpcSrv = server
	coctovigilv1.RegisterInternalServiceServer(server, srv)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		assert.Nil(t, srv.s.Close())
		listener.Close()
		select {
		case err := <-done:
			assert.Nil(t, err)
		case <-time.After(3 * time.Second):
			assert.Fail(t, "the internal RPC server did not stop")
		}
	})
	conn, err := grpc.NewClient("passthrough:///octovigil",
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if !assert.Nil(t, err) {
		return
	}
	t.Cleanup(func() { conn.Close() })
	client := coctovigilv1.NewInternalServiceClient(conn)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	base := coreC.ResourceServiceClient.(*downstreamCoreC)
	var wg sync.WaitGroup
	for idx := range 24 {
		user := pbutils.Clone(base.user).(*corev1.User)
		user.Metadata.Uid = fmt.Sprintf("user-%d", idx)
		user.Spec.Groups = nil
		session := pbutils.Clone(base.session).(*corev1.Session)
		session.Metadata.Uid = vutils.UUIDv4()
		session.Metadata.Name = fmt.Sprintf("session-%d", idx)
		session.Status.UserRef = &metav1.ObjectReference{Uid: user.Metadata.Uid}
		session.Status.DeviceRef = nil
		address := fmt.Sprintf("100.64.1.%d", idx+1)
		session.Status.Connection.Addresses = []*metav1.DualStackNetwork{{V4: address + "/32"}}
		assert.Nil(t, srv.s.cache.SetUser(user))
		assert.Nil(t, srv.s.cache.SetSession(session))
		wg.Go(func() {
			for range 16 {
				authenticated, err := client.AuthenticateAndAuthorize(ctx, &coctovigilv1.AuthenticateAndAuthorizeRequest{
					ServiceUID: "service", Request: &coctovigilv1.DownstreamRequest{
						Source: &coctovigilv1.DownstreamRequest_Source{Address: address},
					},
				})
				if !assert.Nil(t, err) || !assert.NotNil(t, authenticated) {
					return
				}
				assert.True(t, authenticated.IsAuthenticated)
				assert.True(t, authenticated.IsAuthorized)
				assert.Equal(t, session.Metadata.Uid, authenticated.RequestContext.Session.Metadata.Uid)
				assert.Equal(t, user.Metadata.Uid, authenticated.RequestContext.User.Metadata.Uid)
				authorized, err := client.Authorize(ctx, &coctovigilv1.AuthorizeRequest{ServiceUID: "service", SessionUID: session.Metadata.Uid})
				if !assert.Nil(t, err) || !assert.NotNil(t, authorized) {
					return
				}
				assert.True(t, authorized.IsAuthorized)
				downstream, err := client.GetDownstreamFromSessionUID(ctx, &coctovigilv1.GetDownstreamFromSessionUIDRequest{SessionUID: session.Metadata.Uid})
				if !assert.Nil(t, err) || !assert.NotNil(t, downstream) {
					return
				}
				assert.Equal(t, user.Metadata.Uid, downstream.User.Metadata.Uid)
				assert.Equal(t, session.Metadata.Uid, downstream.Session.Metadata.Uid)
				evaluated, err := client.Evaluate(ctx, &coctovigilv1.EvaluateRequest{InlinePolicies: []*coctovigilv1.EvaluateRequest_InlinePolicy{{
					Policy: &corev1.InlinePolicy{Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{
						Effect: corev1.Policy_Spec_Rule_DENY, Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
					}}}},
				}}})
				if !assert.Nil(t, err) || !assert.NotNil(t, evaluated) {
					return
				}
				assert.Equal(t, corev1.Policy_Spec_Rule_DENY, evaluated.Effect)
			}
		})
	}
	wg.Wait()
	assert.Empty(t, coreC.calls)
	_, err = client.Authorize(ctx, &coctovigilv1.AuthorizeRequest{ServiceUID: "missing"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, err = client.GetDownstreamFromSessionUID(ctx, &coctovigilv1.GetDownstreamFromSessionUIDRequest{})
	assert.Equal(t, codes.NotFound, status.Code(err))
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = client.Evaluate(canceled, &coctovigilv1.EvaluateRequest{})
	assert.Equal(t, codes.Canceled, status.Code(err))
}

func TestAuthorizationRPCPolicyErrors(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		for _, mode := range []string{"Expression", "PolicyName", "ContextEncoding"} {
			t.Run(fmt.Sprintf("%s/Anonymous%t", mode, anonymous), func(t *testing.T) {
				srv, coreC := newAuthorizationService(t)
				coreC.service.Spec.IsAnonymous = anonymous
				coreC.service.Spec.Authorization.EnableAnonymous = anonymous
				request := &coctovigilv1.DownstreamRequest{Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2"}}
				switch mode {
				case "Expression":
					coreC.service.Spec.Authorization.InlinePolicies[0].Spec.Rules[0].Condition = &corev1.Condition{Type: &corev1.Condition_Match{Match: "ctx =="}}
				case "PolicyName":
					coreC.service.Spec.Authorization.Policies = []string{"invalid..name"}
				case "ContextEncoding":
					request.Request = &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{Http: &corev1.RequestContext_Request_HTTP{Path: "\xff"}}}
				}
				resp, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{ServiceUID: "service", Request: request})
				assert.Nil(t, resp)
				assert.Equal(t, codes.Internal, status.Code(err))
				downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
				authorized, err := srv.Authorize(t.Context(), &coctovigilv1.AuthorizeRequest{
					ServiceUID: "service", SessionUID: downstream.session.Metadata.Uid, Request: request.Request,
				})
				assert.Nil(t, authorized)
				assert.NotNil(t, err)
			})
		}
	}
	for _, code := range []codes.Code{codes.NotFound, codes.Unavailable, codes.Canceled} {
		srv, coreC := newAuthorizationService(t)
		downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
		assert.Nil(t, srv.s.cache.DeleteUser(downstream.user))
		downstream.errs["user"] = status.Error(code, "User lookup failed")
		resp, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
			ServiceUID: "service", Request: &coctovigilv1.DownstreamRequest{Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2"}},
		})
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
	}
}

func TestEvaluateInvalidContext(t *testing.T) {
	srv, _ := newAuthorizationService(t)
	resp, err := srv.Evaluate(t.Context(), &coctovigilv1.EvaluateRequest{
		Ctx: &structpb.Struct{Fields: map[string]*structpb.Value{"value": structpb.NewStringValue("\xff")}},
	})
	assert.Nil(t, resp)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestAuthenticateAndAuthorizeDynamicConfigValidation(t *testing.T) {
	for _, engine := range []string{"CEL", "OPA"} {
		for _, anonymous := range []bool{false, true} {
			for _, fallback := range []bool{false, true} {
				for _, tc := range []struct {
					name    string
					parent  bool
					invalid string
				}{
					{"InvalidURL", false, "invalid-upstream"},
					{"EmptyURL", false, ""},
					{"InvalidPort", false, "http://127.0.0.1:65536"},
					{"MalformedURL", false, "http://%"},
					{"MissingParent", true, "missing"},
				} {
					t.Run(fmt.Sprintf("%s/Anonymous%t/Fallback%t/%s", engine, anonymous, fallback, tc.name), func(t *testing.T) {
						srv, coreC := newAuthorizationService(t)
						coreC.service.Spec.IsAnonymous = anonymous
						coreC.service.Spec.Authorization.EnableAnonymous = anonymous
						rule := &corev1.Service_Spec_DynamicConfig_Rule{
							Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
						}
						expression := `{"upstream": {"url": ctx.request.http.headers["x-e2e-config"]}}`
						opa := "package octelium.eval\nresult := {\"upstream\": {\"url\": input.ctx.request.http.headers[\"x-e2e-config\"]}}"
						valid := "http://127.0.0.1:9090"
						wantURL := valid
						if tc.parent {
							expression = `{"parent": ctx.request.http.headers["x-e2e-config"]}`
							opa = "package octelium.eval\nresult := {\"parent\": input.ctx.request.http.headers[\"x-e2e-config\"]}"
							valid = "default"
							wantURL = coreC.service.Spec.Config.Upstream.GetUrl()
						}
						if engine == "CEL" {
							rule.Type = &corev1.Service_Spec_DynamicConfig_Rule_Eval{Eval: expression}
						} else {
							rule.Type = &corev1.Service_Spec_DynamicConfig_Rule_Opa{Opa: opa}
						}
						coreC.service.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Rules: []*corev1.Service_Spec_DynamicConfig_Rule{rule}}
						if fallback {
							coreC.service.Spec.DynamicConfig.Rules = append(coreC.service.Spec.DynamicConfig.Rules,
								&corev1.Service_Spec_DynamicConfig_Rule{
									Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
									Type:      &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "default"},
								})
						}
						request := &coctovigilv1.DownstreamRequest{
							Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2"},
							Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
								Http: &corev1.RequestContext_Request_HTTP{Path: "/", Headers: map[string]string{"x-e2e-config": tc.invalid}},
							}},
						}
						resp, err := srv.s.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
							Service: coreC.service, Request: request,
						})
						assert.Nil(t, resp)
						assert.Equal(t, codes.InvalidArgument, status.Code(err))
						resp, err = srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
							ServiceUID: "service", Request: request,
						})
						assert.Nil(t, resp)
						assert.Equal(t, codes.Internal, status.Code(err))
						request.Request.GetHttp().Headers["x-e2e-config"] = valid
						resp, err = srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
							ServiceUID: "service", Request: request,
						})
						if assert.Nil(t, err) && assert.NotNil(t, resp) {
							assert.True(t, resp.IsAuthorized)
							assert.Equal(t, !anonymous, resp.IsAuthenticated)
							if assert.NotNil(t, resp.Config) {
								assert.Equal(t, wantURL, resp.Config.Upstream.GetUrl())
							}
							assert.Empty(t, resp.ServiceConfigName)
						}
						request.Request.GetHttp().Headers["x-e2e-config"] = tc.invalid
						rule.Condition = &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: false}}
						resp, err = srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
							ServiceUID: "service", Request: request,
						})
						if assert.Nil(t, err) && assert.NotNil(t, resp) {
							assert.True(t, resp.IsAuthorized)
							assert.Nil(t, resp.Config)
							if fallback {
								assert.Equal(t, "default", resp.ServiceConfigName)
							} else {
								assert.Empty(t, resp.ServiceConfigName)
							}
						}
						rule.Condition = &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}
						coreC.service.Spec.Authorization.InlinePolicies[0].Spec.Rules[0].Effect = corev1.Policy_Spec_Rule_DENY
						resp, err = srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
							ServiceUID: "service", Request: request,
						})
						if assert.Nil(t, err) && assert.NotNil(t, resp) {
							assert.False(t, resp.IsAuthorized)
							assert.Nil(t, resp.Config)
							assert.Empty(t, resp.ServiceConfigName)
						}
						assert.Empty(t, coreC.calls)
					})
				}
			}
		}
	}
}

func TestInternalRPCDynamicConfigValidation(t *testing.T) {
	for _, engine := range []string{"CEL", "OPA"} {
		t.Run(engine, func(t *testing.T) {
			srv, coreC := newAuthorizationService(t)
			rule := &corev1.Service_Spec_DynamicConfig_Rule{
				Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
			}
			if engine == "CEL" {
				rule.Type = &corev1.Service_Spec_DynamicConfig_Rule_Eval{Eval: `{"upstream": {"url": ctx.request.http.path}}`}
			} else {
				rule.Type = &corev1.Service_Spec_DynamicConfig_Rule_Opa{Opa: "package octelium.eval\nresult := {\"upstream\": {\"url\": input.ctx.request.http.path}}"}
			}
			coreC.service.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Rules: []*corev1.Service_Spec_DynamicConfig_Rule{rule}}
			listener := bufconn.Listen(1024 * 1024)
			server := grpc.NewServer()
			srv.s.grpcSrv = server
			coctovigilv1.RegisterInternalServiceServer(server, srv)
			done := make(chan error, 1)
			go func() { done <- server.Serve(listener) }()
			t.Cleanup(func() {
				assert.Nil(t, srv.s.Close())
				listener.Close()
				select {
				case err := <-done:
					assert.Nil(t, err)
				case <-time.After(3 * time.Second):
					assert.Fail(t, "the internal RPC server did not stop")
				}
			})
			conn, err := grpc.NewClient("passthrough:///octovigil",
				grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
					return listener.DialContext(ctx)
				}), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if !assert.Nil(t, err) {
				return
			}
			t.Cleanup(func() { conn.Close() })
			client := coctovigilv1.NewInternalServiceClient(conn)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					for range 8 {
						for _, path := range []string{"invalid-upstream", "http://127.0.0.1:9090", "http://%"} {
							resp, err := client.AuthenticateAndAuthorize(ctx, &coctovigilv1.AuthenticateAndAuthorizeRequest{
								ServiceUID: "service", Request: &coctovigilv1.DownstreamRequest{
									Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2"},
									Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
										Http: &corev1.RequestContext_Request_HTTP{Path: path},
									}},
								},
							})
							if path != "http://127.0.0.1:9090" {
								assert.Nil(t, resp)
								assert.Equal(t, codes.Internal, status.Code(err))
							} else if assert.Nil(t, err) && assert.NotNil(t, resp) {
								assert.True(t, resp.IsAuthenticated)
								assert.True(t, resp.IsAuthorized)
								if assert.NotNil(t, resp.Config) {
									assert.Equal(t, path, resp.Config.Upstream.GetUrl())
								}
							}
						}
					}
				})
			}
			wg.Wait()
			assert.Empty(t, coreC.calls)
		})
	}
}

func TestInternalRPCNilRequests(t *testing.T) {
	for _, method := range []string{"AuthenticateAndAuthorize", "Authorize", "GetDownstreamFromSessionUID", "Evaluate"} {
		t.Run(method, func(t *testing.T) {
			srv, coreC := newAuthorizationService(t)
			assert.NotPanics(t, func() {
				var err error
				switch method {
				case "AuthenticateAndAuthorize":
					var resp *coctovigilv1.AuthenticateAndAuthorizeResponse
					resp, err = srv.AuthenticateAndAuthorize(t.Context(), nil)
					assert.Nil(t, resp)
				case "Authorize":
					var resp *coctovigilv1.AuthorizeResponse
					resp, err = srv.Authorize(t.Context(), nil)
					assert.Nil(t, resp)
				case "GetDownstreamFromSessionUID":
					var resp *coctovigilv1.GetDownstreamFromSessionUIDResponse
					resp, err = srv.GetDownstreamFromSessionUID(t.Context(), nil)
					assert.Nil(t, resp)
				case "Evaluate":
					var resp *coctovigilv1.EvaluateResponse
					resp, err = srv.Evaluate(t.Context(), nil)
					assert.Nil(t, resp)
				}
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			})
			assert.Empty(t, coreC.calls)
		})
	}
}

func TestEvaluateMalformedInlinePolicies(t *testing.T) {
	for idx, invalid := range []*coctovigilv1.EvaluateRequest_InlinePolicy{
		nil, {}, {Policy: &corev1.InlinePolicy{}},
	} {
		for position := range 2 {
			t.Run(fmt.Sprintf("Policy%d/Position%d", idx, position), func(t *testing.T) {
				srv, coreC := newAuthorizationService(t)
				policies := []*coctovigilv1.EvaluateRequest_InlinePolicy{{Policy: coreC.service.Spec.Authorization.InlinePolicies[0]}}
				if position == 0 {
					policies = append([]*coctovigilv1.EvaluateRequest_InlinePolicy{invalid}, policies...)
				} else {
					policies = append(policies, invalid)
				}
				assert.NotPanics(t, func() {
					resp, err := srv.Evaluate(t.Context(), &coctovigilv1.EvaluateRequest{InlinePolicies: policies})
					assert.Nil(t, resp)
					assert.Equal(t, codes.InvalidArgument, status.Code(err))
				})
				assert.Empty(t, coreC.calls)
			})
		}
	}
}

func TestAuthorizationMalformedAdditionalPolicies(t *testing.T) {
	for idx, invalid := range []*corev1.InlinePolicy{
		nil, {},
	} {
		for _, anonymous := range []bool{false, true} {
			t.Run(fmt.Sprintf("Policy%d/Anonymous%t", idx, anonymous), func(t *testing.T) {
				srv, coreC := newAuthorizationService(t)
				coreC.service.Spec.IsAnonymous = anonymous
				coreC.service.Spec.Authorization.EnableAnonymous = anonymous
				additional := &coctovigilv1.Authorization{InlinePolicies: []*corev1.InlinePolicy{
					coreC.service.Spec.Authorization.InlinePolicies[0], invalid,
				}}
				downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
				assert.NotPanics(t, func() {
					resp, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
						ServiceUID: "service", Additional: additional,
						Request: &coctovigilv1.DownstreamRequest{Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2"}},
					})
					assert.Nil(t, resp)
					assert.Equal(t, codes.InvalidArgument, status.Code(err))
				})
				assert.NotPanics(t, func() {
					resp, err := srv.Authorize(t.Context(), &coctovigilv1.AuthorizeRequest{
						ServiceUID: "service", SessionUID: downstream.session.Metadata.Uid, Additional: additional,
					})
					assert.Nil(t, resp)
					assert.Equal(t, codes.InvalidArgument, status.Code(err))
				})
				assert.Empty(t, coreC.calls)
			})
		}
	}
}

func TestAuthenticateAndAuthorizeMissingDownstreamRequest(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		for _, cold := range []bool{false, true} {
			t.Run(fmt.Sprintf("Anonymous%t/Cold%t", anonymous, cold), func(t *testing.T) {
				srv, coreC := newAuthorizationService(t)
				coreC.service.Spec.IsAnonymous = anonymous
				coreC.service.Spec.Authorization.EnableAnonymous = anonymous
				if cold {
					assert.Nil(t, srv.s.cache.DeleteService(coreC.service))
				}
				assert.NotPanics(t, func() {
					resp, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{ServiceUID: "service"})
					assert.Nil(t, err)
					if assert.NotNil(t, resp) {
						assert.False(t, resp.IsAuthenticated)
						assert.False(t, resp.IsAuthorized)
						assert.Nil(t, resp.RequestContext)
						assert.Nil(t, resp.Config)
						assert.Empty(t, resp.ServiceConfigName)
					}
				})
				assert.NotPanics(t, func() {
					resp, err := srv.s.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.DoAuthenticateAndAuthorizeRequest{Service: coreC.service})
					assert.Nil(t, err)
					if assert.NotNil(t, resp) {
						assert.False(t, resp.IsAuthenticated)
						assert.False(t, resp.IsAuthorized)
						assert.Nil(t, resp.RequestContext)
						assert.Nil(t, resp.Config)
					}
				})
				if cold {
					assert.Equal(t, []string{"service:service"}, coreC.calls)
				} else {
					assert.Empty(t, coreC.calls)
				}
			})
		}
	}
}

func TestEvaluateEmptyInlinePolicy(t *testing.T) {
	for _, spec := range []*corev1.Policy_Spec{
		{}, {IsDisabled: true},
		{IsDisabled: true, Rules: []*corev1.Policy_Spec_Rule{nil}, EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{nil}},
	} {
		srv, coreC := newAuthorizationService(t)
		policy := &corev1.InlinePolicy{Spec: spec}
		resp, err := srv.Evaluate(t.Context(), &coctovigilv1.EvaluateRequest{
			InlinePolicies: []*coctovigilv1.EvaluateRequest_InlinePolicy{{Policy: policy}},
		})
		assert.Nil(t, err)
		if assert.NotNil(t, resp) {
			assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.Effect)
		}
		authenticated, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
			ServiceUID: "service", Request: &coctovigilv1.DownstreamRequest{Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2"}},
			Additional: &coctovigilv1.Authorization{InlinePolicies: []*corev1.InlinePolicy{policy}},
		})
		assert.Nil(t, err)
		if assert.NotNil(t, authenticated) {
			assert.True(t, authenticated.IsAuthenticated)
			assert.True(t, authenticated.IsAuthorized)
		}
		assert.Empty(t, coreC.calls)
	}
}

func TestInternalRPCMalformedRequests(t *testing.T) {
	srv, coreC := newAuthorizationService(t)
	coreC.service.Spec.IsAnonymous = true
	coreC.service.Spec.Authorization.EnableAnonymous = true
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	srv.s.grpcSrv = server
	coctovigilv1.RegisterInternalServiceServer(server, srv)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		assert.Nil(t, srv.s.Close())
		listener.Close()
		select {
		case err := <-done:
			assert.Nil(t, err)
		case <-time.After(3 * time.Second):
			assert.Fail(t, "the internal RPC server did not stop")
		}
	})
	conn, err := grpc.NewClient("passthrough:///octovigil",
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if !assert.Nil(t, err) {
		return
	}
	t.Cleanup(func() { conn.Close() })
	client := coctovigilv1.NewInternalServiceClient(conn)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	allow := coreC.service.Spec.Authorization.InlinePolicies[0]
	invalid := []*coctovigilv1.EvaluateRequest_InlinePolicy{nil, {}, {Policy: &corev1.InlinePolicy{}}}
	policies := []*corev1.InlinePolicy{
		{Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{nil}}},
		{Spec: &corev1.Policy_Spec{EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{nil}}},
		{Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{}}, EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{{}}}},
	}
	downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Go(func() {
			for idx := range 8 {
				evaluated, err := client.Evaluate(ctx, &coctovigilv1.EvaluateRequest{
					InlinePolicies: []*coctovigilv1.EvaluateRequest_InlinePolicy{{Policy: allow}, invalid[(worker+idx)%len(invalid)]},
				})
				assert.Nil(t, evaluated)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				additional := &coctovigilv1.Authorization{InlinePolicies: []*corev1.InlinePolicy{allow, nil}}
				authenticated, err := client.AuthenticateAndAuthorize(ctx, &coctovigilv1.AuthenticateAndAuthorizeRequest{
					ServiceUID: "service", Request: &coctovigilv1.DownstreamRequest{}, Additional: additional,
				})
				assert.Nil(t, authenticated)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				authorized, err := client.Authorize(ctx, &coctovigilv1.AuthorizeRequest{
					ServiceUID: "service", SessionUID: downstream.session.Metadata.Uid, Additional: additional,
				})
				assert.Nil(t, authorized)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				authenticated, err = client.AuthenticateAndAuthorize(ctx, &coctovigilv1.AuthenticateAndAuthorizeRequest{ServiceUID: "service"})
				if assert.Nil(t, err) && assert.NotNil(t, authenticated) {
					assert.False(t, authenticated.IsAuthenticated)
					assert.False(t, authenticated.IsAuthorized)
					assert.Nil(t, authenticated.RequestContext)
				}
				evaluated, err = client.Evaluate(ctx, &coctovigilv1.EvaluateRequest{
					InlinePolicies: []*coctovigilv1.EvaluateRequest_InlinePolicy{{Policy: allow}, {Policy: policies[(worker+idx)%len(policies)]}},
				})
				if assert.Nil(t, err) && assert.NotNil(t, evaluated) {
					assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, evaluated.Effect)
				}
				authenticated, err = client.AuthenticateAndAuthorize(ctx, &coctovigilv1.AuthenticateAndAuthorizeRequest{
					ServiceUID: "service", Request: &coctovigilv1.DownstreamRequest{},
					Additional: &coctovigilv1.Authorization{InlinePolicies: []*corev1.InlinePolicy{policies[(worker+idx)%len(policies)]}},
				})
				if assert.Nil(t, err) && assert.NotNil(t, authenticated) {
					assert.True(t, authenticated.IsAuthorized)
					assert.False(t, authenticated.IsAuthenticated)
				}
				authorized, err = client.Authorize(ctx, &coctovigilv1.AuthorizeRequest{
					ServiceUID: "service", SessionUID: downstream.session.Metadata.Uid,
					Additional: &coctovigilv1.Authorization{InlinePolicies: []*corev1.InlinePolicy{policies[(worker+idx)%len(policies)]}},
				})
				if assert.Nil(t, err) && assert.NotNil(t, authorized) {
					assert.True(t, authorized.IsAuthorized)
				}
			}
		})
	}
	wg.Wait()
	assert.Empty(t, coreC.calls)
}

func TestInternalRPCLookupFailures(t *testing.T) {
	for _, resource := range []string{"policy", "namespace", "trigger"} {
		t.Run(resource, func(t *testing.T) {
			srv, coreC := newAuthorizationService(t)
			lookupErr := status.Error(codes.Unavailable, "authorization lookup failed")
			switch resource {
			case "policy":
				coreC.service.Spec.Authorization.Policies = []string{"deny"}
				coreC.errs["policy:deny"] = lookupErr
			case "namespace":
				assert.Nil(t, srv.s.cache.DeleteNamespace(coreC.namespace))
				coreC.errs["namespace"] = lookupErr
			case "trigger":
				coreC.errs["policy:deny"] = lookupErr
				assert.Nil(t, srv.s.policyTriggerCtl.SetPolicyTrigger(&corev1.PolicyTrigger{
					Metadata: &metav1.Metadata{Uid: "trigger"},
					Status: &corev1.PolicyTrigger_Status{Policies: []string{"deny"},
						PreCondition: &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{MatchAny: true}},
					},
				}))
			}
			listener := bufconn.Listen(1024 * 1024)
			server := grpc.NewServer()
			srv.s.grpcSrv = server
			coctovigilv1.RegisterInternalServiceServer(server, srv)
			done := make(chan error, 1)
			go func() { done <- server.Serve(listener) }()
			t.Cleanup(func() {
				assert.Nil(t, srv.s.Close())
				listener.Close()
				select {
				case err := <-done:
					assert.Nil(t, err)
				case <-time.After(3 * time.Second):
					assert.Fail(t, "the internal RPC server did not stop")
				}
			})
			conn, err := grpc.NewClient("passthrough:///octovigil",
				grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
					return listener.DialContext(ctx)
				}), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if !assert.Nil(t, err) {
				return
			}
			t.Cleanup(func() { conn.Close() })
			client := coctovigilv1.NewInternalServiceClient(conn)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					for range 8 {
						authenticated, err := client.AuthenticateAndAuthorize(ctx, &coctovigilv1.AuthenticateAndAuthorizeRequest{
							ServiceUID: "service", Request: &coctovigilv1.DownstreamRequest{Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2"}},
						})
						assert.Nil(t, authenticated)
						assert.Equal(t, codes.Internal, status.Code(err))
						authorized, err := client.Authorize(ctx, &coctovigilv1.AuthorizeRequest{
							ServiceUID: "service", SessionUID: downstream.session.Metadata.Uid,
						})
						assert.Nil(t, authorized)
						assert.Equal(t, codes.Unavailable, status.Code(err))
						if resource == "policy" {
							evaluated, err := client.Evaluate(ctx, &coctovigilv1.EvaluateRequest{
								Policies: []string{"deny"}, InlinePolicies: []*coctovigilv1.EvaluateRequest_InlinePolicy{{Policy: coreC.service.Spec.Authorization.InlinePolicies[0]}},
							})
							assert.Nil(t, evaluated)
							assert.Equal(t, codes.Internal, status.Code(err))
						}
					}
				})
			}
			wg.Wait()
		})
	}
}

func TestAuthenticateAndAuthorizeRPCOmit(t *testing.T) {
	bodyMap, err := structpb.NewStruct(map[string]any{"model": "gpt", "count": 3})
	assert.Nil(t, err)
	httpC := func(path string) *corev1.RequestContext_Request_HTTP {
		return &corev1.RequestContext_Request_HTTP{
			Path: path, Method: "POST", Uri: path + "?q=1", Host: "service.example.com", Scheme: "https",
			Headers: map[string]string{"x-tenant": "tenant"}, QueryParams: map[string]string{"q": "1"},
			Body: []byte(`{"model":"gpt","count":3}`), BodyMap: bodyMap, Size: 25,
		}
	}
	requests := []*corev1.RequestContext_Request{
		nil,
		{},
		{Ip: "192.0.2.1", Type: &corev1.RequestContext_Request_Http{Http: httpC("/private")}},
		{Type: &corev1.RequestContext_Request_Http{Http: &corev1.RequestContext_Request_HTTP{Path: "/", Body: []byte("raw")}}},
		{Type: &corev1.RequestContext_Request_Kubernetes_{Kubernetes: &corev1.RequestContext_Request_Kubernetes{
			Http: httpC("/api/v1/namespaces/default/pods"), Verb: "list", ApiPrefix: "api", ApiVersion: "v1", Namespace: "default", Resource: "pods",
		}}},
		{Type: &corev1.RequestContext_Request_Grpc{Grpc: &corev1.RequestContext_Request_GRPC{
			Http: httpC("/pkg.Service/Method"), Method: "Method", Service: "Service", ServiceFullName: "pkg.Service", Package: "pkg",
		}}},
		{Type: &corev1.RequestContext_Request_Mcp{Mcp: &corev1.RequestContext_Request_MCP{
			Http: httpC("/mcp"), Method: "tools/call", Name: "tool", RequestID: "1", Capabilities: []string{"tools"},
		}}},
		{Type: &corev1.RequestContext_Request_Llm{Llm: &corev1.RequestContext_Request_LLM{
			Http: httpC("/v1/chat/completions"), Model: "gpt", ToolNames: []string{"search"}, HasTools: true, ToolCount: 1,
		}}},
		{Type: &corev1.RequestContext_Request_Postgres_{Postgres: &corev1.RequestContext_Request_Postgres{
			Type: &corev1.RequestContext_Request_Postgres_Connect_{Connect: &corev1.RequestContext_Request_Postgres_Connect{
				User: "postgres", Database: "db",
			}},
		}}},
		{Type: &corev1.RequestContext_Request_Ssh{Ssh: &corev1.RequestContext_Request_SSH{
			Type: &corev1.RequestContext_Request_SSH_Connect_{Connect: &corev1.RequestContext_Request_SSH_Connect{User: "root"}},
		}}},
		{Type: &corev1.RequestContext_Request_Dns{Dns: &corev1.RequestContext_Request_DNS{Name: "example.com.", TypeID: 1}}},
	}

	for _, shape := range []string{"Authorized", "Unauthorized", "Anonymous", "ConfigName", "Config", "Unauthenticated", "EmptyResourceVersion"} {
		t.Run(shape, func(t *testing.T) {
			srv, coreC := newAuthorizationService(t)
			coreC.service.Metadata.ResourceVersion = "service-rv"
			address := "100.64.0.2"
			switch shape {
			case "Unauthorized":
				coreC.service.Spec.Authorization.InlinePolicies[0].Spec.Rules[0].Effect = corev1.Policy_Spec_Rule_DENY
			case "Anonymous":
				coreC.service.Spec.IsAnonymous = true
				coreC.service.Spec.Authorization.EnableAnonymous = true
			case "ConfigName":
				coreC.service.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{{Name: "named", Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "http://127.0.0.1:9091"},
					}}},
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{{
						Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
						Type:      &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "named"},
					}},
				}
			case "Config":
				coreC.service.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{{
						Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
						Type:      &corev1.Service_Spec_DynamicConfig_Rule_Eval{Eval: `{"upstream": {"url": "http://127.0.0.1:9090"}}`},
					}},
				}
			case "Unauthenticated":
				address = "192.0.2.1"
			case "EmptyResourceVersion":
				coreC.service.Metadata.ResourceVersion = ""
			}
			assert.Nil(t, srv.s.cache.SetService(coreC.service))
			cached := pbutils.Clone(coreC.service).(*corev1.Service)

			listener := bufconn.Listen(1024 * 1024)
			server := grpc.NewServer()
			srv.s.grpcSrv = server
			coctovigilv1.RegisterInternalServiceServer(server, srv)
			done := make(chan error, 1)
			go func() { done <- server.Serve(listener) }()
			t.Cleanup(func() {
				assert.Nil(t, srv.s.Close())
				listener.Close()
				select {
				case err := <-done:
					assert.Nil(t, err)
				case <-time.After(3 * time.Second):
					assert.Fail(t, "the internal RPC server did not stop")
				}
			})
			conn, err := grpc.NewClient("passthrough:///octovigil",
				grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
					return listener.DialContext(ctx)
				}), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if !assert.Nil(t, err) {
				return
			}
			t.Cleanup(func() { conn.Close() })
			client := coctovigilv1.NewInternalServiceClient(conn)

			var omittedRequests, omittedServices int
			for _, request := range requests {
				for _, omitRequest := range []bool{false, true} {
					for _, resourceVersion := range []string{"", "service-rv", "other-rv"} {
						downstream := &coctovigilv1.DownstreamRequest{
							Source:  &coctovigilv1.DownstreamRequest_Source{Address: address},
							Request: request,
						}
						legacy, err := client.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
							ServiceUID: "service", Request: downstream,
						})
						if !assert.Nil(t, err) || !assert.NotNil(t, legacy) {
							return
						}
						resp, err := client.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
							ServiceUID: "service", Request: downstream,
							OmitRequest: omitRequest, ServiceResourceVersion: resourceVersion,
						})
						if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
							return
						}

						switch shape {
						case "Unauthenticated":
							assert.False(t, legacy.IsAuthenticated)
							assert.Nil(t, legacy.RequestContext)
							assert.True(t, pbutils.IsEqual(legacy, resp))
							continue
						case "Unauthorized":
							assert.True(t, legacy.IsAuthenticated)
							assert.False(t, legacy.IsAuthorized)
						case "Anonymous":
							assert.False(t, legacy.IsAuthenticated)
							assert.True(t, legacy.IsAuthorized)
						case "ConfigName":
							assert.True(t, legacy.IsAuthorized)
							assert.Equal(t, "named", legacy.ServiceConfigName)
						case "Config":
							assert.True(t, legacy.IsAuthorized)
							assert.Equal(t, "http://127.0.0.1:9090", legacy.Config.GetUpstream().GetUrl())
						default:
							assert.True(t, legacy.IsAuthenticated)
							assert.True(t, legacy.IsAuthorized)
						}

						if !assert.NotNil(t, resp.RequestContext) {
							return
						}
						assert.True(t, pbutils.IsEqual(request, legacy.RequestContext.Request))
						assert.True(t, pbutils.IsEqual(cached, legacy.RequestContext.Service))

						assert.Equal(t, omitRequest || request == nil, resp.RequestContext.Request == nil)
						isServiceOmitted := resourceVersion != "" && resourceVersion == cached.Metadata.ResourceVersion
						assert.Equal(t, isServiceOmitted, resp.RequestContext.Service == nil)
						if omitRequest && request != nil {
							omittedRequests++
						}
						if isServiceOmitted {
							omittedServices++
						}

						if resp.RequestContext.Request == nil {
							resp.RequestContext.Request = request
						}
						if resp.RequestContext.Service == nil {
							resp.RequestContext.Service = cached
						}
						assert.True(t, pbutils.IsEqual(legacy, resp))
					}
				}
			}

			switch shape {
			case "Unauthenticated":
				assert.Zero(t, omittedRequests)
				assert.Zero(t, omittedServices)
			case "EmptyResourceVersion":
				assert.Equal(t, 3*(len(requests)-1), omittedRequests)
				assert.Zero(t, omittedServices)
			default:
				assert.Equal(t, 3*(len(requests)-1), omittedRequests)
				assert.Equal(t, 2*len(requests), omittedServices)
			}

			svc, err := srv.s.cache.GetService("service")
			assert.Nil(t, err)
			assert.Same(t, coreC.service, svc)
			assert.True(t, pbutils.IsEqual(cached, svc))
			assert.Empty(t, coreC.calls)
		})
	}
}

func newIdentityRequestContext() *corev1.RequestContext {
	return &corev1.RequestContext{
		Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
			Http: &corev1.RequestContext_Request_HTTP{Path: "/"},
		}},
		Service: &corev1.Service{Metadata: &metav1.Metadata{Uid: "service", ResourceVersion: "service-rv"}},
		Session: &corev1.Session{
			Metadata: &metav1.Metadata{Uid: "session", Name: "session", ResourceVersion: "session-rv"},
			Status:   &corev1.Session_Status{Authentication: &corev1.Session_Status_Authentication{TokenID: "token"}},
		},
		User: &corev1.User{
			Metadata: &metav1.Metadata{Uid: "user", Name: "user", ResourceVersion: "user-rv"},
			Spec:     &corev1.User_Spec{Groups: []string{"group1", "group2"}},
		},
		Groups: []*corev1.Group{
			{Metadata: &metav1.Metadata{Uid: "group1", Name: "group1", ResourceVersion: "group1-rv"}},
			{Metadata: &metav1.Metadata{Uid: "group2", Name: "group2", ResourceVersion: "group2-rv"}},
		},
		Device: &corev1.Device{
			Metadata: &metav1.Metadata{Uid: "device", Name: "device", ResourceVersion: "device-rv"},
			Status: &corev1.Device_Status{
				Binding: &corev1.Device_Status_Binding{Uid: "binding", Assurance: corev1.Device_Status_Binding_SIGNED},
				Posture: &corev1.Device_Status_Posture{DiskEncryption: corev1.Device_Status_Posture_PASS},
			},
		},
		Namespace: &corev1.Namespace{Metadata: &metav1.Metadata{Uid: "namespace", Name: "namespace", ResourceVersion: "namespace-rv"}},
	}
}

func TestGetIdentityFingerprint(t *testing.T) {
	base := getIdentityFingerprint(newIdentityRequestContext())
	assert.Len(t, base, sha256.Size)
	assert.Equal(t, base, getIdentityFingerprint(pbutils.Clone(newIdentityRequestContext()).(*corev1.RequestContext)))

	for _, tc := range []struct {
		name   string
		update func(*corev1.RequestContext)
	}{
		{"Request", func(i *corev1.RequestContext) { i.Request = nil }},
		{"Service", func(i *corev1.RequestContext) { i.Service = nil }},
		{"ServiceResourceVersion", func(i *corev1.RequestContext) { i.Service.Metadata.ResourceVersion = "other" }},
		{"SessionContent", func(i *corev1.RequestContext) { i.Session.Status.Authentication.TokenID = "other" }},
		{"UserContent", func(i *corev1.RequestContext) { i.User.Spec.Groups = nil }},
		{"GroupContent", func(i *corev1.RequestContext) { i.Groups[0].Metadata.Name = "other" }},
		{"DeviceContent", func(i *corev1.RequestContext) {
			i.Device.Status.Posture.DiskEncryption = corev1.Device_Status_Posture_FAIL
		}},
		{"NamespaceContent", func(i *corev1.RequestContext) { i.Namespace.Metadata.Name = "other" }},
		{"Name", func(i *corev1.RequestContext) { i.Session.Metadata.Name = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqCtx := newIdentityRequestContext()
			tc.update(reqCtx)
			assert.Equal(t, base, getIdentityFingerprint(reqCtx))
		})
	}

	fingerprints := map[string]string{string(base): "Base"}
	for _, tc := range []struct {
		name   string
		update func(*corev1.RequestContext)
	}{
		{"SessionUID", func(i *corev1.RequestContext) { i.Session.Metadata.Uid = "other" }},
		{"SessionResourceVersion", func(i *corev1.RequestContext) { i.Session.Metadata.ResourceVersion = "other" }},
		{"UserUID", func(i *corev1.RequestContext) { i.User.Metadata.Uid = "other" }},
		{"UserResourceVersion", func(i *corev1.RequestContext) { i.User.Metadata.ResourceVersion = "other" }},
		{"NoUser", func(i *corev1.RequestContext) { i.User = nil }},
		{"GroupUID", func(i *corev1.RequestContext) { i.Groups[1].Metadata.Uid = "other" }},
		{"GroupResourceVersion", func(i *corev1.RequestContext) { i.Groups[1].Metadata.ResourceVersion = "other" }},
		{"GroupRemoved", func(i *corev1.RequestContext) { i.Groups = i.Groups[:1] }},
		{"NoGroups", func(i *corev1.RequestContext) { i.Groups = nil }},
		{"GroupsReordered", func(i *corev1.RequestContext) { i.Groups[0], i.Groups[1] = i.Groups[1], i.Groups[0] }},
		{"GroupDuplicated", func(i *corev1.RequestContext) { i.Groups = append(i.Groups, i.Groups[1]) }},
		{"DeviceUID", func(i *corev1.RequestContext) { i.Device.Metadata.Uid = "other" }},
		{"DeviceResourceVersion", func(i *corev1.RequestContext) { i.Device.Metadata.ResourceVersion = "other" }},
		{"NoDevice", func(i *corev1.RequestContext) { i.Device = nil }},
		{"NoDeviceStatus", func(i *corev1.RequestContext) { i.Device.Status = nil }},
		{"NoPosture", func(i *corev1.RequestContext) { i.Device.Status.Posture = nil }},
		{"ProbeAttempt", func(i *corev1.RequestContext) {
			i.Device.Status.ProbeAttempt = &corev1.Device_Status_ProbeAttempt{Uid: "attempt"}
		}},
		{"Assurance", func(i *corev1.RequestContext) {
			i.Device.Status.Binding.Assurance = corev1.Device_Status_Binding_IDENTIFIER
		}},
		{"NoBinding", func(i *corev1.RequestContext) { i.Device.Status.Binding = nil }},
		{"NamespaceUID", func(i *corev1.RequestContext) { i.Namespace.Metadata.Uid = "other" }},
		{"NamespaceResourceVersion", func(i *corev1.RequestContext) { i.Namespace.Metadata.ResourceVersion = "other" }},
		{"NoNamespace", func(i *corev1.RequestContext) { i.Namespace = nil }},
		{"UIDBoundary", func(i *corev1.RequestContext) {
			i.User.Metadata.Uid, i.User.Metadata.ResourceVersion = "useru", "ser-rv"
		}},
		{"SwappedUIDAndResourceVersion", func(i *corev1.RequestContext) {
			i.User.Metadata.Uid, i.User.Metadata.ResourceVersion = "user-rv", "user"
		}},
		{"UserAsGroup", func(i *corev1.RequestContext) {
			i.Groups = append([]*corev1.Group{{Metadata: i.User.Metadata}}, i.Groups...)
			i.User = nil
		}},
		{"NamespaceAsGroup", func(i *corev1.RequestContext) {
			i.Groups = append(i.Groups, &corev1.Group{Metadata: i.Namespace.Metadata})
			i.Namespace = nil
		}},
		{"SessionAsUser", func(i *corev1.RequestContext) {
			i.User.Metadata = i.Session.Metadata
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqCtx := newIdentityRequestContext()
			tc.update(reqCtx)
			fingerprint := getIdentityFingerprint(reqCtx)
			assert.Len(t, fingerprint, sha256.Size)
			assert.Equal(t, fingerprint, getIdentityFingerprint(pbutils.Clone(reqCtx).(*corev1.RequestContext)))
			prev, ok := fingerprints[string(fingerprint)]
			assert.False(t, ok, "same fingerprint as %s", prev)
			fingerprints[string(fingerprint)] = tc.name
		})
	}

	for _, tc := range []struct {
		name   string
		update func(*corev1.RequestContext)
	}{
		{"NoSession", func(i *corev1.RequestContext) { i.Session = nil }},
		{"NoSessionMetadata", func(i *corev1.RequestContext) { i.Session.Metadata = nil }},
		{"EmptySessionUID", func(i *corev1.RequestContext) { i.Session.Metadata.Uid = "" }},
		{"EmptySessionResourceVersion", func(i *corev1.RequestContext) { i.Session.Metadata.ResourceVersion = "" }},
		{"NoUserMetadata", func(i *corev1.RequestContext) { i.User.Metadata = nil }},
		{"EmptyUserUID", func(i *corev1.RequestContext) { i.User.Metadata.Uid = "" }},
		{"EmptyUserResourceVersion", func(i *corev1.RequestContext) { i.User.Metadata.ResourceVersion = "" }},
		{"NilGroup", func(i *corev1.RequestContext) { i.Groups = append(i.Groups, nil) }},
		{"NoGroupMetadata", func(i *corev1.RequestContext) { i.Groups[0].Metadata = nil }},
		{"EmptyGroupUID", func(i *corev1.RequestContext) { i.Groups[1].Metadata.Uid = "" }},
		{"EmptyGroupResourceVersion", func(i *corev1.RequestContext) { i.Groups[1].Metadata.ResourceVersion = "" }},
		{"NoDeviceMetadata", func(i *corev1.RequestContext) { i.Device.Metadata = nil }},
		{"EmptyDeviceUID", func(i *corev1.RequestContext) { i.Device.Metadata.Uid = "" }},
		{"EmptyDeviceResourceVersion", func(i *corev1.RequestContext) { i.Device.Metadata.ResourceVersion = "" }},
		{"NoNamespaceMetadata", func(i *corev1.RequestContext) { i.Namespace.Metadata = nil }},
		{"EmptyNamespaceUID", func(i *corev1.RequestContext) { i.Namespace.Metadata.Uid = "" }},
		{"EmptyNamespaceResourceVersion", func(i *corev1.RequestContext) { i.Namespace.Metadata.ResourceVersion = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reqCtx := newIdentityRequestContext()
			tc.update(reqCtx)
			assert.Nil(t, getIdentityFingerprint(reqCtx))
		})
	}

	assert.Nil(t, getIdentityFingerprint(nil))
	assert.Nil(t, getIdentityFingerprint(&corev1.RequestContext{}))
	assert.Nil(t, getIdentityFingerprint(&corev1.RequestContext{
		Service:   &corev1.Service{Metadata: &metav1.Metadata{Uid: "service", ResourceVersion: "service-rv"}},
		Namespace: &corev1.Namespace{Metadata: &metav1.Metadata{Uid: "namespace", ResourceVersion: "namespace-rv"}},
	}))
	assert.Len(t, getIdentityFingerprint(&corev1.RequestContext{Session: newIdentityRequestContext().Session}), sha256.Size)
}

func TestGetIdentityFingerprintEffectiveDevice(t *testing.T) {
	now := time.Now()
	r := rand.New(rand.NewPCG(7, 11))
	getEnum := func(names map[int32]string) int32 {
		return int32(r.IntN(len(names)))
	}

	var devices []*corev1.Device
	for i := range 96 {
		dev := &corev1.Device{Metadata: &metav1.Metadata{Uid: "device", ResourceVersion: fmt.Sprintf("device-%d", i)}}
		devices = append(devices, dev)
		if r.IntN(10) == 0 {
			continue
		}
		dev.Status = &corev1.Device_Status{OsType: corev1.Device_Status_LINUX}
		if r.IntN(5) > 0 {
			dev.Status.Binding = &corev1.Device_Status_Binding{
				Uid:       []string{"", "binding", "other"}[r.IntN(3)],
				State:     corev1.Device_Status_Binding_State(getEnum(corev1.Device_Status_Binding_State_name)),
				Validity:  corev1.Device_Status_Binding_Validity(getEnum(corev1.Device_Status_Binding_Validity_name)),
				Assurance: corev1.Device_Status_Binding_Assurance(getEnum(corev1.Device_Status_Binding_Assurance_name)),
			}
			if r.IntN(2) == 0 {
				dev.Status.Binding.State = corev1.Device_Status_Binding_ACCEPTED
				dev.Status.Binding.Validity = corev1.Device_Status_Binding_VALID
			}
		}
		if r.IntN(4) > 0 {
			dev.Status.Posture = &corev1.Device_Status_Posture{DiskEncryption: corev1.Device_Status_Posture_PASS}
			switch r.IntN(5) {
			case 0:
			case 1:
				dev.Status.Posture.ExpiresAt = &timestamppb.Timestamp{Seconds: -1 << 62}
			default:
				dev.Status.Posture.ExpiresAt = timestamppb.New(now.Add(time.Duration(r.IntN(120)-60) * time.Minute))
			}
		}
		if r.IntN(2) == 0 {
			dev.Status.ProbeAttempt = &corev1.Device_Status_ProbeAttempt{Uid: "attempt"}
		}
	}

	var sessions []*corev1.Session
	for i := range 24 {
		sess := &corev1.Session{
			Metadata: &metav1.Metadata{Uid: "session", ResourceVersion: fmt.Sprintf("session-%d", i)},
			Status:   &corev1.Session_Status{},
		}
		if r.IntN(4) > 0 {
			sess.Status.DeviceProof = &corev1.Session_Status_DeviceProof{
				Type:       corev1.Session_Status_DeviceProof_Type(getEnum(corev1.Session_Status_DeviceProof_Type_name)),
				BindingUID: []string{"", "binding", "other"}[r.IntN(3)],
			}
		}
		sessions = append(sessions, sess)
	}

	type sample struct {
		session *corev1.Session
		device  *corev1.Device
	}
	seen := make(map[string]sample)
	variants := make(map[string]map[string]bool)
	var transformed int
	for range 50000 {
		dev := devices[r.IntN(len(devices))]
		sess := sessions[r.IntN(len(sessions))]
		orig := pbutils.Clone(dev).(*corev1.Device)
		effective := getEffectiveDevice(dev, sess, now.Add(time.Duration(r.IntN(120)-60)*time.Minute))
		assert.True(t, pbutils.IsEqual(orig, dev))
		if effective != dev {
			transformed++
		}

		fingerprint := getIdentityFingerprint(&corev1.RequestContext{Session: sess, Device: effective})
		if !assert.Len(t, fingerprint, sha256.Size) {
			return
		}
		if prev, ok := seen[string(fingerprint)]; ok {
			assert.Same(t, prev.session, sess)
			assert.True(t, pbutils.IsEqual(prev.device, effective), "%v\n%v", prev.device, effective)
		} else {
			seen[string(fingerprint)] = sample{session: sess, device: effective}
		}

		pair := dev.Metadata.ResourceVersion + "/" + sess.Metadata.ResourceVersion
		if variants[pair] == nil {
			variants[pair] = make(map[string]bool)
		}
		variants[pair][string(fingerprint)] = true
	}

	var timeDependent int
	for _, fingerprints := range variants {
		assert.LessOrEqual(t, len(fingerprints), 2)
		if len(fingerprints) == 2 {
			timeDependent++
		}
	}
	assert.Equal(t, len(devices)*len(sessions), len(variants))
	assert.Greater(t, timeDependent, 100)
	assert.Greater(t, transformed, 10000)
}

func newIdentityService(t *testing.T) (*internalService, *authorizationCoreC, *downstreamCoreC) {
	t.Helper()
	srv, coreC := newAuthorizationService(t)
	downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
	downstream.session.Metadata.ResourceVersion = vutils.UUIDv7()
	downstream.user.Metadata.ResourceVersion = vutils.UUIDv7()
	downstream.device.Metadata.ResourceVersion = vutils.UUIDv7()
	for _, grp := range downstream.groups {
		grp.Metadata.ResourceVersion = vutils.UUIDv7()
		assert.Nil(t, srv.s.cache.SetGroup(grp))
	}
	coreC.namespace.Metadata.ResourceVersion = vutils.UUIDv7()
	coreC.service.Metadata.ResourceVersion = vutils.UUIDv7()
	assert.Nil(t, srv.s.cache.SetUser(downstream.user))
	assert.Nil(t, srv.s.cache.SetDevice(downstream.device))
	assert.Nil(t, srv.s.cache.SetSession(downstream.session))
	assert.Nil(t, srv.s.cache.SetNamespace(coreC.namespace))
	assert.Nil(t, srv.s.cache.SetService(coreC.service))
	return srv, coreC, downstream
}

func newIdentityRPCClient(t *testing.T, srv *internalService) coctovigilv1.InternalServiceClient {
	t.Helper()
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	srv.s.grpcSrv = server
	coctovigilv1.RegisterInternalServiceServer(server, srv)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		assert.Nil(t, srv.s.Close())
		listener.Close()
		select {
		case err := <-done:
			assert.Nil(t, err)
		case <-time.After(3 * time.Second):
			assert.Fail(t, "the internal RPC server did not stop")
		}
	})
	conn, err := grpc.NewClient("passthrough:///octovigil",
		grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.Nil(t, err)
	t.Cleanup(func() { conn.Close() })
	return coctovigilv1.NewInternalServiceClient(conn)
}

func restoreIdentity(resp *coctovigilv1.AuthenticateAndAuthorizeResponse, from *corev1.RequestContext) {
	resp.RequestContext.Session = from.Session
	resp.RequestContext.User = from.User
	resp.RequestContext.Groups = from.Groups
	resp.RequestContext.Device = from.Device
	resp.RequestContext.Namespace = from.Namespace
}

func TestAuthenticateAndAuthorizeRPCIdentity(t *testing.T) {
	request := &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
		Http: &corev1.RequestContext_Request_HTTP{Path: "/private", Method: "GET", Headers: map[string]string{"x-tenant": "tenant"}},
	}}
	other := sha256.Sum256([]byte("other"))

	for _, shape := range []string{"Authorized", "Unauthorized", "Anonymous", "ConfigName", "Config", "Unauthenticated",
		"NoDevice", "NoGroups", "MissingGroup", "NoNamespace", "PostureUsable",
		"EmptySessionResourceVersion", "EmptyUserResourceVersion", "EmptyGroupResourceVersion",
		"EmptyDeviceResourceVersion", "EmptyNamespaceResourceVersion"} {
		t.Run(shape, func(t *testing.T) {
			srv, coreC, downstream := newIdentityService(t)
			address := "100.64.0.2"
			isFingerprinted := true
			switch shape {
			case "Unauthorized":
				coreC.service.Spec.Authorization.InlinePolicies[0].Spec.Rules[0].Effect = corev1.Policy_Spec_Rule_DENY
			case "Anonymous":
				coreC.service.Spec.IsAnonymous = true
				coreC.service.Spec.Authorization.EnableAnonymous = true
				isFingerprinted = false
			case "ConfigName":
				coreC.service.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{{Name: "named", Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "http://127.0.0.1:9091"},
					}}},
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{{
						Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
						Type:      &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "named"},
					}},
				}
			case "Config":
				coreC.service.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{{
						Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
						Type:      &corev1.Service_Spec_DynamicConfig_Rule_Eval{Eval: `{"upstream": {"url": "http://127.0.0.1:9090"}}`},
					}},
				}
			case "Unauthenticated":
				address = "192.0.2.1"
				isFingerprinted = false
			case "NoDevice":
				downstream.session.Status.DeviceRef = nil
			case "NoGroups":
				downstream.user.Spec.Groups = nil
			case "MissingGroup":
				downstream.user.Spec.Groups = append(downstream.user.Spec.Groups, "group3")
			case "NoNamespace":
				coreC.service.Status.NamespaceRef.Uid = "missing"
			case "PostureUsable":
				downstream.device.Status.ProbeAttempt = nil
				downstream.device.Status.Binding = &corev1.Device_Status_Binding{
					Uid: "binding", State: corev1.Device_Status_Binding_ACCEPTED,
					Validity: corev1.Device_Status_Binding_VALID, Assurance: corev1.Device_Status_Binding_IDENTIFIER,
				}
				downstream.device.Status.Posture.ExpiresAt = timestamppb.New(time.Now().Add(time.Hour))
			case "EmptySessionResourceVersion":
				downstream.session.Metadata.ResourceVersion = ""
				isFingerprinted = false
			case "EmptyUserResourceVersion":
				downstream.user.Metadata.ResourceVersion = ""
				isFingerprinted = false
			case "EmptyGroupResourceVersion":
				downstream.groups[1].Metadata.ResourceVersion = ""
				isFingerprinted = false
			case "EmptyDeviceResourceVersion":
				downstream.device.Metadata.ResourceVersion = ""
				isFingerprinted = false
			case "EmptyNamespaceResourceVersion":
				coreC.namespace.Metadata.ResourceVersion = ""
				isFingerprinted = false
			}
			for _, grp := range downstream.groups {
				assert.Nil(t, srv.s.cache.SetGroup(grp))
			}
			assert.Nil(t, srv.s.cache.SetUser(downstream.user))
			assert.Nil(t, srv.s.cache.SetDevice(downstream.device))
			assert.Nil(t, srv.s.cache.SetSession(downstream.session))
			assert.Nil(t, srv.s.cache.SetService(coreC.service))
			assert.Nil(t, srv.s.cache.SetNamespace(coreC.namespace))
			cached := pbutils.Clone(&corev1.RequestContext{
				Session: downstream.session, User: downstream.user, Groups: downstream.groups,
				Device: downstream.device, Namespace: coreC.namespace, Service: coreC.service,
			}).(*corev1.RequestContext)

			client := newIdentityRPCClient(t, srv)
			downstreamReq := &coctovigilv1.DownstreamRequest{
				Source:  &coctovigilv1.DownstreamRequest_Source{Address: address},
				Request: request,
			}
			call := func(req *coctovigilv1.AuthenticateAndAuthorizeRequest) *coctovigilv1.AuthenticateAndAuthorizeResponse {
				req.ServiceUID = "service"
				req.Request = downstreamReq
				resp, err := client.AuthenticateAndAuthorize(t.Context(), req)
				assert.Nil(t, err)
				assert.NotNil(t, resp)
				return resp
			}

			legacy := call(&coctovigilv1.AuthenticateAndAuthorizeRequest{})
			if legacy == nil {
				return
			}
			assert.Empty(t, legacy.IdentityFingerprint)
			assert.False(t, legacy.IsIdentityOmitted)
			switch shape {
			case "Unauthenticated":
				assert.False(t, legacy.IsAuthenticated)
				assert.Nil(t, legacy.RequestContext)
			case "Anonymous":
				assert.False(t, legacy.IsAuthenticated)
				assert.True(t, legacy.IsAuthorized)
				assert.Nil(t, legacy.RequestContext.Session)
				assert.NotNil(t, legacy.RequestContext.Namespace)
			case "Unauthorized":
				assert.True(t, legacy.IsAuthenticated)
				assert.False(t, legacy.IsAuthorized)
				assert.NotNil(t, legacy.RequestContext.Session)
			default:
				assert.True(t, legacy.IsAuthenticated)
				assert.True(t, legacy.IsAuthorized)
				assert.NotNil(t, legacy.RequestContext.Session)
			}
			switch shape {
			case "NoDevice":
				assert.Nil(t, legacy.RequestContext.Device)
			case "NoGroups":
				assert.Empty(t, legacy.RequestContext.Groups)
			case "MissingGroup":
				assert.Len(t, legacy.RequestContext.Groups, 2)
			case "NoNamespace":
				assert.Nil(t, legacy.RequestContext.Namespace)
			case "PostureUsable":
				assert.NotNil(t, legacy.RequestContext.Device.Status.Posture)
			}

			first := call(&coctovigilv1.AuthenticateAndAuthorizeRequest{OmitUnchangedIdentity: true})
			if first == nil {
				return
			}
			fingerprint := first.IdentityFingerprint
			if isFingerprinted {
				assert.Len(t, fingerprint, sha256.Size)
			} else {
				assert.Empty(t, fingerprint)
			}
			assert.Equal(t, getIdentityFingerprint(legacy.RequestContext), fingerprint)
			assert.False(t, first.IsIdentityOmitted)
			first.IdentityFingerprint = nil
			assert.True(t, pbutils.IsEqual(legacy, first))

			var omitted int
			for _, tc := range []struct {
				name        string
				fingerprint []byte
			}{
				{"None", nil},
				{"Same", fingerprint},
				{"Other", other[:]},
				{"Prefix", fingerprint[:len(fingerprint)/2]},
				{"Extended", append(slices.Clone(fingerprint), 0)},
			} {
				for _, omitUnchanged := range []bool{false, true} {
					for _, omitRequest := range []bool{false, true} {
						resp := call(&coctovigilv1.AuthenticateAndAuthorizeRequest{
							OmitRequest:            omitRequest,
							ServiceResourceVersion: cached.Service.Metadata.ResourceVersion,
							OmitUnchangedIdentity:  omitUnchanged,
							IdentityFingerprint:    tc.fingerprint,
						})
						if resp == nil {
							return
						}
						isOmitted := omitUnchanged && isFingerprinted && tc.name == "Same"
						assert.Equal(t, isOmitted, resp.IsIdentityOmitted, tc.name)
						if omitUnchanged {
							assert.Equal(t, fingerprint, resp.IdentityFingerprint)
						} else {
							assert.Empty(t, resp.IdentityFingerprint)
						}
						if isOmitted {
							omitted++
							assert.Nil(t, resp.RequestContext.Session)
							assert.Nil(t, resp.RequestContext.User)
							assert.Nil(t, resp.RequestContext.Groups)
							assert.Nil(t, resp.RequestContext.Device)
							assert.Nil(t, resp.RequestContext.Namespace)
							restoreIdentity(resp, legacy.RequestContext)
						}
						if resp.RequestContext != nil {
							assert.Equal(t, omitRequest, resp.RequestContext.Request == nil)
							assert.Nil(t, resp.RequestContext.Service)
							resp.RequestContext.Request = legacy.RequestContext.Request
							resp.RequestContext.Service = legacy.RequestContext.Service
						}
						resp.IdentityFingerprint = nil
						resp.IsIdentityOmitted = false
						assert.True(t, pbutils.IsEqual(legacy, resp), tc.name)
					}
				}
			}
			if isFingerprinted {
				assert.Equal(t, 2, omitted)
			} else {
				assert.Zero(t, omitted)
			}

			after := pbutils.Clone(&corev1.RequestContext{
				Session: downstream.session, User: downstream.user, Groups: downstream.groups,
				Device: downstream.device, Namespace: coreC.namespace, Service: coreC.service,
			}).(*corev1.RequestContext)
			assert.True(t, pbutils.IsEqual(cached, after))
			assert.Empty(t, coreC.calls)
		})
	}
}

func TestAuthenticateAndAuthorizeRPCIdentityChanges(t *testing.T) {
	request := &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
		Http: &corev1.RequestContext_Request_HTTP{Path: "/private", Method: "GET"},
	}}

	for _, change := range []string{"Session", "User", "UserGroupRemoved", "UserGroupsReordered", "UserGroupAdded",
		"Group", "GroupDeleted", "Device", "DeviceRemoved", "Namespace", "NamespaceEvicted",
		"SessionExpired", "OtherSession", "SameResourceVersion", "Service"} {
		t.Run(change, func(t *testing.T) {
			srv, coreC, downstream := newIdentityService(t)
			client := newIdentityRPCClient(t, srv)
			address := "100.64.0.2"
			call := func(req *coctovigilv1.AuthenticateAndAuthorizeRequest) *coctovigilv1.AuthenticateAndAuthorizeResponse {
				req.ServiceUID = "service"
				req.Request = &coctovigilv1.DownstreamRequest{
					Source:  &coctovigilv1.DownstreamRequest_Source{Address: address},
					Request: request,
				}
				resp, err := client.AuthenticateAndAuthorize(t.Context(), req)
				assert.Nil(t, err)
				assert.NotNil(t, resp)
				return resp
			}
			check := func(fingerprint []byte, isOmitted bool) []byte {
				t.Helper()
				legacy := call(&coctovigilv1.AuthenticateAndAuthorizeRequest{})
				resp := call(&coctovigilv1.AuthenticateAndAuthorizeRequest{
					OmitUnchangedIdentity: true,
					IdentityFingerprint:   fingerprint,
				})
				if legacy == nil || resp == nil {
					return nil
				}
				ret := resp.IdentityFingerprint
				assert.Equal(t, getIdentityFingerprint(legacy.RequestContext), ret)
				assert.Equal(t, isOmitted, resp.IsIdentityOmitted)
				if isOmitted {
					assert.Equal(t, fingerprint, ret)
					assert.Nil(t, resp.RequestContext.Session)
					restoreIdentity(resp, legacy.RequestContext)
				}
				resp.IdentityFingerprint = nil
				resp.IsIdentityOmitted = false
				assert.True(t, pbutils.IsEqual(legacy, resp))
				return ret
			}

			before := check(nil, false)
			assert.Len(t, before, sha256.Size)
			assert.Equal(t, before, check(before, true))

			newResourceVersion := func(md *metav1.Metadata) {
				md.ResourceVersion = vutils.UUIDv7()
				md.Labels = map[string]string{"version": md.ResourceVersion}
			}
			switch change {
			case "Session":
				sess := pbutils.Clone(downstream.session).(*corev1.Session)
				newResourceVersion(sess.Metadata)
				assert.Nil(t, srv.s.cache.SetSession(sess))
			case "User", "UserGroupRemoved", "UserGroupsReordered", "UserGroupAdded":
				usr := pbutils.Clone(downstream.user).(*corev1.User)
				newResourceVersion(usr.Metadata)
				switch change {
				case "UserGroupRemoved":
					usr.Spec.Groups = []string{"group1"}
				case "UserGroupsReordered":
					usr.Spec.Groups = []string{"group2", "group1"}
				case "UserGroupAdded":
					grp := &corev1.Group{
						Metadata: &metav1.Metadata{Uid: "group3", Name: "group3", ResourceVersion: vutils.UUIDv7()},
						Spec:     &corev1.Group_Spec{},
					}
					assert.Nil(t, srv.s.cache.SetGroup(grp))
					usr.Spec.Groups = append(usr.Spec.Groups, "group3")
				}
				assert.Nil(t, srv.s.cache.SetUser(usr))
			case "Group":
				grp := pbutils.Clone(downstream.groups[0]).(*corev1.Group)
				newResourceVersion(grp.Metadata)
				assert.Nil(t, srv.s.cache.SetGroup(grp))
			case "GroupDeleted":
				assert.Nil(t, srv.s.cache.DeleteGroup(downstream.groups[1]))
				downstream.groups = downstream.groups[:1]
			case "Device":
				dev := pbutils.Clone(downstream.device).(*corev1.Device)
				newResourceVersion(dev.Metadata)
				assert.Nil(t, srv.s.cache.SetDevice(dev))
			case "DeviceRemoved":
				sess := pbutils.Clone(downstream.session).(*corev1.Session)
				newResourceVersion(sess.Metadata)
				sess.Status.DeviceRef = nil
				assert.Nil(t, srv.s.cache.SetSession(sess))
			case "Namespace":
				ns := pbutils.Clone(coreC.namespace).(*corev1.Namespace)
				newResourceVersion(ns.Metadata)
				assert.Nil(t, srv.s.cache.SetNamespace(ns))
			case "NamespaceEvicted":
				assert.Nil(t, srv.s.cache.DeleteNamespace(coreC.namespace))
			case "SessionExpired":
				sess := pbutils.Clone(downstream.session).(*corev1.Session)
				newResourceVersion(sess.Metadata)
				sess.Spec.ExpiresAt = timestamppb.New(time.Now().Add(-time.Minute))
				assert.Nil(t, srv.s.cache.SetSession(sess))
			case "OtherSession":
				sess := pbutils.Clone(downstream.session).(*corev1.Session)
				sess.Metadata.Uid = vutils.UUIDv4()
				sess.Metadata.Name = "other"
				sess.Status.Connection.Addresses = []*metav1.DualStackNetwork{{V4: "100.64.0.3/32"}}
				assert.Nil(t, srv.s.cache.SetSession(sess))
				address = "100.64.0.3"
			case "SameResourceVersion":
				assert.Nil(t, srv.s.cache.SetUser(pbutils.Clone(downstream.user).(*corev1.User)))
				assert.Nil(t, srv.s.cache.SetSession(pbutils.Clone(downstream.session).(*corev1.Session)))
				assert.Nil(t, srv.s.cache.SetDevice(pbutils.Clone(downstream.device).(*corev1.Device)))
			case "Service":
				svc := pbutils.Clone(coreC.service).(*corev1.Service)
				newResourceVersion(svc.Metadata)
				assert.Nil(t, srv.s.cache.SetService(svc))
			}

			switch change {
			case "SameResourceVersion", "Service":
				assert.Equal(t, before, check(before, true))
			case "SessionExpired":
				assert.Empty(t, check(before, false))
			case "NamespaceEvicted":
				evicted := call(&coctovigilv1.AuthenticateAndAuthorizeRequest{
					OmitUnchangedIdentity: true,
					IdentityFingerprint:   before,
				})
				if evicted == nil {
					return
				}
				assert.False(t, evicted.IsIdentityOmitted)
				assert.Nil(t, evicted.RequestContext.Namespace)
				assert.NotNil(t, evicted.RequestContext.Session)
				assert.Len(t, evicted.IdentityFingerprint, sha256.Size)
				assert.NotEqual(t, before, evicted.IdentityFingerprint)
				assert.Equal(t, getIdentityFingerprint(evicted.RequestContext), evicted.IdentityFingerprint)
				assert.Equal(t, before, check(evicted.IdentityFingerprint, false))
				assert.Equal(t, before, check(before, true))
			default:
				after := check(before, false)
				assert.Len(t, after, sha256.Size)
				assert.NotEqual(t, before, after)
				assert.Equal(t, after, check(after, true))
				assert.Equal(t, after, check(nil, false))
			}
		})
	}
}

func TestAuthenticateAndAuthorizeIdentityPosture(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv, _, downstream := newIdentityService(t)
		downstream.device.Status.ProbeAttempt = nil
		downstream.device.Status.Binding = &corev1.Device_Status_Binding{
			Uid: "binding", State: corev1.Device_Status_Binding_ACCEPTED,
			Validity: corev1.Device_Status_Binding_VALID, Assurance: corev1.Device_Status_Binding_IDENTIFIER,
		}
		downstream.device.Status.Posture.ExpiresAt = timestamppb.New(time.Now().Add(time.Minute))
		assert.Nil(t, srv.s.cache.SetDevice(downstream.device))

		call := func(fingerprint []byte) *coctovigilv1.AuthenticateAndAuthorizeResponse {
			resp, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
				ServiceUID: "service",
				Request: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2"},
					Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
						Http: &corev1.RequestContext_Request_HTTP{Path: "/"},
					}},
				},
				OmitUnchangedIdentity: true,
				IdentityFingerprint:   fingerprint,
			})
			assert.Nil(t, err)
			assert.True(t, resp.IsAuthorized)
			return resp
		}

		usable := call(nil)
		assert.False(t, usable.IsIdentityOmitted)
		assert.Same(t, downstream.device, usable.RequestContext.Device)
		assert.True(t, call(usable.IdentityFingerprint).IsIdentityOmitted)

		time.Sleep(time.Minute - time.Second)
		assert.True(t, call(usable.IdentityFingerprint).IsIdentityOmitted)

		time.Sleep(time.Second)
		expired := call(usable.IdentityFingerprint)
		assert.False(t, expired.IsIdentityOmitted)
		assert.NotEqual(t, usable.IdentityFingerprint, expired.IdentityFingerprint)
		assert.NotSame(t, downstream.device, expired.RequestContext.Device)
		assert.Nil(t, expired.RequestContext.Device.Status.Posture)
		assert.NotNil(t, downstream.device.Status.Posture)
		assert.Equal(t, getIdentityFingerprint(expired.RequestContext), expired.IdentityFingerprint)
		assert.True(t, call(expired.IdentityFingerprint).IsIdentityOmitted)
		assert.False(t, call(usable.IdentityFingerprint).IsIdentityOmitted)
	})
}

func TestAuthenticateAndAuthorizeRPCIdentityConcurrent(t *testing.T) {
	srv, _, downstream := newIdentityService(t)
	client := newIdentityRPCClient(t, srv)

	other := pbutils.Clone(downstream.session).(*corev1.Session)
	other.Metadata.Uid = vutils.UUIDv4()
	other.Metadata.Name = "other"
	other.Metadata.ResourceVersion = vutils.UUIDv7()
	other.Status.Connection.Addresses = []*metav1.DualStackNetwork{{V4: "100.64.0.3/32"}}
	assert.Nil(t, srv.s.cache.SetSession(other))
	sessions := map[string]string{"100.64.0.2": downstream.session.Metadata.Uid, "100.64.0.3": other.Metadata.Uid}

	var mu sync.Mutex
	versions := make(map[string]*corev1.User)
	setUser := func(usr *corev1.User) {
		mu.Lock()
		versions[usr.Metadata.ResourceVersion] = pbutils.Clone(usr).(*corev1.User)
		mu.Unlock()
		assert.Nil(t, srv.s.cache.SetUser(usr))
	}
	setUser(downstream.user)

	var fingerprints sync.Map
	done := make(chan struct{})
	var updater sync.WaitGroup
	updater.Go(func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(time.Millisecond):
			}
			usr := pbutils.Clone(downstream.user).(*corev1.User)
			usr.Metadata.ResourceVersion = vutils.UUIDv7()
			usr.Metadata.Labels = map[string]string{"version": usr.Metadata.ResourceVersion}
			setUser(usr)
		}
	})

	var omitted, full sync.Map
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			r := rand.New(rand.NewPCG(uint64(i), 1))
			for range 200 {
				address := []string{"100.64.0.2", "100.64.0.3"}[r.IntN(2)]
				var fingerprint []byte
				switch r.IntN(3) {
				case 0:
					if v, ok := fingerprints.Load(address); ok {
						fingerprint = v.([]byte)
					}
				case 1:
					for other := range sessions {
						if v, ok := fingerprints.Load(other); ok && other != address {
							fingerprint = v.([]byte)
						}
					}
				}
				resp, err := client.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
					ServiceUID: "service",
					Request: &coctovigilv1.DownstreamRequest{
						Source: &coctovigilv1.DownstreamRequest_Source{Address: address},
						Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{Path: "/"},
						}},
					},
					OmitUnchangedIdentity: true,
					IdentityFingerprint:   fingerprint,
				})
				if !assert.Nil(t, err) || !assert.True(t, resp.IsAuthorized) {
					return
				}
				if resp.IsIdentityOmitted {
					assert.Equal(t, fingerprint, resp.IdentityFingerprint)
					assert.Nil(t, resp.RequestContext.Session)
					assert.Nil(t, resp.RequestContext.User)
					omitted.Store(i, true)
					continue
				}
				full.Store(i, true)
				assert.Equal(t, sessions[address], resp.RequestContext.Session.Metadata.Uid)
				assert.Equal(t, getIdentityFingerprint(resp.RequestContext), resp.IdentityFingerprint)
				mu.Lock()
				version := versions[resp.RequestContext.User.Metadata.ResourceVersion]
				mu.Unlock()
				assert.True(t, pbutils.IsEqual(version, resp.RequestContext.User))
				fingerprints.Store(address, resp.IdentityFingerprint)
			}
		})
	}
	wg.Wait()
	close(done)
	updater.Wait()

	var nOmitted, nFull int
	omitted.Range(func(k, v any) bool { nOmitted++; return true })
	full.Range(func(k, v any) bool { nFull++; return true })
	assert.Equal(t, 16, nFull)
	assert.Greater(t, nOmitted, 0)
}

func TestGetIdentityFingerprintBoundaries(t *testing.T) {
	newMetadata := func(uid, resourceVersion string) *metav1.Metadata {
		return &metav1.Metadata{Uid: uid, ResourceVersion: resourceVersion}
	}
	newReqCtx := func() *corev1.RequestContext {
		return &corev1.RequestContext{Session: &corev1.Session{Metadata: newMetadata("s", "s")}}
	}

	for _, tc := range []struct {
		name string
		a    func(*corev1.RequestContext)
		b    func(*corev1.RequestContext)
	}{
		{
			"UIDLength",
			func(i *corev1.RequestContext) { i.User = &corev1.User{Metadata: newMetadata("\x02", "\x01r")} },
			func(i *corev1.RequestContext) { i.User = &corev1.User{Metadata: newMetadata("\x02\x02", "r")} },
		},
		{
			"GroupCount",
			func(i *corev1.RequestContext) {
				i.Groups = []*corev1.Group{{Metadata: newMetadata("r\x02", "\x01\x02")}}
				i.Namespace = &corev1.Namespace{Metadata: newMetadata("\x01\x01", "\x01\x00")}
			},
			func(i *corev1.RequestContext) {
				i.Device = &corev1.Device{
					Metadata: newMetadata("r\x02", "\x01\x02"),
					Status: &corev1.Device_Status{
						ProbeAttempt: &corev1.Device_Status_ProbeAttempt{},
						Binding:      &corev1.Device_Status_Binding{Assurance: corev1.Device_Status_Binding_Assurance(2)},
					},
				}
				i.Namespace = &corev1.Namespace{Metadata: newMetadata("\x02", "\x00")}
			},
		},
		{
			"AbsentUser",
			func(i *corev1.RequestContext) { i.User = &corev1.User{Metadata: newMetadata("\x02", "\x00\x01")} },
			func(i *corev1.RequestContext) {
				i.Groups = []*corev1.Group{{Metadata: newMetadata("\x02\x00", "\x00")}}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newReqCtx()
			tc.a(a)
			b := newReqCtx()
			tc.b(b)
			assert.Len(t, getIdentityFingerprint(a), sha256.Size)
			assert.Len(t, getIdentityFingerprint(b), sha256.Size)
			assert.NotEqual(t, getIdentityFingerprint(a), getIdentityFingerprint(b))
		})
	}
}
