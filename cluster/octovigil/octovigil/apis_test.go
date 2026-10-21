package octovigil

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
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
