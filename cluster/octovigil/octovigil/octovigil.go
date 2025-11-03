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
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/ccctl"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/commoninit"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/httputils"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/octovigilc"
	"github.com/octelium/octelium/cluster/common/oscope"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/cluster/octovigil/octovigil/acache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	devicecontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/devices"
	groupcontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/groups"
	nscontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/namespaces"
	policycontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/policies"
	ptctl "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/policytemplates"
	svccontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/services"
	sesscontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/sessions"
	usercontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/users"
)

type Server struct {
	octeliumC octeliumc.ClientInterface

	cache  *acache.Cache
	jwkCtl *jwkctl.Controller
	domain string

	v4Prefix *netip.Prefix
	v6Prefix *netip.Prefix

	celEngine *celengine.CELEngine

	grpcSrv          *grpc.Server
	ccCtl            *ccctl.Controller
	policyTriggerCtl *policyTriggerCtl
	commonMetrics    *commonMetrics
}

type policyTriggerCtl struct {
	sync.RWMutex
	ptMap map[string]*corev1.PolicyTrigger
}

func (c *policyTriggerCtl) SetPolicyTrigger(i *corev1.PolicyTrigger) error {
	c.Lock()
	c.ptMap[i.Metadata.Uid] = i
	c.Unlock()
	return nil
}

func (c *policyTriggerCtl) DeletePolicyTrigger(i *corev1.PolicyTrigger) error {
	c.Lock()
	delete(c.ptMap, i.Metadata.Uid)
	c.Unlock()
	return nil
}

func New(ctx context.Context, octeliumC octeliumc.ClientInterface) (*Server, error) {

	aCache, err := acache.NewCache()
	if err != nil {
		return nil, err
	}

	ret := &Server{
		octeliumC: octeliumC,
		cache:     aCache,
		policyTriggerCtl: &policyTriggerCtl{
			ptMap: make(map[string]*corev1.PolicyTrigger),
		},
	}

	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}
	ret.domain = cc.Status.Domain

	if cc.Status.Network.ClusterNetwork.V4 != "" {
		v4Prefix, err := netip.ParsePrefix(cc.Status.Network.ClusterNetwork.V4)
		if err != nil {
			return nil, err
		}
		ret.v4Prefix = &v4Prefix
	}

	if cc.Status.Network.ClusterNetwork.V6 != "" {
		v6Prefix, err := netip.ParsePrefix(cc.Status.Network.ClusterNetwork.V6)
		if err != nil {
			return nil, err
		}
		ret.v6Prefix = &v6Prefix
	}

	jwkCtl, err := jwkctl.NewJWKController(ctx, octeliumC)
	if err != nil {
		return nil, err
	}

	ret.jwkCtl = jwkCtl

	ret.celEngine, err = celengine.New(ctx, &celengine.Opts{})
	if err != nil {
		return nil, err
	}

	ret.ccCtl, err = ccctl.New(ctx, octeliumC, &ccctl.Opts{})
	if err != nil {
		return nil, err
	}

	ret.commonMetrics, err = newCommonMetrics(ctx)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *Server) GetCache() *acache.Cache {
	return s.cache
}

func (s *Server) Close() error {
	err := s.cache.Close()
	if s.grpcSrv != nil {
		s.grpcSrv.Stop()
	}
	return err
}

func (s *Server) getReqCtx(di *acache.DownstreamInfo, req *corev1.RequestContext_Request, svc *corev1.Service) *corev1.RequestContext {
	reqCtx := &corev1.RequestContext{
		User:    di.User,
		Device:  di.Device,
		Service: svc,
		Session: di.Session,
		Groups:  di.Groups,
		Request: req,
	}

	reqCtx.Namespace, _ = s.cache.GetNamespace(svc.Status.NamespaceRef.Uid)

	return reqCtx
}

func (s *Server) getConnectionIdentifier(r *coctovigilv1.DoAuthenticateAndAuthorizeRequest) (string, *jwkctl.AccessTokenClaims, error) {
	if r == nil {
		return "", nil, errors.Errorf("Nil req")
	}

	if r.Service == nil {
		return "", nil, errors.Errorf("Nil Service")
	}

	if r.Request == nil {
		return "", nil, errors.Errorf("Nil DownstreamRequest")
	}

	svc := r.Service

	req := r.Request

	if req.Source != nil && req.Source.Address != "" && s.isAddressFromClient(req.Source.Address) {
		return req.Source.Address, nil, nil
	}

	if svc.Spec.IsPublic {
		if hdr := s.getHTTPHeadersFromReq(req); hdr != nil {
			if tkn, err := s.getAccessTokenFromHTTPHeader(hdr); err == nil {
				claims, err := s.jwkCtl.VerifyAccessToken(tkn)
				if err != nil {
					return "", nil, err
				}

				return claims.SessionUID, claims, nil
			}
		}
	}

	return "", nil, errors.Errorf("Could not find Connection identifier. This is not client connection and there are no auth headers")
}

func (s *Server) getHTTPHeadersFromReq(req *coctovigilv1.DownstreamRequest) map[string]string {
	if req.Request == nil {
		return nil
	}

	switch req.Request.Type.(type) {
	case *corev1.RequestContext_Request_Grpc:
		if req.Request.GetGrpc().Http == nil {
			return nil
		}
		return req.Request.GetGrpc().Http.Headers
	case *corev1.RequestContext_Request_Http:
		return req.Request.GetHttp().Headers
	case *corev1.RequestContext_Request_Kubernetes_:
		if req.Request.GetKubernetes().Http == nil {
			return nil
		}
		return req.Request.GetKubernetes().Http.Headers
	default:
		return nil
	}
}

func (s *Server) isAddressFromClient(addrStr string) bool {
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return false
	}

	if s.v6Prefix != nil && s.v6Prefix.Contains(addr) {
		return true
	}

	if s.v4Prefix != nil && s.v4Prefix.Contains(addr) {
		return true
	}

	return false
}

func (s *Server) getAccessTokenFromHTTPHeader(hdr map[string]string) (string, error) {
	if hdr == nil {
		return "", errors.Errorf("HTTP request headers do not exist")
	}

	if authHdr, ok := hdr["x-octelium-auth"]; ok && authHdr != "" {
		return authHdr, nil
	}

	if authHdr, ok := hdr["authorization"]; ok && strings.HasPrefix(authHdr, "Bearer ") {
		return strings.TrimPrefix(authHdr, "Bearer "), nil
	}

	cookieVal := hdr["cookie"]
	if cookieVal == "" {
		return "", errors.Errorf("Could not find jwt neither in header or cookie")
	}

	header := http.Header{}
	header.Add("Cookie", cookieVal)
	request := http.Request{Header: header}
	cookie, err := request.Cookie("octelium_auth")
	if err != nil {
		return "", err
	}

	return cookie.Value, nil
}

var UnauthenticatedErr = errors.New("Vigil Unauthenticated error")

func (s *Server) Authenticate(ctx context.Context, req *coctovigilv1.DoAuthenticateAndAuthorizeRequest) (*acache.DownstreamInfo, error) {
	return s.authenticate(ctx, req)
}

func (s *Server) authenticate(ctx context.Context, req *coctovigilv1.DoAuthenticateAndAuthorizeRequest) (*acache.DownstreamInfo, error) {

	sessID, tknClaims, err := s.getConnectionIdentifier(req)
	if err != nil {
		return nil, errors.Wrap(UnauthenticatedErr, fmt.Sprintf("Could not get connection identifier: %+v", err))
	}

	di, err := s.cache.GetDownstreamInfoBySessionIdentifier(sessID)
	if err != nil {
		if errors.Is(err, acache.SessionNotFound) {
			return nil, UnauthenticatedErr
		}
		return nil, errors.Errorf("Could not get downstream info from identifier: %+v", err)
	}

	if ucorev1.ToSession(di.Session).IsExpired() {
		return nil, errors.Wrap(UnauthenticatedErr, "The Session is expired")
	}

	if di.User == nil {
		usr, err := s.octeliumC.CoreC().GetUser(ctx,
			&rmetav1.GetOptions{Uid: di.Session.Status.UserRef.Uid})
		if err != nil {
			return nil, err
		}

		s.cache.SetUser(usr)

		di.User = usr
	}

	if di.Device == nil && di.Session.Status.DeviceRef != nil {
		device, err := s.octeliumC.CoreC().GetDevice(ctx,
			&rmetav1.GetOptions{
				Uid: di.Session.Status.DeviceRef.Uid,
			})
		if err != nil {
			return nil, err
		}

		s.cache.SetDevice(device)

		di.Device = device
	}

	if di.Groups == nil {
		for _, g := range di.User.Spec.Groups {
			grpV, err := s.octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{
				Name: g,
			})
			if err != nil {
				return nil, err
			}
			s.cache.SetGroup(grpV)
			di.Groups = append(di.Groups, grpV)
		}
	}

	if tknClaims != nil {
		if tknClaims.SessionUID != di.Session.Metadata.Uid {
			return nil, errors.Wrap(UnauthenticatedErr, "Token claims are not valid")
		}
		if tknClaims.TokenID != di.Session.Status.Authentication.TokenID {
			return nil, errors.Wrap(UnauthenticatedErr, "Token claims are not valid")
		}
	}

	return di, nil
}

type AuthenticateAndAuthorizeRequest struct {
	Service *corev1.Service
	Request *coctovigilv1.DownstreamRequest
}

type AuthenticateAndAuthorizeResponse struct {
	IsAuthenticated             bool
	IsAuthorized                bool
	RequestContext              *corev1.RequestContext
	AuthorizationDecisionReason *corev1.AccessLog_Entry_Common_Reason
}

func (s *Server) AuthenticateAndAuthorize(ctx context.Context, req *coctovigilv1.DoAuthenticateAndAuthorizeRequest) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
	ret := &coctovigilv1.AuthenticateAndAuthorizeResponse{}

	downstreamInfo, err := s.authenticate(ctx, req)
	if err != nil {
		zap.L().Debug("Could not authenticate", zap.Error(err))
		if errors.Is(err, UnauthenticatedErr) {
			return ret, nil
		}
		return nil, err
	}

	ret.IsAuthenticated = true
	ret.RequestContext = s.getReqCtx(downstreamInfo, req.Request.Request, req.Service)

	isAuthorized, reason, err := s.isAuthorizedWithMetrics(ctx, ret.RequestContext)
	if err != nil {
		return nil, err
	}

	ret.IsAuthorized = isAuthorized
	ret.AuthorizationDecisionReason = reason

	if err := s.setServiceConfig(ctx, ret); err != nil {
		zap.L().Warn("Could not getServiceConfigNam", zap.Error(err))
	}

	return ret, nil
}

func (s *Server) isAuthorizedWithMetrics(ctx context.Context, req *corev1.RequestContext) (bool, *corev1.AccessLog_Entry_Common_Reason, error) {
	startedAt := time.Now()
	s.commonMetrics.atAuthorizationRequestStart()
	isAuthorized, reason, err := s.isAuthorized(ctx, req)
	s.commonMetrics.atAuthorizationRequestEnd(startedAt,
		metric.WithAttributeSet(
			attribute.NewSet(
				attribute.Bool("req.authorized", isAuthorized),
				attribute.Bool("req.error", err != nil))))
	return isAuthorized, reason, err
}

func (s *Server) setServiceConfig(ctx context.Context, resp *coctovigilv1.AuthenticateAndAuthorizeResponse) error {

	reqCtx := resp.RequestContext
	svc := reqCtx.Service
	if svc.Spec.DynamicConfig == nil || len(svc.Spec.DynamicConfig.Rules) < 1 {
		return nil
	}

	reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
	if err != nil {
		return err
	}

	inputMap := map[string]any{
		"ctx": reqCtxMap,
	}

	for _, rule := range svc.Spec.DynamicConfig.Rules {
		isMatch, err := s.celEngine.EvalCondition(ctx, rule.Condition, inputMap)
		if err != nil {
			zap.L().Warn("Could not evalCondition for dynamicConfig rule",
				zap.Any("cond", rule.Condition), zap.Error(err))
			continue
		}
		if isMatch {
			switch rule.Type.(type) {
			case *corev1.Service_Spec_DynamicConfig_Rule_ConfigName:
				resp.ServiceConfigName = rule.GetConfigName()
				return nil
			case *corev1.Service_Spec_DynamicConfig_Rule_Eval:
				if cfgMap, err := s.celEngine.EvalPolicyMapStrAny(ctx, rule.GetEval(), inputMap); err == nil {
					cfg := &corev1.Service_Spec_Config{}
					if err := pbutils.UnmarshalFromMap(cfgMap, cfg); err == nil {
						resp.Config = cfg
						return nil
					}
				}
			}
		}
	}

	return nil
}

func (s *Server) DoAuthorize(ctx context.Context,
	req *corev1.RequestContext) (*coctovigilv1.AuthorizeResponse, error) {
	isAuthorized, reason, err := s.isAuthorized(ctx, req)
	if err != nil {
		return nil, err
	}

	return &coctovigilv1.AuthorizeResponse{
		IsAuthorized: isAuthorized,
		Reason:       reason,
	}, nil
}

func (s *Server) isAuthorized(ctx context.Context,
	req *corev1.RequestContext) (bool, *corev1.AccessLog_Entry_Common_Reason, error) {

	reason := &corev1.AccessLog_Entry_Common_Reason{}
	if req == nil {
		return false, nil, errors.Errorf("Nil request")
	}
	if req.User == nil {
		return false, nil, errors.Errorf("Nil User")
	}
	if req.Session == nil {
		return false, nil, errors.Errorf("Nil Session")
	}
	if req.Service == nil {
		return false, nil, errors.Errorf("Nil Service")
	}

	if !ucorev1.ToSession(req.Session).IsValid() {
		reason.Type = corev1.AccessLog_Entry_Common_Reason_SESSION_INVALID
		return false, reason, nil
	}

	if req.Session.Status.IsLocked {
		reason.Type = corev1.AccessLog_Entry_Common_Reason_SESSION_LOCKED
		return false, reason, nil
	}

	if req.User.Status.IsLocked {
		reason.Type = corev1.AccessLog_Entry_Common_Reason_USER_LOCKED
		return false, reason, nil
	}

	switch req.Session.Status.AuthenticatorAction {
	case corev1.Session_Status_AUTHENTICATOR_ACTION_UNSET:
	case corev1.Session_Status_AUTHENTICATION_REQUIRED:
		reason.Type = corev1.AccessLog_Entry_Common_Reason_AUTHENTICATOR_AUTHENTICATION_REQUIRED
		return false, reason, nil
	case corev1.Session_Status_REGISTRATION_REQUIRED:
		reason.Type = corev1.AccessLog_Entry_Common_Reason_AUTHENTICATOR_REGISTRATION_REQUIRED
		return false, reason, nil
	case corev1.Session_Status_AUTHENTICATION_RECOMMENDED,
		corev1.Session_Status_REGISTRATION_RECOMMENDED:
	default:
		return false, reason, errors.Errorf("Unhandled authenticatorAction")
	}

	if req.Device != nil &&
		req.Device.Spec.State != corev1.Device_Spec_ACTIVE {
		reason.Type = corev1.AccessLog_Entry_Common_Reason_DEVICE_NOT_ACTIVE
		return false, reason, nil
	}

	if req.Device != nil && req.Device.Status.IsLocked {
		reason.Type = corev1.AccessLog_Entry_Common_Reason_DEVICE_LOCKED
		return false, reason, nil
	}

	if req.User.Spec.IsDisabled {
		reason.Type = corev1.AccessLog_Entry_Common_Reason_USER_DEACTIVATED
		return false, reason, nil
	}

	if (!req.Service.Spec.IsPublic) && (!ucorev1.ToSession(req.Session).IsClient()) {
		reason.Type = corev1.AccessLog_Entry_Common_Reason_SESSION_CLIENT_TYPE_INVALID
		return false, reason, nil
	}

	if req.Service.Spec.IsPublic && req.Session.Status.Type == corev1.Session_Status_CLIENTLESS {
		if cc := s.ccCtl.Get(); cc != nil && cc.Spec.Ingress != nil && cc.Spec.Ingress.UseForwardedForHeader {
			if req.Request != nil && req.Request.GetHttp() != nil && req.Request.GetHttp().Headers != nil {
				ipAddr := httputils.GetDownstreamPublicIPFromXFFHeader(req.Request.GetHttp().Headers["x-forwarded-for"])
				if ipAddr != "" && req.Session.Status.Authentication != nil &&
					req.Session.Status.Authentication.Info != nil &&
					req.Session.Status.Authentication.Info.Downstream != nil &&
					req.Session.Status.Authentication.Info.Downstream.IpAddress != "" {
					if ipAddr != req.Session.Status.Authentication.Info.Downstream.IpAddress {
						return false, reason, nil
					}
				}
			}
		}
	}

	if !oscope.IsAuthorizedByScopes(req) {
		reason.Type = corev1.AccessLog_Entry_Common_Reason_SCOPE_UNAUTHORIZED
		return false, reason, nil
	}

	ctx, cancelFn := context.WithTimeout(ctx, 2*time.Second)
	defer cancelFn()

	resp, err := s.getDecision(ctx, &getDecisionReq{
		i: req,
	})
	if err != nil {
		return false, reason, err
	}

	if resp.decision == matchDecisionMATCH_YES {
		return resp.effect == corev1.Policy_Spec_Rule_ALLOW,
			resp.reason, nil
	}

	reason = &corev1.AccessLog_Entry_Common_Reason{
		Type: corev1.AccessLog_Entry_Common_Reason_NO_POLICY_MATCH,
	}
	return false, reason, nil

}

func Run(ctx context.Context) error {

	zap.L().Debug("Starting running Octovigil")

	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return err
	}

	if err := commoninit.Run(ctx, nil); err != nil {
		return err
	}

	s, err := New(ctx, octeliumC)
	if err != nil {
		return err
	}
	if err := s.run(ctx); err != nil {
		return err
	}

	watcher := watchers.NewCoreV1(octeliumC)

	usrCtl := usercontroller.NewController(s.GetCache())
	groupCtl := groupcontroller.NewController(s.GetCache())
	deviceCtl := devicecontroller.NewController(s.GetCache())
	sessCtl := sesscontroller.NewController(s.GetCache())
	svcCtl := svccontroller.NewController(s.GetCache())
	policyCtl := policycontroller.NewController(s.GetCache())

	nsCtl := nscontroller.NewController(s.GetCache())
	ptCtl := ptctl.NewController(s.policyTriggerCtl)

	if err := watcher.User(ctx, nil, usrCtl.OnAdd, usrCtl.OnUpdate, usrCtl.OnDelete); err != nil {
		return err
	}

	if err := watcher.Group(ctx, nil, groupCtl.OnAdd, groupCtl.OnUpdate, groupCtl.OnDelete); err != nil {
		return err
	}

	if err := watcher.Namespace(ctx, nil, nsCtl.OnAdd, nsCtl.OnUpdate, nsCtl.OnDelete); err != nil {
		return err
	}

	if err := watcher.Device(ctx, nil, deviceCtl.OnAdd, deviceCtl.OnUpdate, deviceCtl.OnDelete); err != nil {
		return err
	}

	if err := watcher.Session(ctx, nil, sessCtl.OnAdd, sessCtl.OnUpdate, sessCtl.OnDelete); err != nil {
		return err
	}

	if err := watcher.Service(ctx, nil, svcCtl.OnAdd, svcCtl.OnUpdate, svcCtl.OnDelete); err != nil {
		return err
	}

	if err := watcher.Policy(ctx, nil, policyCtl.OnAdd, policyCtl.OnUpdate, policyCtl.OnDelete); err != nil {
		return err
	}

	if err := watcher.PolicyTrigger(ctx, nil, ptCtl.OnAdd, ptCtl.OnUpdate, ptCtl.OnDelete); err != nil {
		return err
	}

	zap.L().Info("Octovigil is now running")

	<-ctx.Done()

	zap.L().Debug("Received TERM signal. Shutting down...")

	return nil
}

func (s *Server) run(ctx context.Context) error {

	if err := s.ccCtl.Run(ctx); err != nil {
		return err
	}

	if err := s.jwkCtl.Run(ctx); err != nil {
		return err
	}

	s.grpcSrv = grpc.NewServer(
		grpc.MaxConcurrentStreams(100*1000),
		grpc.MaxRecvMsgSize(33*1024*1024),
		grpc.MaxSendMsgSize(33*1024*1024),
	)
	coctovigilv1.RegisterInternalServiceServer(s.grpcSrv, &internalService{
		s: s,
	})
	grpc_health_v1.RegisterHealthServer(s.grpcSrv, healthcheck.NewServer())

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", octovigilc.GetPort()))
	if err != nil {
		return err
	}

	go func() {
		zap.L().Debug("running gRPC server.")
		if err := s.grpcSrv.Serve(lis); err != nil {
			zap.L().Info("gRPC server closed", zap.Error(err))
		}
	}()

	return nil
}

func (s *Server) Run(ctx context.Context) error {
	return s.run(ctx)
}
