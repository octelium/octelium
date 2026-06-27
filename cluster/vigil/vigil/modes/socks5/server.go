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

package socks5

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/ocrypto"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/cluster/vigil/vigil/vigilutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const handshakeTimeout = 10 * time.Second

type Server struct {
	octovigilC *octovigilc.Client
	vCache     *vcache.Cache

	lis      net.Listener
	socksSrv *gosocks5.Server

	octeliumC octeliumc.ClientInterface

	cancelFn     context.CancelFunc
	doneComplete chan struct{}
	dctxMap      struct {
		mu      sync.Mutex
		dctxMap map[string]*dctx
	}

	mu       sync.Mutex
	isClosed bool

	lbManager *loadbalancer.LBManager
	secretMan *secretman.SecretManager

	crtMan struct {
		mu  sync.RWMutex
		crt *corev1.Secret
	}
	tlsCfgMan struct {
		tlsCfg *tls.Config
		mu     sync.RWMutex
	}

	metricsStore *metricsStore
}

type metricsStore struct {
	*metricutils.CommonMetrics
}

func New(ctx context.Context, opts *modes.Opts) (*Server, error) {
	server := &Server{
		doneComplete: make(chan struct{}),
		octovigilC:   opts.OctovigilC,
		vCache:       opts.VCache,
		octeliumC:    opts.OcteliumC,
		lbManager:    opts.LBManager,
		secretMan:    opts.SecretMan,
		metricsStore: &metricsStore{},
	}

	server.dctxMap.dctxMap = make(map[string]*dctx)

	var err error
	server.metricsStore.CommonMetrics, err = metricutils.NewCommonMetrics(ctx, opts.VCache.GetService())
	if err != nil {
		return nil, err
	}

	server.socksSrv = gosocks5.NewServer(
		gosocks5.WithAuthMethods([]gosocks5.Authenticator{
			&gosocks5.UserPassAuthenticator{
				Credentials: sessionSelectorCredentialStore{},
			},
			gosocks5.NoAuthAuthenticator{},
		}),
		gosocks5.WithResolver(noResolveResolver{}),
		gosocks5.WithRule(&gosocks5.PermitCommand{
			EnableConnect:   true,
			EnableBind:      false,
			EnableAssociate: false,
		}),
		gosocks5.WithLogger(zapLogger{}),
		gosocks5.WithConnectHandle(server.handleConnect),
		gosocks5.WithBindHandle(rejectUnsupportedCommand),
		gosocks5.WithAssociateHandle(rejectUnsupportedCommand),
	)

	return server, nil
}

func (s *Server) svc() *corev1.Service {
	return s.vCache.GetService()
}

func (s *Server) SetClusterCertificate(crt *corev1.Secret) error {
	s.crtMan.mu.Lock()
	defer s.crtMan.mu.Unlock()
	s.crtMan.crt = crt
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isClosed {
		return nil
	}

	s.isClosed = true

	if s.cancelFn != nil {
		s.cancelFn()
	}

	zap.L().Debug("Closing SOCKS5 server")

	if s.lis != nil {
		s.lis.Close()
	}

	s.dctxMap.mu.Lock()
	for _, dctx := range s.dctxMap.dctxMap {
		dctx.close()
	}
	s.dctxMap.mu.Unlock()

	zap.L().Debug("SOCKS5 server closed")
	close(s.doneComplete)

	return nil
}

func (s *Server) Run(ctx context.Context) error {
	zap.L().Debug("Starting SOCKS5 server")

	svc := s.svc()
	if svc == nil {
		return errors.Errorf("could not get service from cache")
	}

	var err error
	s.lis, err = net.Listen("tcp", ":"+strconv.Itoa(int(ucorev1.ToService(svc).RealPort())))
	if err != nil {
		return err
	}

	if svc.Spec.IsTLS {
		if err := s.setTLSConfig(ctx); err != nil {
			return err
		}
	}

	ctx, cancelFn := context.WithCancel(ctx)
	s.cancelFn = cancelFn

	go s.serve(ctx)

	zap.L().Debug("SOCKS5 server is now running")
	return nil
}

func (s *Server) serve(ctx context.Context) {
	zap.L().Debug("Starting serving SOCKS5 connections")

	for {
		conn, err := s.lis.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				zap.L().Debug("shutting down SOCKS5 server gracefully via context")
				return
			default:
			}

			if opErr, ok := err.(*net.OpError); ok && !opErr.Temporary() && !opErr.Timeout() {
				zap.L().Debug("SOCKS5 listener closed, stopping accept loop")
				return
			}

			zap.L().Warn("Could not accept SOCKS5 conn", zap.Error(err))
			time.Sleep(100 * time.Millisecond)
			continue
		}

		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	zap.L().Debug("Started handling a new SOCKS5 conn",
		zap.String("addr", c.RemoteAddr().String()))

	svc := s.svc()
	if svc == nil {
		zap.L().Warn("Could not get the Service from cache")
		c.Close()
		return
	}

	if svc.Spec.IsDisabled {
		c.Close()
		return
	}

	if err := setKeepAlive(c); err != nil {
		zap.L().Debug("Could not set keepAlive", zap.Error(err))
	}

	s.tlsCfgMan.mu.RLock()
	if svc.Spec.IsTLS {
		if s.tlsCfgMan.tlsCfg != nil {
			c = tls.Server(c, s.tlsCfgMan.tlsCfg)
			s.tlsCfgMan.mu.RUnlock()
		} else {
			s.tlsCfgMan.mu.RUnlock()
			c.Close()
			return
		}
	} else {
		s.tlsCfgMan.mu.RUnlock()
	}

	connDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-connDone:
		}
	}()

	defer close(connDone)
	defer c.Close()

	if err := c.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		zap.L().Debug("Could not set SOCKS5 handshake deadline", zap.Error(err))
	}

	if err := s.socksSrv.ServeConn(c); err != nil {
		zap.L().Debug("SOCKS5 connection ended", zap.Error(err))
	}
}

func (s *Server) handleConnect(ctx context.Context, writer io.Writer, req *gosocks5.Request) error {
	startTime := time.Now()

	clientConn, ok := writer.(net.Conn)
	if !ok {
		gosocks5.SendReply(writer, statute.RepServerFailure, nil)
		return errors.Errorf("SOCKS5 writer is not net.Conn: %T", writer)
	}

	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		zap.L().Debug("Could not clear SOCKS5 conn deadline", zap.Error(err))
	}

	svc := s.svc()
	if svc == nil {
		gosocks5.SendReply(writer, statute.RepServerFailure, nil)
		return errors.Errorf("could not get service from cache")
	}

	if svc.Spec.IsDisabled {
		gosocks5.SendReply(writer, statute.RepRuleFailure, nil)
		return errors.Errorf("service is disabled")
	}

	target, err := newTarget(req)
	if err != nil {
		gosocks5.SendReply(writer, statute.RepAddrTypeNotSupported, nil)
		return err
	}

	request := s.getDownstreamReq(ctx, clientConn, target)

	authResp, err := s.octovigilC.AuthenticateAndAuthorize(ctx, &octovigilc.AuthenticateAndAuthorizeRequest{
		Request: request,
	})
	if err != nil {
		zap.L().Debug("Could not authenticate/authorize SOCKS5 request", zap.Error(err))
		gosocks5.SendReply(writer, statute.RepServerFailure, nil)
		return err
	}

	if !authResp.IsAuthenticated {
		gosocks5.SendReply(writer, statute.RepRuleFailure, nil)
		return errors.Errorf("SOCKS5 request is not authenticated")
	}

	if !authResp.IsAuthorized {
		s.emitConnectLog(startTime, "", authResp, target, false)
		gosocks5.SendReply(writer, statute.RepRuleFailure, nil)
		return errors.Errorf("SOCKS5 request is not authorized")
	}

	svcConfig := vigilutils.GetServiceConfig(ctx, authResp)

	var upstreamSession *corev1.Session
	if isEmbeddedMode(svcConfig) {
		upstreamSession, err = s.getEmbeddedUpstreamSession(ctx, req)
		if err != nil {
			zap.L().Debug("Could not get embedded SOCKS5 upstream Session", zap.Error(err))
			gosocks5.SendReply(writer, statute.RepRuleFailure, nil)
			return err
		}
	}

	dctx := newDctx(ctx, clientConn, writer, req.Reader, target, authResp, svcConfig, upstreamSession)

	s.dctxMap.mu.Lock()
	s.dctxMap.dctxMap[dctx.id] = dctx
	s.dctxMap.mu.Unlock()

	defer func() {
		dctx.close()

		s.dctxMap.mu.Lock()
		delete(s.dctxMap.dctxMap, dctx.id)
		s.dctxMap.mu.Unlock()
	}()

	s.emitConnectLog(startTime, dctx.id, authResp, target, true)

	s.metricsStore.AtRequestStart()
	err = dctx.serve(ctx, s.lbManager, svc, s.secretMan)
	s.metricsStore.AtRequestEnd(dctx.createdAt, nil)

	s.emitEndLog(startTime, dctx, authResp, target)

	return err
}

func (s *Server) getEmbeddedUpstreamSession(ctx context.Context, req *gosocks5.Request) (*corev1.Session, error) {
	sessionName := getAuthUsername(req)
	if sessionName == "" {
		return nil, errors.Errorf("SOCKS5 embedded mode requires username/password auth with username set to the upstream Session name")
	}

	if err := apivalidation.ValidateName(sessionName, 0, 0); err != nil {
		return nil, err
	}

	sess, err := s.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
		Name: sessionName,
	})
	if err != nil {
		return nil, err
	}

	if !ucorev1.ToSession(sess).IsClientConnectedSOCKS5() {
		return nil, errors.Errorf("upstream Session is not connected or not SOCKS5 embedded")
	}

	return sess, nil
}

func (s *Server) getDownstreamReq(ctx context.Context, c net.Conn, target *target) *coctovigilv1.DownstreamRequest {
	return &coctovigilv1.DownstreamRequest{
		Source: vigilutils.GetDownstreamRequestSource(c),
		Request: &corev1.RequestContext_Request{
			Type: &corev1.RequestContext_Request_Socks5{
				Socks5: &corev1.RequestContext_Request_SOCKS5{
					Type: &corev1.RequestContext_Request_SOCKS5_Connect_{
						Connect: &corev1.RequestContext_Request_SOCKS5_Connect{
							Host:        target.host,
							Port:        uint32(target.port),
							AddressType: target.toRequestAddressType(),
						},
					},
				},
			},
		},
	}
}

func (s *Server) emitConnectLog(
	startTime time.Time,
	connectionID string,
	authResp *coctovigilv1.AuthenticateAndAuthorizeResponse,
	target *target,
	isAuthorized bool,
) {
	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       startTime,
		IsAuthenticated: true,
		IsAuthorized:    isAuthorized,
		ReqCtx:          authResp.RequestContext,
		ConnectionID:    connectionID,
		Reason:          authResp.AuthorizationDecisionReason,
	})

	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Socks5{
		Socks5: &corev1.AccessLog_Entry_Info_SOCKS5{
			Type:        corev1.AccessLog_Entry_Info_SOCKS5_CONNECT,
			Host:        target.host,
			Port:        uint32(target.port),
			AddressType: target.toLogAddressType(),
		},
	}

	otelutils.EmitAccessLog(logE)
}

func (s *Server) emitEndLog(
	startTime time.Time,
	dctx *dctx,
	authResp *coctovigilv1.AuthenticateAndAuthorizeResponse,
	target *target,
) {
	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       startTime,
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          authResp.RequestContext,
		ConnectionID:    dctx.id,
		Reason:          authResp.AuthorizationDecisionReason,
	})

	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Socks5{
		Socks5: &corev1.AccessLog_Entry_Info_SOCKS5{
			Type:          corev1.AccessLog_Entry_Info_SOCKS5_SESSION_END,
			Host:          target.host,
			Port:          uint32(target.port),
			AddressType:   target.toLogAddressType(),
			ReceivedBytes: uint64(dctx.proxy.recvBytes),
			SentBytes:     uint64(dctx.proxy.sentBytes),
			UpstreamHost:  dctx.upstreamHost,
			UpstreamPort:  uint32(dctx.upstreamPort),
		},
	}

	otelutils.EmitAccessLog(logE)
}

func (s *Server) setTLSConfig(ctx context.Context) error {
	crt, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: vutils.ClusterCertSecretName})
	if err != nil && !grpcerr.IsNotFound(err) {
		return err
	}

	s.crtMan.mu.Lock()
	s.crtMan.crt = crt
	s.crtMan.mu.Unlock()

	s.tlsCfgMan.mu.Lock()
	s.tlsCfgMan.tlsCfg = &tls.Config{
		ClientAuth: tls.NoClientCert,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.crtMan.mu.RLock()
			defer s.crtMan.mu.RUnlock()
			if s.crtMan.crt == nil {
				return nil, nil
			}
			return ocrypto.GetTLSCertificate(s.crtMan.crt)
		},
	}
	s.tlsCfgMan.mu.Unlock()

	return nil
}

func rejectUnsupportedCommand(ctx context.Context, writer io.Writer, req *gosocks5.Request) error {
	gosocks5.SendReply(writer, statute.RepCommandNotSupported, nil)
	return errors.Errorf("unsupported SOCKS5 command: %d", req.Command)
}

func setKeepAlive(conn net.Conn) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}
	if err := tcpConn.SetKeepAlive(true); err != nil {
		return err
	}
	if err := tcpConn.SetKeepAlivePeriod(40 * time.Second); err != nil {
		return err
	}
	return nil
}
