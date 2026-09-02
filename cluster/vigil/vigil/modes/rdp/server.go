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

package rdp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
)

type Server struct {
	octovigilC *octovigilc.Client
	vCache     *vcache.Cache

	lis net.Listener

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

func (s *Server) svc() *corev1.Service {
	return s.vCache.GetService()
}

func (s *Server) SetClusterCertificate(crt *corev1.Secret) error {
	s.crtMan.mu.Lock()
	defer s.crtMan.mu.Unlock()
	s.crtMan.crt = crt
	return nil
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

	return server, nil
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

	zap.L().Debug("Closing RDP server")

	if s.lis != nil {
		s.lis.Close()
	}

	s.dctxMap.mu.Lock()
	for _, dctx := range s.dctxMap.dctxMap {
		dctx.close()
	}
	s.dctxMap.mu.Unlock()

	zap.L().Debug("RDP server closed")
	close(s.doneComplete)

	return nil
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	zap.L().Debug("Started handling a new RDP conn", zap.String("addr", c.RemoteAddr().String()))

	startTime := time.Now()
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

	if err := c.SetReadDeadline(time.Now().Add(x224HandshakeTimeout)); err != nil {
		c.Close()
		return
	}

	clientX224, err := ReadTPKT(c)
	if err != nil {
		zap.L().Debug("Could not read RDP X.224 connection request", zap.Error(err))
		s.metricsStore.AddConnRejected("HANDSHAKE")
		c.Close()
		return
	}

	if err := ValidateConnectionRequest(clientX224); err != nil {
		zap.L().Debug("Invalid RDP X.224 connection request", zap.Error(err))
		s.metricsStore.AddConnRejected("HANDSHAKE")
		c.Close()
		return
	}

	if err := c.SetReadDeadline(time.Time{}); err != nil {
		c.Close()
		return
	}

	authResp, err := s.octovigilC.AuthenticateAndAuthorize(ctx, &octovigilc.AuthenticateAndAuthorizeRequest{
		Request: s.getDownstreamReq(ctx, c),
	})
	if err != nil {
		zap.L().Debug("Could not auth RDP conn", zap.Error(err))
		s.metricsStore.AtRequestStart()
		s.metricsStore.AtRequestEnd(startTime, metric.WithAttributes(attribute.String("state", "DENIED")))
		c.Close()
		return
	}

	if !authResp.IsAuthenticated {
		s.metricsStore.AtRequestStart()
		s.metricsStore.AtRequestEnd(startTime, metric.WithAttributes(attribute.String("state", "DENIED")))
		c.Close()
		return
	}

	if !authResp.IsAuthorized {
		logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
			StartTime:       startTime,
			IsAuthenticated: true,
			ReqCtx:          authResp.RequestContext,
			Reason:          authResp.AuthorizationDecisionReason,
		})
		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Tcp{
			Tcp: &corev1.AccessLog_Entry_Info_TCP{
				Type: corev1.AccessLog_Entry_Info_TCP_START,
			},
		}
		otelutils.EmitAccessLog(logE)
		s.metricsStore.AtRequestStart()
		s.metricsStore.AtRequestEnd(startTime, metric.WithAttributeSet(attribute.NewSet(
			attribute.String("state", "DENIED"),
			attribute.String("reason", authResp.AuthorizationDecisionReason.GetType().String()),
		)))
		c.Close()
		return
	}

	i := authResp.RequestContext
	dctx := newDctx(ctx, c, i, authResp, clientX224)

	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       startTime,
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          i,
		ConnectionID:    dctx.id,
		Reason:          authResp.AuthorizationDecisionReason,
	})
	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Tcp{
		Tcp: &corev1.AccessLog_Entry_Info_TCP{
			Type: corev1.AccessLog_Entry_Info_TCP_START,
		},
	}
	otelutils.EmitAccessLog(logE)

	s.dctxMap.mu.Lock()
	s.dctxMap.dctxMap[dctx.id] = dctx
	s.dctxMap.mu.Unlock()

	s.metricsStore.AtRequestStart()
	s.metricsStore.AtSessionStart()

	func() {
		defer func() {
			attrs := metric.WithAttributes(attribute.String("state", "ALLOWED"))
			s.metricsStore.AtRequestEnd(dctx.createdAt, attrs)
			s.metricsStore.AtSessionEnd(dctx.createdAt, attrs)
			s.metricsStore.AddBytesTransferred(
				dctx.proxy.bytesToDownstream, dctx.proxy.bytesFromDownstream, attrs)

			if dctx.proxy.upstreamErr != nil {
				s.metricsStore.AddConnRejected(dctx.proxy.rejectReason)
			}
		}()

		dctx.serve(ctx, s.lbManager, s.secretMan, s.tlsConfig())
	}()

	dctx.close()

	s.dctxMap.mu.Lock()
	delete(s.dctxMap.dctxMap, dctx.id)
	s.dctxMap.mu.Unlock()

	logEnd := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       startTime,
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          i,
		ConnectionID:    dctx.id,
	})
	logEnd.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Tcp{
		Tcp: &corev1.AccessLog_Entry_Info_TCP{
			Type:          corev1.AccessLog_Entry_Info_TCP_END,
			ReceivedBytes: uint64(dctx.proxy.bytesFromDownstream),
			SentBytes:     uint64(dctx.proxy.bytesToDownstream),
		},
	}
	otelutils.EmitAccessLog(logEnd)
}

func (s *Server) getDownstreamReq(ctx context.Context, c net.Conn) *coctovigilv1.DownstreamRequest {
	return &coctovigilv1.DownstreamRequest{
		Source: vigilutils.GetDownstreamRequestSource(c),
	}
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
			return ocrypto.GetTLSCertificate(s.crtMan.crt)
		},
	}
	s.tlsCfgMan.mu.Unlock()

	return nil
}

func (s *Server) tlsConfig() *tls.Config {
	s.tlsCfgMan.mu.RLock()
	defer s.tlsCfgMan.mu.RUnlock()
	return s.tlsCfgMan.tlsCfg
}

func (s *Server) Run(ctx context.Context) error {
	zap.L().Debug("Starting running RDP server")

	if err := s.setTLSConfig(ctx); err != nil {
		return err
	}

	var err error
	s.lis, err = net.Listen("tcp", fmt.Sprintf(":%d", ucorev1.ToService(s.svc()).RealPort()))
	if err != nil {
		return err
	}

	ctx, cancelFn := context.WithCancel(ctx)
	s.cancelFn = cancelFn

	go s.serve(ctx)

	zap.L().Debug("RDP server is now running")
	return nil
}

func (s *Server) serve(ctx context.Context) {
	zap.L().Debug("Starting serving RDP connections")

	for {
		conn, err := s.lis.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				zap.L().Debug("shutting down RDP server gracefully via context")
				return
			default:
			}

			if opErr, ok := err.(*net.OpError); ok && !opErr.Temporary() && !opErr.Timeout() {
				zap.L().Debug("RDP listener closed, stopping accept loop")
				return
			}

			zap.L().Warn("Could not accept RDP conn", zap.Error(err))
			time.Sleep(100 * time.Millisecond)
			continue
		}

		go s.handleConn(ctx, conn)
	}
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
