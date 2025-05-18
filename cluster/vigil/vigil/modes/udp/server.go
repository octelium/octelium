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

package udp

import (
	"context"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/controllers"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

var (
	udpConnTrackTimeout = 30 * time.Second
	udpBufSize          = 1500
)

type Server struct {
	octovigilC *octovigilc.Client
	vCache     *vcache.Cache
	mu         sync.RWMutex

	lis *net.UDPConn

	octeliumC octeliumc.ClientInterface

	cancelFn context.CancelFunc

	isClosed bool

	svcCtl     *controllers.ServiceController
	sessionCtl *controllers.SessionController
	lbManager  *loadbalancer.LBManager

	// logManager *logmanager.LogManager
	secretMan *secretman.SecretManager

	Listener *net.UDPConn

	dctxMap struct {
		mu      sync.Mutex
		dctxMap map[string]*dctx
	}
	svcRef *metav1.ObjectReference

	metricsStore *metricsStore
}

type metricsStore struct {
	*metricutils.CommonMetrics
}

func New(ctx context.Context, opts *modes.Opts) (*Server, error) {
	ret := &Server{
		octovigilC:   opts.OctovigilC,
		vCache:       opts.VCache,
		octeliumC:    opts.OcteliumC,
		lbManager:    opts.LBManager,
		svcCtl:       &controllers.ServiceController{},
		sessionCtl:   &controllers.SessionController{},
		secretMan:    opts.SecretMan,
		metricsStore: &metricsStore{},
	}

	var err error
	ret.metricsStore.CommonMetrics, err = metricutils.NewCommonMetrics(ctx, opts.VCache.GetService())
	if err != nil {
		return nil, err
	}

	ret.dctxMap.dctxMap = make(map[string]*dctx)

	return ret, nil
}

func (s *Server) SetClusterCertificate(crt *corev1.Secret) error {

	return nil
}

func (s *Server) Run(ctx context.Context) error {
	zap.L().Debug("Starting running UDP server")

	svc := s.vCache.GetService()
	if svc == nil {
		return errors.Errorf("Nil svc")
	}
	s.svcRef = umetav1.GetObjectReference(svc)

	var err error

	addr := &net.UDPAddr{
		IP:   net.ParseIP("::"),
		Port: ucorev1.ToService(svc).RealPort(),
	}

	zap.S().Debugf("Listening to addr: %s", addr.String())

	s.lis, err = net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	ctx, cancelFn := context.WithCancel(ctx)
	s.cancelFn = cancelFn

	go s.doRun(ctx)

	zap.L().Debug("UDP server is now running")

	return nil
}

func (s *Server) closeDctx(dctx *dctx) {

	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       dctx.createdAt,
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          dctx.i,
		ConnectionID:    dctx.id,
	})

	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Udp{
		Udp: &corev1.AccessLog_Entry_Info_UDP{
			Type: corev1.AccessLog_Entry_Info_UDP_END,
		},
	}
	otelutils.EmitAccessLog(logE)

	s.dctxMap.mu.Lock()
	defer s.dctxMap.mu.Unlock()
	dctx.close()
	delete(s.dctxMap.dctxMap, dctx.addr.String())
}

func (s *Server) replyLoop(dctx *dctx) {
	s.metricsStore.AtRequestStart()
	defer s.closeDctx(dctx)
	defer s.metricsStore.AtRequestEnd(dctx.createdAt, nil)

	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       dctx.createdAt,
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          dctx.i,
		ConnectionID:    dctx.id,
	})
	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Udp{
		Udp: &corev1.AccessLog_Entry_Info_UDP{
			Type: corev1.AccessLog_Entry_Info_UDP_START,
		},
	}
	otelutils.EmitAccessLog(logE)

	readBuf := make([]byte, udpBufSize)
	for {
		dctx.connUpstream.SetReadDeadline(time.Now().Add(udpConnTrackTimeout))
	again:
		read, err := dctx.connUpstream.Read(readBuf)
		if err != nil {
			if err, ok := err.(*net.OpError); ok && err.Err == syscall.ECONNREFUSED {
				goto again
			}
			return
		}
		for i := 0; i != read; {
			written, err := s.lis.WriteToUDP(readBuf[i:read], dctx.addr)
			if err != nil {
				return
			}
			i += written
		}
	}
}

func (s *Server) doRun(ctx context.Context) {
	zap.S().Debugf("Starting running the run loop")
	for {
		select {
		case <-ctx.Done():
			return
		default:
			readBuf := make([]byte, udpBufSize)
			n, addr, err := s.lis.ReadFromUDP(readBuf)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if err := s.handlePacket(ctx, readBuf, n, addr); err != nil {
				zap.S().Debugf("Could not handle packet: %+v", err)
			}
		}

	}
}

func (s *Server) handlePacket(ctx context.Context, buf []byte, n int, addr *net.UDPAddr) error {

	svc := s.vCache.GetService()
	if svc == nil {
		zap.L().Warn("Could not get the Service from cache")
		return errors.Errorf("Cannot find svc in cache")
	}

	req := &coctovigilv1.DownstreamRequest{
		Source: &coctovigilv1.DownstreamRequest_Source{
			Address: addr.IP.String(),
			Port:    int32(addr.Port),
		},
	}

	zap.S().Debugf("Authenticating downstream req: %+v", req)

	authResp, err := s.octovigilC.AuthenticateAndAuthorize(ctx, &octovigilc.AuthenticateAndAuthorizeRequest{
		Request: req,
	})
	if err != nil {
		return err
	}

	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       time.Now(),
		IsAuthenticated: authResp.IsAuthenticated,
		IsAuthorized:    authResp.IsAuthorized,
		ReqCtx:          authResp.RequestContext,
		Reason:          authResp.AuthorizationDecisionReason,
	})
	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Udp{
		Udp: &corev1.AccessLog_Entry_Info_UDP{
			Type: corev1.AccessLog_Entry_Info_UDP_START,
		},
	}

	otelutils.EmitAccessLog(logE)
	if !authResp.IsAuthorized {
		return nil
	}

	i := authResp.RequestContext
	var isNewlyCreated bool

	s.dctxMap.mu.Lock()

	dctx, ok := s.dctxMap.dctxMap[addr.String()]
	if !ok {
		dctx = newDctx(addr, authResp.RequestContext)
		s.dctxMap.dctxMap[addr.String()] = dctx
		isNewlyCreated = true
	} else {
		if dctx.sessUID != i.Session.Metadata.Uid {
			s.dctxMap.mu.Unlock()
			return errors.Errorf("stored dctx and Session UID do not match")
		}
	}
	s.dctxMap.mu.Unlock()

	if isNewlyCreated {
		dctx.connUpstream, err = s.getUpstreamConn(ctx, authResp)
		if err != nil {
			s.closeDctx(dctx)
			return err
		}

		go s.replyLoop(dctx)
		zap.S().Debugf("Successfully built new dctx for: %s", dctx.addr.String())
	} else {
		zap.S().Debugf("Got stored dctx for: %s", dctx.addr.String())
	}

	for i := 0; i != n; {
		written, err := dctx.connUpstream.Write(buf[i:n])
		if err != nil {
			break
		}
		i += written
	}

	return nil
}

func (s *Server) getUpstreamConn(ctx context.Context, authResp *coctovigilv1.AuthenticateAndAuthorizeResponse) (*net.UDPConn, error) {
	upstream, err := s.lbManager.GetUpstream(ctx, authResp)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", upstream.HostPort)
	if err != nil {
		return nil, err
	}

	return net.DialUDP("udp", nil, addr)
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return nil
	}
	zap.L().Debug("Starting closing UDP server")
	s.isClosed = true
	s.cancelFn()

	s.lis.Close()

	s.dctxMap.mu.Lock()
	defer s.dctxMap.mu.Unlock()
	for _, dctx := range s.dctxMap.dctxMap {
		dctx.close()
	}

	s.dctxMap.dctxMap = make(map[string]*dctx)

	zap.L().Debug("UDP server is now closed")
	return nil
}
