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

package ssh

import (
	"fmt"
	"net"
	"time"

	"sync"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/controllers"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/cluster/vigil/vigil/vigilutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

type Server struct {
	ConnectionTimeout time.Duration

	cancelFn context.CancelFunc

	sshConfig *ssh.ServerConfig

	lbManager *loadbalancer.LBManager

	octovigilC *octovigilc.Client
	vCache     *vcache.Cache

	lis net.Listener

	octeliumC octeliumc.ClientInterface

	secretMan *secretman.SecretManager

	dctxMap struct {
		mu      sync.Mutex
		dctxMap map[string]*dctx
	}

	mu         sync.Mutex
	isClosed   bool
	svcCtl     *controllers.ServiceController
	sessionCtl *controllers.SessionController

	userSigner ssh.Signer

	opts         *modes.Opts
	metricsStore *metricsStore
}

type metricsStore struct {
	*metricutils.CommonMetrics
}

func (s *Server) SetClusterCertificate(crt *corev1.Secret) error {
	return nil
}

func New(ctx context.Context, opts *modes.Opts) (*Server, error) {
	server := &Server{
		octovigilC:   opts.OctovigilC,
		vCache:       opts.VCache,
		octeliumC:    opts.OcteliumC,
		svcCtl:       &controllers.ServiceController{},
		sessionCtl:   &controllers.SessionController{},
		lbManager:    opts.LBManager,
		secretMan:    opts.SecretMan,
		opts:         opts,
		metricsStore: &metricsStore{},
	}

	octeliumC := opts.OcteliumC

	server.dctxMap.dctxMap = make(map[string]*dctx)

	server.sshConfig = &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-2.0-Octelium",
	}

	signer, err := sshutils.GenerateSigner()
	if err != nil {
		return nil, err
	}

	hostSigner, err := sshutils.GenerateHostSigner(ctx, octeliumC, signer)
	if err != nil {
		return nil, err
	}

	server.sshConfig.AddHostKey(hostSigner)

	server.userSigner, err = sshutils.GenerateUserSigner(ctx, octeliumC, signer)
	if err != nil {
		return nil, err
	}

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
	zap.L().Debug("Starting closing the SSH server")
	s.cancelFn()

	zap.L().Debug("Closing active dctxs")
	s.dctxMap.mu.Lock()
	for _, dctx := range s.dctxMap.dctxMap {
		dctx.close()
	}
	s.dctxMap.mu.Unlock()
	zap.L().Debug("Closing the SSH server listener")
	if s.lis != nil {
		s.lis.Close()
		s.lis = nil
	}

	zap.L().Debug("SSH server is now closed")

	return nil
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	startTime := time.Now()

	svc := s.vCache.GetService()

	ctx, cancelFn := context.WithCancel(ctx)
	defer cancelFn()

	zap.L().Debug("Started handling a new conn", zap.String("remoteAddr", c.RemoteAddr().String()))

	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		zap.L().Debug("Could not establish a newServerConn")
		c.Close()
		return
	}

	request := s.getDownstreamReq(ctx, c, sshConn)

	authResp, err := s.octovigilC.AuthenticateAndAuthorize(ctx, &octovigilc.AuthenticateAndAuthorizeRequest{
		Request: request,
	})
	if err != nil {
		zap.L().Debug("Could not auth conn. Closing...", zap.Error(err))
		c.Close()
		return
	}

	if authResp.IsAuthenticated && !authResp.IsAuthorized {
		logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
			StartTime:       startTime,
			IsAuthenticated: true,
			ReqCtx:          authResp.RequestContext,
			Reason:          authResp.AuthorizationDecisionReason,
		})
		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Ssh{
			Ssh: &corev1.AccessLog_Entry_Info_SSH{
				Type: corev1.AccessLog_Entry_Info_SSH_SESSION_START,
			},
		}
		otelutils.EmitAccessLog(logE)
		c.Close()
		return
	}

	i := authResp.RequestContext

	var upstreamSession *corev1.Session

	if s.opts.PostAuthorize != nil {
		res, err := s.opts.PostAuthorize(ctx, &modes.PostAuthorizeRequest{
			Request: request,
			Resp:    authResp,
		})
		if err != nil {
			zap.L().Debug("could not postAuthorize", zap.Error(err))
			sshConn.Close()
			c.Close()
			return
		}

		zap.L().Debug("postAuthorize successfully done", zap.Any("res", res))

		if !res.IsAuthorized {
			sshConn.Close()
			c.Close()
			logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
				StartTime:       startTime,
				IsAuthenticated: true,
				IsAuthorized:    true,
				ReqCtx:          i,
				Reason:          authResp.AuthorizationDecisionReason,
			})
			otelutils.EmitAccessLog(logE)
			return
		}
	}

	if ucorev1.ToService(svc).IsESSH() {
		upstreamSession, err = s.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Name: sshConn.User(),
		})
		if err != nil {
			zap.L().Debug("Could not find eSSH Session from ssh user", zap.Error(err))

			sshConn.Close()
			c.Close()
			return
		}

		if !ucorev1.ToSession(upstreamSession).IsClientConnectedESSH() {
			zap.L().Debug("Upstream Session is not connected or not eSSH")

			sshConn.Close()
			c.Close()
			return
		}
	}

	dctx := newDctx(ctx,
		svc,
		s.opts,
		c, sshConn, i,
		upstreamSession,
		authResp, authResp.AuthorizationDecisionReason)
	if err := dctx.connect(ctx, s.octeliumC, svc, s.lbManager, s.userSigner, s.secretMan); err != nil {
		zap.L().Warn("Could not connect to upstream", zap.Error(err))
		sshConn.Close()
		c.Close()
		return
	}

	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       startTime,
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          i,
		ConnectionID:    dctx.id,
		Reason:          authResp.AuthorizationDecisionReason,
	})
	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Ssh{
		Ssh: &corev1.AccessLog_Entry_Info_SSH{
			Type: corev1.AccessLog_Entry_Info_SSH_START,
			Details: &corev1.AccessLog_Entry_Info_SSH_Start_{
				Start: &corev1.AccessLog_Entry_Info_SSH_Start{
					User:          dctx.getEffectiveSSHUser(),
					RequestedUser: sshConn.User(),
				},
			},
		},
	}
	otelutils.EmitAccessLog(logE)

	defer dctx.close()

	s.dctxMap.mu.Lock()
	s.dctxMap.dctxMap[dctx.id] = dctx
	s.dctxMap.mu.Unlock()

	s.metricsStore.AtRequestStart()

	defer func() {
		logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
			StartTime:       startTime,
			IsAuthenticated: true,
			IsAuthorized:    true,
			ReqCtx:          i,
			ConnectionID:    dctx.id,
			Reason:          authResp.AuthorizationDecisionReason,
		})

		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Ssh{
			Ssh: &corev1.AccessLog_Entry_Info_SSH{
				Type: corev1.AccessLog_Entry_Info_SSH_END,
			},
		}
		otelutils.EmitAccessLog(logE)

		s.dctxMap.mu.Lock()
		delete(s.dctxMap.dctxMap, dctx.id)
		s.dctxMap.mu.Unlock()
	}()

	defer s.metricsStore.AtRequestEnd(dctx.createdAt, nil)

	go dctx.startKeepAliveUpstreamLoop(ctx)

	for {
		select {
		case <-dctx.keepAliveCh:
			zap.L().Debug("Keepalive ch triggered. Exiting handleConn")
			return
		case <-ctx.Done():
			zap.L().Debug("ctx done. Exiting handleConn")
			return
		case req := <-reqs:
			if req == nil {
				zap.L().Debug("Nil req. Exiting handleConn")
				return
			}
			go dctx.handleGlobalReq(req)
		case nch := <-chans:
			if nch == nil {
				zap.L().Debug("Nil nch. Exiting handleConn")
				return
			}
			go dctx.handleNewChannel(ctx, nch)
		}
	}
}

func (s *Server) getDownstreamReq(ctx context.Context, c net.Conn, sshConn *ssh.ServerConn) *coctovigilv1.DownstreamRequest {

	return &coctovigilv1.DownstreamRequest{
		Source: vigilutils.GetDownstreamRequestSource(c),
		Request: &corev1.RequestContext_Request{
			Type: &corev1.RequestContext_Request_Ssh{
				Ssh: &corev1.RequestContext_Request_SSH{
					Type: &corev1.RequestContext_Request_SSH_Connect_{
						Connect: &corev1.RequestContext_Request_SSH_Connect{
							User: sshConn.User(),
						},
					},
				},
			},
		},
	}
}

/*
func (s *Server) authConn(ctx context.Context, c net.Conn, sshConn *ssh.ServerConn, svc *corev1.Service) (*corev1.RequestContext, bool, error) {

	if svc == nil {
		zap.S().Warnf("Could not get the Service from cache")
		return nil, false, errors.Errorf("Cannot find svc in cache")
	}

	req := &pbmeta.DownstreamRequest{
		Source: &pbmeta.DownstreamRequest_Source{
			Address: func() string {
				switch addr := c.RemoteAddr().(type) {
				case *net.UDPAddr:
					return addr.IP.String()
				case *net.TCPAddr:
					return addr.IP.String()
				default:
					return ""
				}
			}(),
			Port: func() int32 {
				switch addr := c.RemoteAddr().(type) {
				case *net.UDPAddr:
					return int32(addr.Port)
				case *net.TCPAddr:
					return int32(addr.Port)
				default:
					return 0
				}
			}(),
		},
		Type: &pbmeta.DownstreamRequest_Ssh{
			Ssh: &pbmeta.DownstreamRequest_SSH{
				User: sshConn.User(),
			},
		},
	}

	zap.S().Debugf("Authenticating downstream req: %+v", req)

	i, err := s.vigil.Authenticate(ctx, svc, req)
	if err != nil {
		zap.S().Debugf("Could not authenticate downstream: %+v", err)
		return nil, false, err
	}

	zap.S().Debugf("Authorizing downstream: %+v", i)

	isAuthorized, err := s.vigil.IsAuthorized(ctx, i)
	if err != nil {
		zap.S().Debugf("Could not authorize downstream: %+v", err)
		return nil, true, err
	}

	if !isAuthorized {
		zap.S().Debugf("Downstream is not authorized: %+v", i)
		return nil, true, errors.Errorf("Unauthorized User")
	}

	return i, true, nil
}
*/

func (s *Server) Run(ctx context.Context) error {
	var err error
	zap.L().Debug("Starting running SSH server")
	s.lis, err = net.Listen("tcp", fmt.Sprintf(":%d", ucorev1.ToService(s.vCache.GetService()).RealPort()))
	if err != nil {
		return err
	}

	ctx, cancelFn := context.WithCancel(ctx)
	s.cancelFn = cancelFn

	go s.serve(ctx)

	zap.L().Debug("SSH server is now running")

	return nil
}

func (s *Server) serve(ctx context.Context) {
	zap.L().Debug("Starting serving connections")

	for {
		conn, err := s.lis.Accept()
		if err != nil {
			zap.L().Debug("Could not accept conn", zap.Error(err))
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				zap.L().Debug("Timeout err")
				time.Sleep(100 * time.Millisecond)
				continue
			}

			select {
			case <-ctx.Done():
				zap.L().Debug("shutting down server")
				return
			default:
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		go s.handleConn(ctx, conn)
	}
}
