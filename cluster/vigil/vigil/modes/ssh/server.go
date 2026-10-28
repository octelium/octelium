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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"sync"

	"context"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/apivalidation"
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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type Server struct {
	ConnectionTimeout time.Duration

	cancelFn context.CancelFunc

	sshConfig         *ssh.ServerConfig
	sshConfigWildcard *ssh.ServerConfig

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
	sshMetrics *metricutils.SSHMetrics
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
	wildcardConfig := *server.sshConfig
	server.sshConfigWildcard = &wildcardConfig

	var err error
	svc := opts.VCache.GetService()

	{
		signerHost, err := sshutils.GenerateServiceEd25519HostSigner(ctx, octeliumC, svc)
		if err != nil {
			signerHost, err = sshutils.GenerateSigner()
			if err != nil {
				return nil, err
			}
		}

		hostSigner, err := sshutils.GenerateHostSigner(ctx, octeliumC, signerHost)
		if err != nil {
			return nil, err
		}

		server.sshConfig.AddHostKey(hostSigner)

		hostSignerWildcard, err := sshutils.GenerateHostSignerWithPrincipals(ctx, octeliumC, signerHost, "*")
		if err != nil {
			return nil, err
		}
		server.sshConfigWildcard.AddHostKey(hostSignerWildcard)
	}

	{
		signerUser, err := sshutils.GenerateServiceEd25519UserSigner(ctx, octeliumC, svc)
		if err != nil {
			signerUser, err = sshutils.GenerateSigner()
			if err != nil {
				return nil, err
			}
		}

		server.userSigner, err = sshutils.GenerateUserSigner(ctx, octeliumC, signerUser)
		if err != nil {
			return nil, err
		}
	}

	server.metricsStore.CommonMetrics, err = metricutils.NewCommonMetrics(ctx, svc)
	if err != nil {
		return nil, err
	}

	server.metricsStore.sshMetrics, err = metricutils.NewSSHMetrics(ctx, svc)
	if err != nil {
		return nil, err
	}

	return server, nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return nil
	}
	s.isClosed = true

	cancelFn := s.cancelFn
	lis := s.lis

	var dctxs []*dctx
	s.dctxMap.mu.Lock()
	for _, d := range s.dctxMap.dctxMap {
		dctxs = append(dctxs, d)
	}
	s.dctxMap.mu.Unlock()

	s.mu.Unlock()

	if cancelFn != nil {
		cancelFn()
	}

	for _, d := range dctxs {
		d.close()
	}

	if lis != nil {
		lis.Close()
	}

	zap.L().Debug("SSH server is now closed")

	return nil
}

func (s *Server) newServerConn(c net.Conn) (*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	version := []byte(s.sshConfig.ServerVersion + "\r\n")
	if n, err := c.Write(version); err != nil {
		return nil, nil, nil, err
	} else if n != len(version) {
		return nil, nil, nil, io.ErrShortWrite
	}

	reader := bufio.NewReaderSize(c, 256)
	var clientVersion []byte
	for range 1024 {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, nil, nil, err
		}
		if len(line) > 255 {
			return nil, nil, nil, fmt.Errorf("SSH client version is too long")
		}
		if bytes.HasPrefix(line, []byte("SSH-")) {
			clientVersion = append([]byte(nil), line...)
			break
		}
	}
	if len(clientVersion) == 0 {
		return nil, nil, nil, fmt.Errorf("Too many lines before SSH client version")
	}

	config := s.sshConfig
	if supportsWildcardHostPrincipals(string(clientVersion)) {
		config = s.sshConfigWildcard
	}

	return ssh.NewServerConn(&sshVersionConn{
		Conn:    c,
		reader:  io.MultiReader(bytes.NewReader(clientVersion), reader),
		version: version,
	}, config)
}

func supportsWildcardHostPrincipals(version string) bool {
	const prefix = "SSH-2.0-OpenSSH_"
	if !strings.HasPrefix(version, prefix) {
		return false
	}

	var major, minor int
	version = strings.TrimPrefix(strings.TrimPrefix(version, prefix), "for_Windows_")
	if _, err := fmt.Sscanf(version, "%d.%d", &major, &minor); err != nil {
		return false
	}
	return major > 10 || (major == 10 && minor >= 3)
}

type sshVersionConn struct {
	net.Conn
	reader  io.Reader
	version []byte
}

func (c *sshVersionConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *sshVersionConn) Write(p []byte) (int, error) {
	n := min(len(p), len(c.version))
	if !bytes.Equal(p[:n], c.version[:n]) {
		return 0, fmt.Errorf("Unexpected SSH server version")
	}
	c.version = c.version[n:]
	if n == len(p) {
		return n, nil
	}
	written, err := c.Conn.Write(p[n:])
	return n + written, err
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) {
	defer modes.Recover()
	defer c.Close()

	startTime := time.Now()

	svc := s.vCache.GetService()
	if svc == nil {
		c.Close()
		return
	}

	if svc.Spec.IsDisabled {
		c.Close()
		return
	}

	ctx, cancelFn := context.WithCancel(ctx)
	defer cancelFn()

	zap.L().Debug("Started handling a new conn", zap.String("remoteAddr", c.RemoteAddr().String()))

	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	sshConn, chans, reqs, err := s.newServerConn(c)
	_ = c.SetDeadline(time.Time{})
	if err != nil {
		zap.L().Debug("Could not establish a newServerConn")
		s.metricsStore.AddConnRejected("HANDSHAKE")
		c.Close()
		return
	}

	request := s.getDownstreamReq(ctx, c, sshConn)

	authResp, err := s.octovigilC.AuthenticateAndAuthorize(ctx, &octovigilc.AuthenticateAndAuthorizeRequest{
		Request: request,
	})
	if err != nil {
		zap.L().Debug("Could not auth conn. Closing...", zap.Error(err))
		s.metricsStore.AtRequestStart()
		s.metricsStore.AtRequestEnd(startTime, metric.WithAttributes(attribute.String("state", "DENIED")))
		sshConn.Close()
		c.Close()
		return
	}

	if !authResp.IsAuthenticated {
		s.metricsStore.AtRequestStart()
		s.metricsStore.AtRequestEnd(startTime, metric.WithAttributes(attribute.String("state", "DENIED")))
		sshConn.Close()
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
		logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Ssh{
			Ssh: &corev1.AccessLog_Entry_Info_SSH{
				Type: corev1.AccessLog_Entry_Info_SSH_SESSION_START,
			},
		}
		otelutils.EmitAccessLog(logE)
		s.metricsStore.AtRequestStart()
		s.metricsStore.AtRequestEnd(startTime, metric.WithAttributeSet(attribute.NewSet(
			attribute.String("state", "DENIED"),
			attribute.String("reason", authResp.AuthorizationDecisionReason.GetType().String()),
		)))
		sshConn.Close()
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
				ReqCtx:          i,
				Reason:          authResp.AuthorizationDecisionReason,
			})
			otelutils.EmitAccessLog(logE)
			s.metricsStore.AtRequestStart()
			s.metricsStore.AtRequestEnd(startTime, metric.WithAttributeSet(attribute.NewSet(
				attribute.String("state", "DENIED"),
				attribute.String("reason", authResp.AuthorizationDecisionReason.GetType().String()),
			)))
			return
		}
	}

	if ucorev1.ToService(svc).IsESSH() {

		sshUser := sshConn.User()
		if err := apivalidation.ValidateName(sshUser, 0, 0); err != nil {
			sshConn.Close()
			c.Close()
			return
		}

		upstreamSession, err = s.octeliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Name: sshUser,
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
		s.metricsStore.CommonMetrics, s.metricsStore.sshMetrics,
		authResp, authResp.AuthorizationDecisionReason)
	if err := dctx.connect(ctx, s.octeliumC, svc, s.lbManager, s.userSigner, s.secretMan); err != nil {
		zap.L().Warn("Could not connect to upstream", zap.Error(err))
		s.metricsStore.AddConnRejected("UPSTREAM_DIAL")
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
	s.metricsStore.AtSessionStart()

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

	defer s.metricsStore.AtRequestEnd(dctx.createdAt,
		metric.WithAttributes(attribute.String("state", "ALLOWED")))
	defer s.metricsStore.AtSessionEnd(dctx.createdAt,
		metric.WithAttributes(attribute.Bool("req.ssh.is_essh",
			ucorev1.ToService(svc).IsESSH())))

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
