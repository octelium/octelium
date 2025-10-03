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

package vigil

import (
	"context"
	"os"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/commoninit"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/pprofsrv"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/cluster/vigil/vigil/controllers"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	secretcontroller "github.com/octelium/octelium/cluster/vigil/vigil/controllers/secrets"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/dns"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/mysql"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/postgres"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/ssh"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/tcp"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/udp"
)

type Server struct {
	opts       *Opts
	octeliumC  octeliumc.ClientInterface
	octovigilC *octovigilc.Client
	svcUID     string

	server modes.Server

	svcCtl *controllers.ServiceController

	secretMan *secretman.SecretManager
	// logManager   *logmanager.LogManager
	lbManager *loadbalancer.LBManager
	// metricsStore *metricsstore.MetricsStore

	vCache *vcache.Cache
}

type Opts struct {
	OcteliumC  octeliumc.ClientInterface
	Service    *corev1.Service
	OctovigilC *octovigilc.Client

	PostAuthorize func(ctx context.Context, req *modes.PostAuthorizeRequest) (*modes.PostAuthorizeResponse, error)
	GetUpstream   func(ctx context.Context, opts *modes.Opts, reqCtx *corev1.RequestContext) (*loadbalancer.Upstream, error)
}

func NewServer(ctx context.Context, opts *Opts) (*Server, error) {
	var err error
	octeliumC := opts.OcteliumC
	ret := &Server{
		opts:      opts,
		octeliumC: octeliumC,
		svcUID:    opts.Service.Metadata.Uid,
		svcCtl:    &controllers.ServiceController{},
	}

	ret.vCache, err = vcache.NewCache(ctx)
	if err != nil {
		return nil, err
	}

	svc := opts.Service

	ret.vCache.SetService(svc)

	ret.octovigilC, err = octovigilc.NewClient(ctx, &octovigilc.Opts{
		OcteliumC: octeliumC,
		VCache:    ret.vCache,
	})
	if err != nil {
		return nil, err
	}

	zap.L().Debug("Creating a Vigil Server", zap.Any("svc", svc))

	ret.secretMan, err = secretman.New(ctx, octeliumC, ret.vCache)
	if err != nil {
		return nil, err
	}

	ret.lbManager = loadbalancer.NewLbManager(octeliumC, ret.vCache)

	ret.svcCtl.FnOnUpdate = func(ctx context.Context, new, old *corev1.Service) error {

		if new.Metadata.Uid != ret.svcUID {
			return nil
		}

		zap.L().Debug("Starting onServiceUpdate",
			zap.Any("svc", new))

		ret.vCache.SetService(new)

		if err := ret.secretMan.ApplyService(ctx); err != nil {
			zap.L().Warn("Could not applyService for secretMan", zap.Error(err))
		}

		if (new.Spec.Mode != old.Spec.Mode) ||
			(ucorev1.ToService(new).RealPort() != ucorev1.ToService(old).RealPort()) {
			zap.L().Info("Mode or Port changed. Reloading Service...")
			ret.server.Close()
			zap.L().Debug("Server is now closed")
			if err := ret.createServer(ctx); err != nil {
				return err
			}
			zap.L().Debug("Server recreated")
			return ret.server.Run(ctx)
		} else {

			return nil

		}

	}

	if err := ret.createServer(ctx); err != nil {
		return nil, err
	}

	return ret, nil
}

func (s *Server) createServer(ctx context.Context) error {
	mode := ucorev1.ToService(s.vCache.GetService()).GetMode()

	var err error

	opts := &modes.Opts{
		OcteliumC: s.octeliumC,
		// LogManager:    s.logManager,
		LBManager:  s.lbManager,
		SecretMan:  s.secretMan,
		VCache:     s.vCache,
		OctovigilC: s.octovigilC,
		// MetricsStore:  s.metricsStore,
		GetUpstream:   s.opts.GetUpstream,
		PostAuthorize: s.opts.PostAuthorize,
	}

	switch mode {
	case corev1.Service_Spec_SSH:
		zap.L().Debug("Starting in SSH mode")
		s.server, err = ssh.New(ctx, opts)
	case corev1.Service_Spec_UDP:
		zap.L().Debug("Starting in UDP mode")
		s.server, err = udp.New(ctx, opts)
	case corev1.Service_Spec_TCP, corev1.Service_Spec_MODE_UNSET:
		zap.L().Debug("Starting in TCP mode")
		s.server, err = tcp.New(ctx, opts)
	case corev1.Service_Spec_DNS:
		zap.L().Debug("Starting in DNS mode")
		s.server, err = dns.New(ctx, opts)
	case corev1.Service_Spec_HTTP,
		corev1.Service_Spec_KUBERNETES,
		corev1.Service_Spec_GRPC,
		corev1.Service_Spec_WEB:
		zap.L().Debug("Starting in HTTP mode", zap.String("mode", mode.String()))
		s.server, err = httpg.New(ctx, opts)
	case corev1.Service_Spec_POSTGRES:
		zap.L().Debug("Starting in Postgres mode", zap.String("mode", mode.String()))
		s.server, err = postgres.New(ctx, opts)
	case corev1.Service_Spec_MYSQL:
		zap.L().Debug("Starting in MySQL mode", zap.String("mode", mode.String()))
		s.server, err = mysql.New(ctx, opts)
	default:
		return errors.Errorf("Unsupported protocol type by Vigil's server: %s", mode)
	}

	return err
}

func (s *srvMainI) GetService() *corev1.Service {
	return s.vCache.GetService()
}

func (s *srvMainI) GetLBManager() *loadbalancer.LBManager {
	return s.lbManager
}

type srvMainI struct {
	*Server
}

func (s *Server) Run(ctx context.Context) error {

	if err := s.secretMan.ApplyService(ctx); err != nil {
		return err
	}

	if err := s.lbManager.Run(ctx); err != nil {
		return err
	}

	if err := s.server.Run(ctx); err != nil {
		return errors.Errorf("Could not run server: %+v", err)
	}

	watcher := watchers.NewCoreV1(s.octeliumC)

	secretCtl := secretcontroller.NewController(s.server, s.secretMan, s.vCache)

	if err := watcher.Service(ctx, nil, s.svcCtl.OnAdd, s.svcCtl.OnUpdate, s.svcCtl.OnDelete); err != nil {
		return err
	}
	if err := watcher.Secret(ctx, nil, secretCtl.OnAdd, secretCtl.OnUpdate, secretCtl.OnDelete); err != nil {
		return err
	}

	return nil
}

func Run(ctx context.Context) error {

	pprofsrv.New().Run(ctx)

	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return err
	}

	if err := commoninit.Run(ctx, nil); err != nil {
		return err
	}

	svc, err := octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: os.Getenv("OCTELIUM_SVC_UID")})
	if err != nil {
		return err
	}

	s, err := NewServer(ctx, &Opts{
		OcteliumC: octeliumC,
		Service:   svc,
	})
	if err != nil {
		return err
	}

	if err := s.Run(ctx); err != nil {
		return err
	}

	healthcheck.Run(vutils.HealthCheckPortVigil)
	zap.L().Info("Vigil is running", zap.String("svc", svc.Metadata.Name))

	<-ctx.Done()

	return nil
}
