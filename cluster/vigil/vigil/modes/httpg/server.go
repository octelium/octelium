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

package httpg

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"sync"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/ocrypto"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/metricutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/accesslog"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/auth"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/cache"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/compress"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/direct"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/extproc"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/headers"
	jsonschema "github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/jsonchema"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/lua"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/metrics"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/path"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/paths"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/preauth"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/ratelimit"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/retry"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares/validation"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type Server struct {
	octovigilC *octovigilc.Client
	vCache     *vcache.Cache

	lis net.Listener

	octeliumC octeliumc.ClientInterface

	cancelFn     context.CancelFunc
	doneComplete chan struct{}

	srv *http.Server

	mu       sync.Mutex
	isClosed bool

	lbManager *loadbalancer.LBManager
	secretMan *secretman.SecretManager

	crtMan struct {
		mu  sync.RWMutex
		crt *corev1.Secret
	}
	metricsStore *metricsStore

	celEngine *celengine.CELEngine

	reverseProxyErrLogger *log.Logger
	domain                string
	forwardedObfuscatedID string

	svcUID string
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
	zap.L().Debug("Setting TLS Certificate")
	s.crtMan.crt = crt
	return nil
}

func New(ctx context.Context, opts *modes.Opts) (*Server, error) {
	server := &Server{
		doneComplete: make(chan struct{}),
		vCache:       opts.VCache,
		octovigilC:   opts.OctovigilC,
		octeliumC:    opts.OcteliumC,
		lbManager:    opts.LBManager,
		secretMan:    opts.SecretMan,
		metricsStore: &metricsStore{},
		reverseProxyErrLogger: log.New(&zapWriter{
			log: zap.L(),
		}, "", 0),
		forwardedObfuscatedID: fmt.Sprintf("_octelium-%s", utilrand.GetRandomStringLowercase(6)),
		svcUID:                opts.VCache.GetService().Metadata.Uid,
	}

	var err error
	server.metricsStore.CommonMetrics, err = metricutils.NewCommonMetrics(ctx, opts.VCache.GetService())
	if err != nil {
		return nil, err
	}

	server.celEngine, err = celengine.New(ctx, &celengine.Opts{})
	if err != nil {
		return nil, err
	}

	cc, err := server.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}

	server.domain = cc.Status.Domain

	return server, nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed {
		return nil
	}

	zap.L().Debug("Starting closing HTTP server")

	s.isClosed = true
	s.cancelFn()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.srv.Shutdown(ctx)

	close(s.doneComplete)

	zap.L().Debug("HTTP server is now closed")

	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	proxy, err := s.getProxy(ctx)
	if err != nil {
		zap.L().Warn("Could not getProxy", zap.Error(err))
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	proxy.ServeHTTP(w, r)
}

func (s *Server) getTLSConfig(ctx context.Context, svc *corev1.Service) (*tls.Config, error) {
	zap.L().Debug("Getting TLS config")

	crt, err := s.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: vutils.ClusterCertSecretName})
	if err != nil && !grpcerr.IsNotFound(err) {
		return nil, err
	}

	s.crtMan.mu.Lock()
	s.crtMan.crt = crt
	s.crtMan.mu.Unlock()

	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		NextProtos: func() []string {
			if ucorev1.ToService(svc).IsListenerHTTP2() {
				return []string{"h2", "http/1.1"}
			} else {
				return []string{"http/1.1"}
			}
		}(),

		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},

		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			s.crtMan.mu.RLock()
			defer s.crtMan.mu.RUnlock()

			return ocrypto.GetTLSCertificate(s.crtMan.crt)
		},
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	var err error

	zap.L().Debug("Starting running HTTP server")

	svc := s.svc()

	addr := fmt.Sprintf(":%d", ucorev1.ToService(s.svc()).RealPort())
	if svc.Spec.IsTLS {
		tlsCfg, err := s.getTLSConfig(ctx, svc)
		if err != nil {
			return err
		}
		s.lis, err = tls.Listen("tcp", addr, tlsCfg)
		if err != nil {
			return err
		}
	} else {
		s.lis, err = net.Listen("tcp", addr)
		if err != nil {
			return err
		}
	}

	ctx, cancelFn := context.WithCancel(ctx)
	s.cancelFn = cancelFn

	if err := s.serve(ctx); err != nil {
		return err
	}

	zap.L().Debug("HTTP server is now running")

	return nil
}

func (s *Server) getHTTPHandler(ctx context.Context, svc *corev1.Service) (http.Handler, error) {
	chain := middlewares.New()

	appendPlugins := func(phase corev1.Service_Spec_Config_HTTP_Plugin_Phase) {

		chain = chain.Append(func(next http.Handler) (http.Handler, error) {
			return path.New(ctx, next, s.celEngine, phase)
		})

		chain = chain.Append(func(next http.Handler) (http.Handler, error) {
			return ratelimit.New(ctx, next, s.celEngine, s.octeliumC, phase)
		})

		chain = chain.Append(func(next http.Handler) (http.Handler, error) {
			return jsonschema.New(ctx, next, s.celEngine, phase)
		})

		chain = chain.Append(func(next http.Handler) (http.Handler, error) {
			return direct.New(ctx, next, s.celEngine, phase)
		})

		chain = chain.Append(func(next http.Handler) (http.Handler, error) {
			return cache.New(ctx, next, s.celEngine, s.octeliumC, s.svcUID, phase)
		})

		chain = chain.Append(func(next http.Handler) (http.Handler, error) {
			return lua.New(ctx, next, s.celEngine, phase)
		})

		chain = chain.Append(func(next http.Handler) (http.Handler, error) {
			return extproc.New(ctx, next, s.celEngine, phase)
		})
	}

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return metrics.New(ctx, next, s.metricsStore.CommonMetrics)
	})

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return preauth.New(ctx, next, s.octeliumC, s.domain)
	})

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return compress.New(ctx, next)
	})

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return accesslog.New(ctx, next)
	})

	appendPlugins(corev1.Service_Spec_Config_HTTP_Plugin_PRE_AUTH)

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return auth.New(ctx, next, s.octeliumC, s.octovigilC, s.domain)
	})

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return validation.New(ctx, next)
	})

	appendPlugins(corev1.Service_Spec_Config_HTTP_Plugin_POST_AUTH)

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return headers.New(ctx, next, s.celEngine, s.secretMan)
	})

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return paths.New(ctx, next)
	})

	chain = chain.Append(func(next http.Handler) (http.Handler, error) {
		return retry.New(ctx, next)
	})

	handler, err := chain.Then(s)
	if err != nil {
		return nil, err
	}

	handler = http.AllowQuerySemicolons(handler)

	if ucorev1.ToService(svc).IsListenerHTTP2() {
		zap.L().Debug("Using HTTP2 on listener")
		handler = h2c.NewHandler(handler, &http2.Server{})
	}

	return handler, nil
}

func (s *Server) serve(ctx context.Context) error {
	zap.L().Debug("Starting serving connections")

	svc := s.svc()

	handler, err := s.getHTTPHandler(ctx, svc)
	if err != nil {
		return err
	}

	s.srv = &http.Server{
		Addr:              fmt.Sprintf(":%d", ucorev1.ToService(svc).RealPort()),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			svc := s.vCache.GetService()

			reqCtx := &middlewares.RequestContext{
				CreatedAt:     time.Now(),
				Service:       svc,
				Conn:          c,
				ServiceConfig: svc.Spec.Config,
			}

			return context.WithValue(ctx, middlewares.CtxRequestContext, reqCtx)
		},
	}

	if svc.Spec.IsTLS {
		tlsCfg, err := s.getTLSConfig(ctx, svc)
		if err != nil {
			return err
		}
		s.srv.TLSConfig = tlsCfg
	}

	go func() {
		s.srv.Serve(s.lis)
		zap.L().Debug("srv done serving")
	}()

	return nil
}
