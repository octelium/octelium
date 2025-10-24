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

package authserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/cached"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/github"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/oidc"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/oidcassertion"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/saml"
	"github.com/octelium/octelium/cluster/authserver/authserver/providers/utils"
	"github.com/octelium/octelium/cluster/authserver/authserver/rsccache"
	"github.com/octelium/octelium/cluster/common/ccctl"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/commoninit"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/common/watchers"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/patrickmn/go-cache"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type server struct {
	rootURL    string
	domain     string
	authDomain string

	octeliumC octeliumc.ClientInterface

	genCache *cache.Cache

	webProvidersC struct {
		sync.RWMutex
		connectors []utils.Provider
	}

	assertionProvidersC struct {
		sync.RWMutex
		connectors []utils.Provider
	}

	jwkCtl *jwkctl.Controller
	ccCtl  *ccctl.Controller

	celEngine *celengine.CELEngine

	passkeyCtl  *webauthn.WebAuthn
	rscCache    *rsccache.Cache
	mdsProvider metadata.Provider
}

func (s *server) onClusterConfigUpdate(ctx context.Context, new, old *corev1.ClusterConfig) error {
	s.setTemplateGlobals(new)

	return nil
}

func initServer(ctx context.Context,
	octeliumC octeliumc.ClientInterface,
	clusterCfg *corev1.ClusterConfig) (*server, error) {

	rootURL := fmt.Sprintf("https://%s", clusterCfg.Status.Domain)
	var err error

	ret := &server{

		rootURL:    rootURL,
		authDomain: clusterCfg.Status.Domain,
		domain:     clusterCfg.Status.Domain,

		octeliumC: octeliumC,

		genCache: cache.New(cache.NoExpiration, 1*time.Minute),
	}

	ret.ccCtl, err = ccctl.New(ctx, octeliumC, &ccctl.Opts{
		OnUpdate: ret.onClusterConfigUpdate,
	})
	if err != nil {
		return nil, err
	}

	jwkCtl, err := jwkctl.NewJWKController(ctx, octeliumC)
	if err != nil {
		return nil, err
	}
	ret.jwkCtl = jwkCtl

	if err := ret.setIdentityProviders(ctx); err != nil {
		return nil, err
	}

	ret.setTemplateGlobals(clusterCfg)

	watcherC := watchers.NewCoreV1(ret.octeliumC)

	if err := watcherC.IdentityProvider(ctx, nil,
		func(ctx context.Context, item *corev1.IdentityProvider) error {
			return ret.setIdentityProviders(ctx)
		},
		func(ctx context.Context, new, old *corev1.IdentityProvider) error {
			return ret.setIdentityProviders(ctx)
		},
		func(ctx context.Context, item *corev1.IdentityProvider) error {
			return ret.setIdentityProviders(ctx)
		},
	); err != nil {
		return nil, err
	}

	if err := watcherC.Secret(ctx, nil,
		func(ctx context.Context, item *corev1.Secret) error {
			return ret.setIdentityProviders(ctx)
		},
		func(ctx context.Context, new, old *corev1.Secret) error {
			return ret.setIdentityProviders(ctx)
		},
		func(ctx context.Context, item *corev1.Secret) error {
			return ret.setIdentityProviders(ctx)
		},
	); err != nil {
		return nil, err
	}

	ret.celEngine, err = celengine.New(ctx, &celengine.Opts{})
	if err != nil {
		return nil, err
	}

	ret.passkeyCtl, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Octelium",
		RPID:          clusterCfg.Status.Domain,
		Debug:         ldflags.IsDev(),
		RPOrigins:     []string{fmt.Sprintf("https://%s", clusterCfg.Status.Domain)},
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    60 * time.Second,
				TimeoutUVD: 60 * time.Second,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    60 * time.Second,
				TimeoutUVD: 60 * time.Second,
			},
		},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationPreferred,
		},
	})
	if err != nil {
		return nil, err
	}

	ret.rscCache, err = rsccache.NewCache()
	if err != nil {
		return nil, err
	}

	ret.mdsProvider, err = cached.New(
		cached.WithPath(fmt.Sprintf("/tmp/mds-%s", utilrand.GetRandomStringCanonical(8))),
		cached.WithForceUpdate(true),
		cached.WithUpdate(true),
	)
	if err != nil {
		zap.L().Warn("Could not create MDS provider", zap.Error(err))
	}

	zap.L().Debug("initializing authServer completed")

	return ret, nil
}

func (s *server) setTemplateGlobals(clusterCfg *corev1.ClusterConfig) {
	t := &templateGlobals{
		Cluster: templateGlobalsCluster{
			Domain:      clusterCfg.Status.Domain,
			DisplayName: clusterCfg.Metadata.DisplayName,
		},
	}

	s.genCache.Set("template-globals", t, cache.NoExpiration)
}

func (s *server) getTemplateGlobals() *templateGlobals {
	val, found := s.genCache.Get("template-globals")
	if !found {
		return nil
	}

	return val.(*templateGlobals)
}

func (s *server) setIdentityProviders(ctx context.Context) error {

	s.webProvidersC.Lock()
	defer s.webProvidersC.Unlock()

	s.assertionProvidersC.Lock()
	defer s.assertionProvidersC.Unlock()

	zap.L().Debug("Resetting the Identity Provider list")

	s.webProvidersC.connectors = []utils.Provider{}
	s.assertionProvidersC.connectors = []utils.Provider{}

	clusterCfg, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	identityProviders, err := s.octeliumC.CoreC().ListIdentityProvider(ctx, &rmetav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, idp := range identityProviders.Items {

		var c utils.Provider

		switch idp.Spec.Type.(type) {
		case *corev1.IdentityProvider_Spec_Github_:
			c, err = github.NewConnector(ctx, &utils.ProviderOpts{
				OcteliumC:     s.octeliumC,
				Provider:      idp,
				ClusterConfig: clusterCfg,
				CELEngine:     s.celEngine,
			})
			if err != nil {
				return err
			}
		case *corev1.IdentityProvider_Spec_Oidc:
			c, err = oidc.NewConnector(ctx, &utils.ProviderOpts{
				OcteliumC:     s.octeliumC,
				Provider:      idp,
				ClusterConfig: clusterCfg,
				CELEngine:     s.celEngine,
			})
			if err != nil {
				return err
			}
		case *corev1.IdentityProvider_Spec_Saml:
			c, err = saml.NewConnector(ctx, &utils.ProviderOpts{
				OcteliumC:     s.octeliumC,
				Provider:      idp,
				ClusterConfig: clusterCfg,
				CELEngine:     s.celEngine,
			})
			if err != nil {
				return err
			}

		default:
			continue
		}

		s.webProvidersC.connectors = append(s.webProvidersC.connectors, c)
		zap.L().Debug("Added web IdentityProvider", zap.String("name", c.Name()))
	}

	for _, idp := range identityProviders.Items {
		switch idp.Spec.Type.(type) {
		case *corev1.IdentityProvider_Spec_OidcIdentityToken:
			c, err := oidcassertion.NewConnector(ctx, &utils.ProviderOpts{
				OcteliumC:     s.octeliumC,
				Provider:      idp,
				ClusterConfig: clusterCfg,
				CELEngine:     s.celEngine,
			})
			if err != nil {
				return err
			}
			s.assertionProvidersC.connectors = append(s.assertionProvidersC.connectors, c)
			zap.L().Debug("Added assertion IdentityProvider", zap.String("name", c.Name()))
		}
	}

	zap.L().Debug("Successfully set the Identity Provider list")

	return nil
}

func (s *server) run(ctx context.Context, grpcMode bool) error {
	if err := s.jwkCtl.Run(ctx); err != nil {
		return err
	}

	if err := s.ccCtl.Run(ctx); err != nil {
		return err
	}

	if err := watchers.NewCoreV1(s.octeliumC).Authenticator(ctx, nil,
		func(ctx context.Context, item *corev1.Authenticator) error {
			return s.rscCache.SetAuthenticator(item)
		},
		func(ctx context.Context, new, old *corev1.Authenticator) error {
			return s.rscCache.SetAuthenticator(new)
		},
		func(ctx context.Context, item *corev1.Authenticator) error {
			return s.rscCache.DeleteAuthenticator(item)
		}); err != nil {
		return err
	}

	if grpcMode {
		authSrv := &authMainSvc{
			s: s,
		}

		grpcSrv := grpc.NewServer(
			grpc.MaxConcurrentStreams(100*1000),
			grpc.ConnectionTimeout(10*time.Second),
			grpc.MaxRecvMsgSize(200*1024),
			grpc.ReadBufferSize(32*1024),
		)
		authv1.RegisterMainServiceServer(grpcSrv, authSrv)

		lisGRPC, err := net.Listen("tcp", vutils.ManagedServiceAddr)
		if err != nil {
			return err
		}

		go func() {
			zap.L().Debug("running auth gRPC server...")
			if err := grpcSrv.Serve(lisGRPC); err != nil {
				zap.L().Info("gRPC server closed", zap.Error(err))
			}
		}()
	} else {

		r := mux.NewRouter()
		r.HandleFunc("/", s.handleLogin).Methods("GET")
		r.HandleFunc("/login", s.handleLogin).Methods("GET")

		r.HandleFunc("/begin", s.handleAuth).Methods("POST")
		r.HandleFunc("/callback", s.handleAuthCallback).Methods("GET", "POST")
		r.HandleFunc("/callback/success", s.handleAuthSuccess).Methods("GET")
		r.HandleFunc("/oauth2/token", s.handleOAuth2Token).Methods("POST")

		r.HandleFunc("/.well-known/oauth-authorization-server", s.handleOAuth2Metadata).Methods("GET")

		r.HandleFunc("/assets/{file}", s.handleStatic).Methods("GET")

		r.HandleFunc("/authenticators/authenticate", s.handleAuthenticatorAuthenticate).Methods("GET")
		r.HandleFunc("/authenticators/register", s.handleAuthenticatorRegister).Methods("GET")
		r.HandleFunc("/authenticators", s.handleAuthenticatorList).Methods("GET")
		r.HandleFunc("/denied", s.handleDenied).Methods("GET")

		r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			zap.L().Debug("404 req", zap.Any("path", r.URL.Path), zap.String("method", r.Method))
			if r.Method == "GET" {
				s.redirectToLogin(w, r)
			} else {
				http.NotFound(w, r)
			}
		})

		go func() error {
			srv := &http.Server{
				Handler:      r,
				Addr:         vutils.ManagedServiceAddr,
				WriteTimeout: 15 * time.Second,
				ReadTimeout:  15 * time.Second,
			}

			return srv.ListenAndServe()
		}()
	}

	return nil
}

func Run(ctx context.Context, grpcMode bool) error {
	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return err
	}

	if err := commoninit.Run(ctx, nil); err != nil {
		return err
	}

	clusterCfg, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	s, err := initServer(ctx, octeliumC, clusterCfg)
	if err != nil {
		return err
	}

	if err := s.run(ctx, grpcMode); err != nil {
		return err
	}

	healthcheck.Run(vutils.HealthCheckPortManagedService)
	zap.L().Info("AuthServer is now running...")
	<-ctx.Done()

	return nil
}

func (s *server) getWebProviderFromUID(uid string) (utils.Provider, error) {
	s.webProvidersC.RLock()
	defer s.webProvidersC.RUnlock()
	for _, itm := range s.webProvidersC.connectors {
		idp := itm.Provider()
		if idp.Metadata.Uid != uid {
			continue
		}

		if idp.Spec.IsDisabled {
			return nil, s.errPermissionDenied("IdentityProvider is disabled")
		}

		if idp.Status.IsLocked {
			return nil, s.errPermissionDenied("IdentityProvider is locked")
		}

		return itm, nil
	}

	return nil, errors.Errorf("Could not find IdentityProvider: %s in the cached list", uid)
}

func (s *server) getAssertionProviderFromName(name string) (utils.Provider, error) {
	s.assertionProvidersC.RLock()
	defer s.assertionProvidersC.RUnlock()
	for _, itm := range s.assertionProvidersC.connectors {
		if itm.Name() == name {
			return itm, nil
		}
	}

	return nil, errors.Errorf("Could not find IdentityProvider: %s in the cached list", name)
}

func (s *server) checkMaxSessionsPerUser(ctx context.Context, usr *corev1.User, cc *corev1.ClusterConfig) error {
	var maxSess uint32
	if usr.Spec.Session != nil && usr.Spec.Session.MaxPerUser > 0 {
		maxSess = usr.Spec.Session.MaxPerUser
	} else {
		switch usr.Spec.Type {
		case corev1.User_Spec_HUMAN:
			if cc.Spec.Session != nil && cc.Spec.Session.Human != nil && cc.Spec.Session.Human.MaxPerUser > 0 {
				maxSess = cc.Spec.Session.Human.MaxPerUser
			} else {
				maxSess = 16
			}
		case corev1.User_Spec_WORKLOAD, corev1.User_Spec_TYPE_UNKNOWN:
			if cc.Spec.Session != nil && cc.Spec.Session.Workload != nil && cc.Spec.Session.Workload.MaxPerUser > 0 {
				maxSess = cc.Spec.Session.Workload.MaxPerUser
			} else {
				maxSess = 128
			}
		}
	}

	if maxSess > 10000 {
		maxSess = 10000
	}

	sessList, err := s.octeliumC.CoreC().ListSession(ctx, urscsrv.FilterByUser(usr))
	if err != nil {
		return s.errInternalErr(err)
	}
	if uint32(len(sessList.Items)) >= maxSess {
		return s.errPermissionDenied("Session per User limit exceeded")
	}

	return nil
}

func GetAuthGRPCServer(ctx context.Context, octeliumC octeliumc.ClientInterface) (authv1.MainServiceServer, error) {
	cc, err := octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}
	s, err := initServer(ctx, octeliumC, cc)
	if err != nil {
		return nil, err
	}
	authSrv := &authMainSvc{
		s: s,
	}
	return authSrv, nil
}
