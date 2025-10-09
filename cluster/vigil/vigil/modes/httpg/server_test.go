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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gorilla/websocket"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type tstSrvHTTP struct {
	port        int
	srv         *http.Server
	isHTTP2     bool
	crt         *tls.Certificate
	isWS        bool
	bearerToken string
	caPool      *x509.CertPool
	lis         net.Listener

	wait      time.Duration
	startedAt time.Time
}

type tstResp struct {
	Hello string `json:"hello"`
}

func (s *tstSrvHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.wait > 0 && time.Since(s.startedAt) < s.wait {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	if r.Method == http.MethodPost {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()

		var req tstResp
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		resp, err := json.Marshal(&tstResp{
			Hello: req.Hello,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	}

	if s.bearerToken != "" {
		bearer := r.Header.Get("Authorization")
		tkn := strings.TrimPrefix(bearer, "Bearer ")
		if s.bearerToken != tkn {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	if !s.isWS {
		w.Header().Set("Content-Type", "application/json")
		resp, err := json.Marshal(&tstResp{
			Hello: "world",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(resp)
		return
	}

	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer wsConn.Close()
	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, payload, err := wsConn.ReadMessage()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			wsConn.WriteMessage(websocket.BinaryMessage, payload)
		}
	}
}

func newSrvHTTP(t *testing.T, port int, isHTTP2 bool, crt *tls.Certificate) *tstSrvHTTP {
	return &tstSrvHTTP{
		port:    port,
		isHTTP2: isHTTP2,
		crt:     crt,
	}
}

func (s *tstSrvHTTP) run(t *testing.T) {
	addr := fmt.Sprintf("localhost:%d", s.port)
	var err error

	handler := http.AllowQuerySemicolons(s)
	if s.isHTTP2 {
		handler = h2c.NewHandler(handler, &http2.Server{})
	}
	s.srv = &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	if s.crt != nil {
		zap.L().Debug("upstream listening over TLS")
		s.lis, err = func() (net.Listener, error) {
			for range 100 {
				ret, err := tls.Listen("tcp", addr, s.getTLSConfig())
				if err == nil {
					return ret, nil
				}
				time.Sleep(1 * time.Second)
			}
			return nil, errors.Errorf("Could not listen tstSrvHTTP")
		}()
		assert.Nil(t, err)
	} else {
		s.lis, err = func() (net.Listener, error) {
			for range 100 {
				ret, err := net.Listen("tcp", addr)
				if err == nil {
					return ret, nil
				}
				time.Sleep(1 * time.Second)
			}
			return nil, errors.Errorf("Could not listen tstSrvHTTP")
		}()
		assert.Nil(t, err)
	}

	s.startedAt = time.Now()
	go s.srv.Serve(s.lis)
}

func (s *tstSrvHTTP) getTLSConfig() *tls.Config {
	if s.crt == nil {
		return nil
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*s.crt},
		NextProtos: func() []string {
			if s.isHTTP2 {
				return []string{"h2", "http/1.1"}
			} else {
				return []string{"http/1.1"}
			}
		}(),
		RootCAs: s.caPool,
	}

}

func (s *tstSrvHTTP) close() {
	if s.srv != nil {
		s.srv.Close()
	}
	if s.lis != nil {
		s.lis.Close()
	}

	time.Sleep(1 * time.Second)
}

type tstSrvGRPC struct {
	port int
	crt  *tls.Certificate
	corev1.UnimplementedMainServiceServer
	grpcSrv *grpc.Server
}

func newSrvGRPC(t *testing.T, port int, crt *tls.Certificate) *tstSrvGRPC {
	return &tstSrvGRPC{
		port: port,
		crt:  crt,
	}
}

func (s *tstSrvGRPC) run(t *testing.T) {
	addr := fmt.Sprintf("localhost:%d", s.port)
	lis, err := func() (net.Listener, error) {
		for i := 0; i < 100; i++ {
			listener, err := net.Listen("tcp", addr)
			if err == nil {
				return listener, nil
			}
			zap.L().Debug("Could not listen tstTCPProxy. Trying again...", zap.Error(err))
			time.Sleep(1 * time.Second)
		}
		return nil, errors.Errorf("Could not listen tstTCPProxy")
	}()

	assert.Nil(t, err)

	s.grpcSrv = grpc.NewServer()

	corev1.RegisterMainServiceServer(s.grpcSrv, s)
	go func() {
		s.grpcSrv.Serve(lis)
	}()
	time.Sleep(1 * time.Second)
}

func (s *tstSrvGRPC) CreateUser(ctx context.Context, req *corev1.User) (*corev1.User, error) {
	return req, nil
}

func (s *tstSrvGRPC) CreateSecret(ctx context.Context, req *corev1.Secret) (*corev1.Secret, error) {
	return nil, status.Errorf(codes.InvalidArgument, "Un-auth")
}

func (s *tstSrvGRPC) close() {
	s.grpcSrv.Stop()
	time.Sleep(1 * time.Second)
}

type tstOAuthSrv struct {
	srv         *http.Server
	port        int
	accessToken string
}

func (s *tstOAuthSrv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ret := map[string]any{
		"token_type":   "Bearer",
		"access_token": s.accessToken,
		"expires_in":   3600,
	}
	respBytes, _ := json.Marshal(&ret)
	w.Write(respBytes)
}

func (s *tstOAuthSrv) run(t *testing.T) {
	s.srv = &http.Server{
		Addr:    net.JoinHostPort("localhost", fmt.Sprintf("%d", s.port)),
		Handler: s,
	}

	lis, err := net.Listen("tcp", net.JoinHostPort("localhost", fmt.Sprintf("%d", s.port)))
	assert.Nil(t, err)
	go s.srv.Serve(lis)
}

func (s *tstOAuthSrv) close() {
	s.srv.Close()
	time.Sleep(1 * time.Second)
}

func TestServer(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	upstreamPort := tests.GetPort()
	getUpstreamSpec := func(isTLS bool) *corev1.Service_Spec_Config_Upstream {
		scheme := func() string {
			if isTLS {
				return "https"
			}
			return "http"
		}()

		return &corev1.Service_Spec_Config_Upstream{
			Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{
				Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{
					Endpoints: []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
						{
							Url: fmt.Sprintf("%s://localhost:%d", scheme, upstreamPort),
						},
					},
				},
			},

			/*
				Config: &corev1.Service_Spec_Config_Upstream_Config{
					Type: &corev1.Service_Spec_Config_Upstream_Config_Http{
						Http: &corev1.Service_Spec_Config_Upstream_Config_HTTP{
							EnableHTTP2: isHTTP2,
						},
					},
				},
			*/
		}
	}
	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Config: &corev1.Service_Spec_Config{
				Upstream: getUpstreamSpec(false),
			},
			Mode: corev1.Service_Spec_HTTP,
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,

		LBManager: loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	/*
		{
			resp, err := resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
			assert.Nil(t, err)

			assert.True(t, resp.IsSuccess())
			assert.Equal(t, "world", resp.Result().(*tstResp).Hello)

			// now unauthorized
			svc.Spec.Authorization.InlinePolicies[0].Spec.Rules[0].GroupsAny = []string{"root"}

			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err)

			svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			vCache.SetService(svcV)

			resp, err = resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, 403, resp.StatusCode())

			// authorized again
			svc.Spec.Authorization.InlinePolicies[0].Spec.Rules[0].GroupsAny = []string{"all"}

			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err)

			svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			vCache.SetService(svcV)

			resp, err = resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
			assert.Nil(t, err)
			assert.True(t, resp.IsSuccess())
			assert.Equal(t, "world", resp.Result().(*tstResp).Hello)
		}
	*/

	{
		usr, err := tstuser.NewUserWorkloadClientless(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		srv.octovigilC.GetCache().SetSession(usr.Session)

		resp, err := resty.New().R().SetHeader("X-Octelium-Auth", usr.GetAccessToken().AccessToken).
			SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.True(t, resp.IsSuccess())
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)
	}

	{
		// test bearer token
		tkn := utilrand.GetRandomString(16)
		srv.Close()
		upstreamSrv.close()
		upstreamSrv.bearerToken = tkn
		upstreamSrv.run(t)

		sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(6),
			},
			Spec: &corev1.Secret_Spec{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: tkn,
				},
			},
		})
		assert.Nil(t, err)

		svc.Spec.Config = &corev1.Service_Spec_Config{
			Upstream: getUpstreamSpec(false),
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					Auth: &corev1.Service_Spec_Config_HTTP_Auth{
						Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_{
							Bearer: &corev1.Service_Spec_Config_HTTP_Auth_Bearer{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_FromSecret{
									FromSecret: sec.Metadata.Name,
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		resp, err := resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.True(t, resp.IsSuccess())
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)

		/*
			svc.Spec.Config = nil
			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err, "%+v", err)
			svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			vCache.SetService(svcV)
		*/

		upstreamSrv.bearerToken = utilrand.GetRandomString(32)
		resp, err = resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode())

	}

	{
		// test oauth2 client credentials
		tkn := utilrand.GetRandomString(16)
		srv.Close()
		upstreamSrv.close()
		upstreamSrv.bearerToken = tkn
		upstreamSrv.run(t)

		oauth2Srv := &tstOAuthSrv{
			accessToken: tkn,
			port:        tests.GetPort(),
		}

		oauth2Srv.run(t)
		defer oauth2Srv.close()
		time.Sleep(2 * time.Second)

		sec, err := adminSrv.CreateSecret(ctx, &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(6),
			},
			Spec: &corev1.Secret_Spec{},
			Data: &corev1.Secret_Data{
				Type: &corev1.Secret_Data_Value{
					Value: tkn,
				},
			},
		})
		assert.Nil(t, err)

		if svc.Spec.Config == nil {
			svc.Spec.Config = &corev1.Service_Spec_Config{
				Upstream: getUpstreamSpec(false),
			}
		}
		svc.Spec.Config.Type = &corev1.Service_Spec_Config_Http{
			Http: &corev1.Service_Spec_Config_HTTP{
				Auth: &corev1.Service_Spec_Config_HTTP_Auth{
					Type: &corev1.Service_Spec_Config_HTTP_Auth_Oauth2ClientCredentials{
						Oauth2ClientCredentials: &corev1.Service_Spec_Config_HTTP_Auth_OAuth2ClientCredentials{
							ClientID: utilrand.GetRandomStringCanonical(8),
							TokenURL: fmt.Sprintf("http://localhost:%d/oauth2/token", oauth2Srv.port),
							ClientSecret: &corev1.Service_Spec_Config_HTTP_Auth_OAuth2ClientCredentials_ClientSecret{
								Type: &corev1.Service_Spec_Config_HTTP_Auth_OAuth2ClientCredentials_ClientSecret_FromSecret{
									FromSecret: sec.Metadata.Name,
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			OctovigilC: octovigilC,
			VCache:     vCache,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		err = secretMan.ApplyService(ctx)
		assert.Nil(t, err)

		resp, err := resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.True(t, resp.IsSuccess())
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)

		/*
			svc.Spec.Config = nil
			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err)
			svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			vCache.SetService(svcV)
		*/

		upstreamSrv.bearerToken = utilrand.GetRandomString(32)
		resp, err = resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode())

	}

	{
		// test mTLS
		srv.Close()
		upstreamSrv.close()

		root, err := utils_cert.GenerateCARoot()
		assert.Nil(t, err)
		sn, err := utils_cert.GenerateSerialNumber()
		assert.Nil(t, err)
		srvCrt, err := utils_cert.GenerateCertificate(&x509.Certificate{
			BasicConstraintsValid: true,
			SerialNumber:          sn,
			Subject: pkix.Name{
				CommonName: "localhost",
			},

			DNSNames: []string{"localhost"},

			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}, root.Certificate, root.PrivateKey, false)
		assert.Nil(t, err)

		srvCert, err := tls.X509KeyPair((srvCrt.MustGetCertPEM()), (srvCrt.MustGetPrivateKeyPEM()))
		assert.Nil(t, err)
		upstreamSrv = newSrvHTTP(t, upstreamPort, false, &srvCert)
		srvCaPool := x509.NewCertPool()
		ok := srvCaPool.AppendCertsFromPEM(root.MustGetCertPEM())
		assert.True(t, ok)
		upstreamSrv.caPool = srvCaPool
		upstreamSrv.run(t)

		clientCrt, err := utils_cert.GenerateCertificate(&x509.Certificate{
			BasicConstraintsValid: true,
			SerialNumber:          sn,
			Subject: pkix.Name{
				CommonName: "client",
			},

			NotBefore:   time.Now(),
			NotAfter:    time.Now().Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}, root.Certificate, root.PrivateKey, false)
		assert.Nil(t, err)

		sec := &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(6),
			},
			Spec: &corev1.Secret_Spec{},
		}
		ucorev1.ToSecret(sec).SetCertificate(string(clientCrt.MustGetCertPEM()),
			string(clientCrt.MustGetPrivateKeyPEM()))
		sec, err = adminSrv.CreateSecret(ctx, sec)
		assert.Nil(t, err)

		svc.Spec.Config = &corev1.Service_Spec_Config{
			Upstream: getUpstreamSpec(true),
			ClientCertificate: &corev1.Service_Spec_Config_ClientCertificate{

				Type: &corev1.Service_Spec_Config_ClientCertificate_FromSecret{
					FromSecret: sec.Metadata.Name,
				},

				TrustedCAs: []string{
					string(root.MustGetCertPEM()),
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secV, err := fakeC.OcteliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Uid: sec.Metadata.Uid})
		assert.Nil(t, err)

		secretMan.Set(secV)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		resp, err := resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.True(t, resp.IsSuccess())
		zap.L().Debug("response", zap.Int("code", resp.StatusCode()), zap.String("body", string(resp.Body())))
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)

		/*
			svc.Spec.Config = nil
			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err)
			svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
			assert.Nil(t, err)
			vCache.SetService(svcV)


		*/

		upstreamSrv.bearerToken = ""
		upstreamSrv.caPool = nil
		upstreamSrv.crt = nil
	}

	{

		srv.Close()
		upstreamSrv.close()
		upstreamSrv.isHTTP2 = true
		upstreamSrv.run(t)

		svc.Spec.Config = &corev1.Service_Spec_Config{
			Upstream: getUpstreamSpec(false),
			Type: &corev1.Service_Spec_Config_Http{
				Http: &corev1.Service_Spec_Config_HTTP{
					IsUpstreamHTTP2: true,
				},
			},
		}
		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		resp, err := resty.New().R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err)
		assert.True(t, resp.IsSuccess())
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)

		svc.Spec.Config = nil
	}

	{

		srv.Close()
		upstreamSrv.close()
		upstreamSrv.isHTTP2 = false
		upstreamSrv.isWS = true
		upstreamSrv.run(t)

		if svc.Spec.Config == nil {
			svc.Spec.Config = &corev1.Service_Spec_Config{}
		}
		svc.Spec.Config.Upstream = getUpstreamSpec(false)
		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		wsClient := websocket.Dialer{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		}

		wsC, _, err := wsClient.DialContext(ctx,
			fmt.Sprintf("ws://localhost:%d/", ucorev1.ToService(svcV).RealPort()), http.Header{})
		assert.Nil(t, err)

		for i := 0; i < 10; i++ {
			msg := utilrand.GetRandomBytesMust(32)
			err = wsC.WriteMessage(websocket.BinaryMessage, msg)
			assert.Nil(t, err)
			_, read, err := wsC.ReadMessage()
			assert.Nil(t, err)
			assert.True(t, utils.SecureBytesEqual(msg, read))
		}

		wsC.Close()
	}

	{
		srv.Close()
		upstreamSrv.close()
		upstreamSrv.isWS = false
		upstreamSrv.isHTTP2 = false
		upstreamSrv.run(t)

		if svc.Spec.Config == nil {
			svc.Spec.Config = &corev1.Service_Spec_Config{}
		}
		svc.Spec.Config.Upstream = getUpstreamSpec(false)
		svc.Spec.IsTLS = true
		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		cert, err := srv.octeliumC.CoreC().GetSecret(ctx, &rmetav1.GetOptions{Name: vutils.ClusterCertSecretName})
		assert.Nil(t, err)

		err = srv.SetClusterCertificate(cert)
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err, "%+v", err)

		time.Sleep(1 * time.Second)
		rootCa := x509.NewCertPool()

		ca, err := utils_cert.ParseX509LeafCertificateChainPEM(ucorev1.ToSecret(cert).GetSpecValueBytes())
		assert.Nil(t, err)
		rootCa.AddCert(ca)

		resp, err := resty.New().SetDebug(true).SetTLSClientConfig(&tls.Config{
			RootCAs: rootCa,
		}).R().SetResult(&tstResp{}).Get(fmt.Sprintf("https://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
		assert.Equal(t, "world", resp.Result().(*tstResp).Hello)
	}

	{

		srv.Close()
		upstreamSrv.close()

		grpcSrv := newSrvGRPC(t, upstreamPort, nil)
		grpcSrv.run(t)

		svc.Spec.IsTLS = false
		svc.Spec.Port = uint32(tests.GetPort())
		svc.Spec.Mode = corev1.Service_Spec_GRPC
		if svc.Spec.Config == nil {
			svc.Spec.Config = &corev1.Service_Spec_Config{}
		}
		svc.Spec.Config.Upstream = &corev1.Service_Spec_Config_Upstream{
			Type: &corev1.Service_Spec_Config_Upstream_Url{
				Url: fmt.Sprintf("http://localhost:%d", upstreamPort),
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)
		time.Sleep(1 * time.Second)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err, "%+v", err)

		time.Sleep(1 * time.Second)
		grcpConn, err := grpc.Dial(fmt.Sprintf("localhost:%d", ucorev1.ToService(svcV).RealPort()), grpc.WithTransportCredentials(insecure.NewCredentials()))
		assert.Nil(t, err)
		grpcC := corev1.NewMainServiceClient(grcpConn)
		req := &corev1.User{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomString(10),
				Uid:  utilrand.GetRandomString(10),
			},
		}
		resp, err := grpcC.CreateUser(ctx, req)
		assert.Nil(t, err, "%+v", err)
		assert.True(t, pbutils.IsEqual(req, resp))

		_, err = grpcC.CreateSecret(ctx, &corev1.Secret{})
		assert.NotNil(t, err, "%+v", err)
		assert.True(t, grpcerr.IsInvalidArg(err))

		grpcSrv.close()
	}

	time.Sleep(2 * time.Second)
	err = srv.Close()
	assert.Nil(t, err)

}

func TestServerK8s(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	upstreamPort := tests.GetPort()

	root, err := utils_cert.GenerateCARoot()
	assert.Nil(t, err)

	sn, err := utils_cert.GenerateSerialNumber()
	assert.Nil(t, err)

	srvCrt, err := utils_cert.GenerateCertificate(&x509.Certificate{
		BasicConstraintsValid: true,
		SerialNumber:          sn,
		Subject: pkix.Name{
			CommonName: "localhost",
		},

		DNSNames: []string{"localhost"},

		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, root.Certificate, root.PrivateKey, false)
	assert.Nil(t, err)

	clientCrt, err := utils_cert.GenerateCertificate(&x509.Certificate{
		BasicConstraintsValid: true,
		SerialNumber:          sn,
		Subject: pkix.Name{
			CommonName: "client",
		},

		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, root.Certificate, root.PrivateKey, false)
	assert.Nil(t, err)

	sec := &corev1.Secret{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Secret_Spec{},
	}
	ucorev1.ToSecret(sec).SetCertificate(string(clientCrt.MustGetCertPEM()),
		string(clientCrt.MustGetPrivateKeyPEM()))
	sec, err = adminSrv.CreateSecret(ctx, sec)
	assert.Nil(t, err)

	srvCert, err := tls.X509KeyPair((srvCrt.MustGetCertPEM()), (srvCrt.MustGetPrivateKeyPEM()))
	assert.Nil(t, err)

	upstreamSrv := newSrvHTTP(t, upstreamPort, false, &srvCert)
	upstreamSrv.caPool = x509.NewCertPool()
	upstreamSrv.caPool.AddCert(root.Certificate)
	upstreamSrv.run(t)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_KUBERNETES,

			Config: &corev1.Service_Spec_Config{

				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("https://localhost:%d", upstreamPort),
					},
				},
				Type: &corev1.Service_Spec_Config_Kubernetes_{
					Kubernetes: &corev1.Service_Spec_Config_Kubernetes{
						Type: &corev1.Service_Spec_Config_Kubernetes_ClientCertificate{
							ClientCertificate: &corev1.Service_Spec_Config_ClientCertificate{
								TrustedCAs: []string{
									string(root.MustGetCertPEM()),
								},

								Type: &corev1.Service_Spec_Config_ClientCertificate_FromSecret{
									FromSecret: sec.Metadata.Name,
								},
							},
						},
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())
	assert.Equal(t, "world", resp.Result().(*tstResp).Hello)
}

func TestUserUpstream(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, false, nil)

	upstreamSrv.run(t)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
					User: usr.Usr.Metadata.Name,
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)

	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usrDownstream, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usrDownstream.Connect()
	assert.Nil(t, err, "%+v", err)

	usrDownstream.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usrDownstream.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usrDownstream.Session)
	assert.Nil(t, err)
	usrDownstream.Resync()

	srv.octovigilC.GetCache().SetSession(usrDownstream.Session)
	usrDownstream.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsError())
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode())

	err = usr.ConnectWithServeAll()
	assert.Nil(t, err)

	usr.Resync()

	usr.Session.Status.Connection.Addresses = []*metav1.DualStackNetwork{
		{
			V4: "127.0.0.1/32",
			V6: "::1/128",
		},
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usrDownstream.Resync()

	tstP := &tstTCPProxy{
		host:       "www.google.com",
		port:       443,
		listenPort: 23000,
		ready:      make(chan struct{}),
	}
	err = tstP.run(ctx)
	assert.Nil(t, err)

	zap.L().Debug("Running tcp proxy", zap.Int("port", tstP.listenPort))

	<-tstP.ready
	time.Sleep(1 * time.Second)

	resp, err = resty.New().SetDebug(true).R().
		SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess(), "code: %d", resp.StatusCode())
}

type tstTCPProxy struct {
	host string
	port int

	listenPort int

	ready chan struct{}
}

func (p *tstTCPProxy) run(ctx context.Context) error {
	go func(ctx context.Context) {
		if err := p.doRun(ctx); err != nil {
			zap.L().Error("Could not doRun", zap.Error(err))
		}
	}(ctx)
	return nil
}

func (p *tstTCPProxy) doRun(ctx context.Context) error {
	zap.L().Debug("Starting TCP listener")
	var err error
	var listener net.Listener

	if err := func() error {
		for i := 0; i < 100; i++ {
			listener, err = net.Listen("tcp", fmt.Sprintf(":%d", p.listenPort))
			if err == nil {
				p.ready <- struct{}{}
				return nil
			}
			zap.L().Debug("Could not listen tstTCPProxy. Trying again...", zap.Error(err))
			time.Sleep(1 * time.Second)
		}
		return err
	}(); err != nil {
		return err
	}

	zap.L().Debug("created listener")

	defer listener.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()

			zap.L().Debug("new conn")
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			go func(conn net.Conn) {
				connBackend, err := p.getConnBackend()
				if err != nil {
					return
				}
				p.ServeTCP(conn.(*net.TCPConn), connBackend)
			}(conn)
		}
	}

}

func (p *tstTCPProxy) getConnBackend() (WriteCloser, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(p.host, fmt.Sprintf("%d", p.port)))
	if err != nil {
		return nil, err
	}
	return net.DialTCP("tcp", nil, tcpAddr)

}

func (p *tstTCPProxy) ServeTCP(conn, connBackend WriteCloser) {
	zap.L().Debug("Starting serveTCP")
	defer conn.Close()
	defer connBackend.Close()

	errChan := make(chan error, 2)
	go p.connCopy(conn, connBackend, errChan)
	go p.connCopy(connBackend, conn, errChan)

	<-errChan
}

func (p tstTCPProxy) connCopy(dst, src WriteCloser, errCh chan error) {
	_, err := io.Copy(dst, src)
	errCh <- err

	errClose := dst.CloseWrite()
	if errClose != nil {
		return
	}

	{
		dst.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
}

type WriteCloser interface {
	net.Conn
	CloseWrite() error
}

func TestAnonymous(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, false, nil)

	upstreamSrv.run(t)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic:    true,
			IsAnonymous: true,
			Port:        uint32(tests.GetPort()),
			Mode:        corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())

	svc.Spec.IsAnonymous = false
	svc, err = adminSrv.UpdateService(ctx, svc)
	assert.Nil(t, err)
	svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)
	vCache.SetService(svcV)
	time.Sleep(1 * time.Second)
	resp, err = resty.New().SetDebug(true).R().SetResult(&tstResp{}).Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsError())
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode())
}

func TestBuffered(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstreamSrv.port),
					},
				},
				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						EnableRequestBuffering: true,
						Body: &corev1.Service_Spec_Config_HTTP_Body{
							Mode: corev1.Service_Spec_Config_HTTP_Body_JSON,
						},
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	res := &tstResp{}
	tReq := &tstResp{
		Hello: utilrand.GetRandomString(32),
	}
	resp, err := resty.New().SetDebug(true).R().
		SetResult(res).
		SetBody(tReq).
		Post(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())
	assert.Equal(t, tReq.Hello, res.Hello)
}

func TestDirectResponse(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{

				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Response: &corev1.Service_Spec_Config_HTTP_Response{
							Type: &corev1.Service_Spec_Config_HTTP_Response_Direct_{
								Direct: &corev1.Service_Spec_Config_HTTP_Response_Direct{
									ContentType: fmt.Sprintf("application/%s", utilrand.GetRandomStringCanonical(8)),
									StatusCode:  209,
									Type: &corev1.Service_Spec_Config_HTTP_Response_Direct_Inline{
										Inline: utilrand.GetRandomString(400),
									},
								},
							},
						},
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().
		Post(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())

	assert.Equal(t, svc.Spec.Config.GetHttp().Response.GetDirect().GetInline(), string(resp.Body()))
	assert.Equal(t, svc.Spec.Config.GetHttp().Response.GetDirect().ContentType,
		string(resp.Header().Get("Content-Type")))
	assert.Equal(t, svc.Spec.Config.GetHttp().Response.GetDirect().StatusCode, int32(resp.StatusCode()))
}

func TestJSONSchemaPlugin(t *testing.T) {

	const schema = `
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "User",
  "description": "A user in the system",
  "type": "object",
  "properties": {
    "id": {
      "description": "The unique identifier for the user",
      "type": "integer"
    },
    "username": {
      "description": "The user's username",
      "type": "string",
      "minLength": 3,
      "maxLength": 20,
      "pattern": "^[a-zA-Z0-9_]+$"
    },
    "email": {
      "description": "The user's email address",
      "type": "string",
      "format": "email"
    },
    "age": {
      "description": "Age in years",
      "type": "integer",
      "minimum": 13,
      "maximum": 120
    },
    "isActive": {
      "description": "Whether the user account is active",
      "type": "boolean",
      "default": true
    },
    "roles": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["admin", "editor", "viewer"]
      },
      "minItems": 1,
      "uniqueItems": true
    },
    "address": {
      "type": "object",
      "properties": {
        "street": { "type": "string" },
        "city": { "type": "string" },
        "state": { "type": "string" },
        "zip": { "type": "string", "pattern": "^\\d{5}(-\\d{4})?$" }
      },
      "required": ["street", "city", "zip"]
    }
  },
  "required": ["id", "username", "email"],
  "additionalProperties": false
}`

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstreamSrv.port),
					},
				},
				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						EnableRequestBuffering: true,
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
							{
								Name: "validation-1",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_JsonSchema{
									JsonSchema: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Inline{
											Inline: schema,
										},
										StatusCode: 417,
										Body: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Body{
											Type: &corev1.Service_Spec_Config_HTTP_Plugin_JSONSchema_Body_Inline{
												Inline: utilrand.GetRandomString(32),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().SetBody(map[string]any{
		"id":       utilrand.GetRandomStringCanonical(8),
		"username": utilrand.GetRandomStringCanonical(8),
		"email":    fmt.Sprintf("%s@example.com", utilrand.GetRandomStringCanonical(8)),
	}).
		Post(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsError())

	assert.Equal(t, svc.Spec.Config.GetHttp().Plugins[0].GetJsonSchema().Body.GetInline(), string(resp.Body()))
	assert.Equal(t, svc.Spec.Config.GetHttp().Plugins[0].GetJsonSchema().StatusCode, int32(resp.StatusCode()))
}

func TestHTTPSUpstream(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://raw.githubusercontent.com",
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().
		Get(fmt.Sprintf("http://localhost:%d/octelium/octelium/refs/heads/main/unsorted/latest_release", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())

	resp2, err := resty.New().SetDebug(true).R().
		Get("https://raw.githubusercontent.com/octelium/octelium/refs/heads/main/unsorted/latest_release")
	assert.Nil(t, err)

	assert.Equal(t, resp.Body(), resp2.Body())
}

func TestLua(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},

				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
							{
								Name: "lua-1",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
									Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
											Inline: `
function onResponse(ctx)
  octelium.req.setResponseHeader("Content-Encoding", "application/json")
  octelium.req.setResponseBody(json.encode(ctx.user))
  octelium.req.setStatusCode(218)
end
																`,
										},
									},
								},
							},
						},
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)
	resp, err := resty.New().SetDebug(true).R().
		Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())
	assert.Equal(t, 218, resp.StatusCode())

}

func TestLua2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},

				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
							{
								Name: "lua-1",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
									Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
											Inline: `
function onRequest(ctx)
  if strings.hasSuffix(ctx.request.http.path, ".php") then
    local resp = {}
	resp.uid = ctx.user.metadata.uid
	octelium.req.setResponseBody(json.encode(resp))
    octelium.req.exit(400)
  end
end
																`,
										},
									},
								},
							},
						},
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())

	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d/page.php", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)

		res := make(map[string]any)
		err = json.Unmarshal(resp.Body(), &res)
		assert.Nil(t, err)
		assert.Equal(t, 400, resp.StatusCode())

		assert.Equal(t, usr.Usr.Metadata.Uid, res["uid"].(string))
	}

}

func TestLuaMultiple(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}
	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},

				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
							{
								Name: "lua-1",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
									Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
											Inline: `
function onResponse(ctx)
  octelium.req.setResponseHeader("X-Custom-Resp", "lua-1")
  octelium.req.setStatusCode(206)
end
																`,
										},
									},
								},
							},
							{
								Name: "lua-2",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_{
									Lua: &corev1.Service_Spec_Config_HTTP_Plugin_Lua{
										Type: &corev1.Service_Spec_Config_HTTP_Plugin_Lua_Inline{
											Inline: `
function onResponse(ctx)
  octelium.req.setResponseHeader("X-Custom-Resp", "lua-2")
  octelium.req.setStatusCode(207)
end
																`,
										},
									},
								},
							},
						},
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())

		assert.Equal(t, 207, resp.StatusCode())
		assert.Equal(t, "lua-2", resp.Header().Get("X-Custom-Resp"))
	}

}

func TestRateLimitPlugin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://www.google.com",
					},
				},

				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Plugins: []*corev1.Service_Spec_Config_HTTP_Plugin{
							{
								Name: "rl-1",
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
								Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_{
									RateLimit: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit{
										Limit: 2,
										Window: &metav1.Duration{
											Type: &metav1.Duration_Seconds{
												Seconds: 3,
											},
										},
									},
								},
							},
						},
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)
	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsError())
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode())
	}

	time.Sleep(4 * time.Second)
	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsSuccess())
	}

	{
		resp, err := resty.New().SetDebug(true).R().
			Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.IsError())
		assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode())
	}
}

func TestRetry(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	upstreamPort := tests.GetPort()

	upstreamSrv := newSrvHTTP(t, upstreamPort, true, nil)
	upstreamSrv.wait = 3 * time.Second
	upstreamSrv.run(t)

	{
		cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
		assert.Nil(t, err)

		cc.Status.Network.ClusterNetwork = &metav1.DualStackNetwork{
			V4: "127.0.0.0/8",
			V6: "::1/128",
		}
		_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
		assert.Nil(t, err)
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			IsPublic: true,
			Port:     uint32(tests.GetPort()),
			Mode:     corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("http://localhost:%d", upstreamSrv.port),
					},
				},
				Type: &corev1.Service_Spec_Config_Http{
					Http: &corev1.Service_Spec_Config_HTTP{
						Retry: &corev1.Service_Spec_Config_HTTP_Retry{
							MaxElapsedTime: &metav1.Duration{
								Type: &metav1.Duration_Seconds{
									Seconds: 9,
								},
							},
						},
					},
				},
			},
			Authorization: &corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
								{
									Effect: corev1.Policy_Spec_Rule_ALLOW,
									Condition: &corev1.Condition{
										Type: &corev1.Condition_MatchAny{
											MatchAny: true,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svcV)

	octovigilC, err := octovigilc.NewClient(ctx, &octovigilc.Opts{
		VCache:    vCache,
		OcteliumC: fakeC.OcteliumC,
	})
	assert.Nil(t, err)

	secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
	assert.Nil(t, err)

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		LBManager:  loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
	})
	assert.Nil(t, err)
	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	err = usr.Connect()
	assert.Nil(t, err, "%+v", err)

	usr.Session.Status.Connection = &corev1.Session_Status_Connection{
		Addresses: []*metav1.DualStackNetwork{
			{
				V4: "127.0.0.1/32",
				V6: "::1/128",
			},
		},
		Type:   corev1.Session_Status_Connection_WIREGUARD,
		L3Mode: corev1.Session_Status_Connection_V4,
	}

	usr.Session, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, usr.Session)
	assert.Nil(t, err)
	usr.Resync()

	srv.octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	resp, err := resty.New().SetDebug(true).R().
		Get(fmt.Sprintf("http://localhost:%d", ucorev1.ToService(svcV).RealPort()))
	assert.Nil(t, err, "%+v", err)
	assert.True(t, resp.IsSuccess())

	assert.Equal(t, http.StatusOK, resp.StatusCode())
}
