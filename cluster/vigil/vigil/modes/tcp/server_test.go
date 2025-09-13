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

package tcp

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	v1 "github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
)

type tstSrv struct {
	lis  net.Listener
	port int

	crt    *tls.Certificate
	caPool *x509.CertPool
}

func newTestServer(port int) *tstSrv {

	return &tstSrv{
		port: port,
	}
}

func (s *tstSrv) run(t *testing.T) {

	var err error
	if s.crt != nil {

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{*s.crt},
		}
		if s.caPool != nil {
			tlsCfg.RootCAs = s.caPool
		}
		s.lis, err = tls.Listen("tcp", fmt.Sprintf(":%d", s.port), tlsCfg)
		assert.Nil(t, err)
	} else {
		s.lis, err = net.Listen("tcp", fmt.Sprintf(":%d", s.port))
		assert.Nil(t, err)
	}

	go func() {
		for {
			conn, err := s.lis.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				for {
					buf := make([]byte, 4096)
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					conn.Write(buf[:n])
				}
			}(conn)

		}
	}()
}

func (s *tstSrv) close() {
	if s.lis != nil {
		s.lis.Close()
	}
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

	upstreamSrv := newTestServer(upstreamPort)
	upstreamSrv.run(t)
	defer upstreamSrv.close()

	svc, err := adminSrv.CreateService(ctx, &v1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &v1.Service_Spec{
			Port: uint32(tests.GetPort()),
			Mode: corev1.Service_Spec_TCP,
			Config: &v1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("tcp://localhost:%d", upstreamPort),
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

	/*
		logManager, err := logmanager.NewLogManager(ctx, &logmanager.LogManagerOpts{})
		assert.Nil(t, err)
		metricsStore, err := metricsstore.NewMetricsStore(ctx, nil)
		assert.Nil(t, err)
	*/

	srv, err := New(ctx, &modes.Opts{
		OcteliumC:  fakeC.OcteliumC,
		VCache:     vCache,
		OctovigilC: octovigilC,
		SecretMan:  secretMan,
		// LogManager:   logManager,
		LBManager: loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
		// MetricsStore: metricsStore,
	})
	assert.Nil(t, err)
	err = srv.Run(ctx)
	assert.Nil(t, err)

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

	octovigilC.GetCache().SetSession(usr.Session)
	usr.Resync()

	time.Sleep(1 * time.Second)

	c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", svc.Spec.Port))
	assert.Nil(t, err)

	msg := utilrand.GetRandomBytesMust(32)

	_, err = c.Write(msg)
	assert.Nil(t, err)

	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, msg, buf[:n])
	err = c.Close()
	assert.Nil(t, err)

	time.Sleep(2 * time.Second)
	err = srv.Close()
	assert.Nil(t, err)

	{
		// test mTLS
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
		upstreamSrv.crt = &srvCert
		srvCaPool := x509.NewCertPool()
		ok := srvCaPool.AppendCertsFromPEM(root.MustGetCertPEM())
		assert.True(t, ok)
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

		secReq := &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(6),
			},
			Spec: &corev1.Secret_Spec{},
		}
		ucorev1.ToSecret(secReq).SetCertificate(
			string(clientCrt.MustGetCertPEM()),
			string(clientCrt.MustGetPrivateKeyPEM()))

		sec, err := adminSrv.CreateSecret(ctx, secReq)
		assert.Nil(t, err)

		svc.Spec.Config.ClientCertificate = &corev1.Service_Spec_Config_ClientCertificate{

			Type: &corev1.Service_Spec_Config_ClientCertificate_FromSecret{
				FromSecret: sec.Metadata.Name,
			},

			TrustedCAs: []string{
				string(root.MustGetCertPEM()),
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		svcV, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		vCache.SetService(svcV)

		secretMan, err := secretman.New(ctx, fakeC.OcteliumC, vCache)
		assert.Nil(t, err)

		/*
			logManager, err := logmanager.NewLogManager(ctx, &logmanager.LogManagerOpts{})
			assert.Nil(t, err)

			metricsStore, err := metricsstore.NewMetricsStore(ctx, nil)
			assert.Nil(t, err)
		*/

		srv, err = New(ctx, &modes.Opts{
			OcteliumC:  fakeC.OcteliumC,
			VCache:     vCache,
			OctovigilC: octovigilC,
			SecretMan:  secretMan,
			// LogManager:   logManager,
			LBManager: loadbalancer.NewLbManager(fakeC.OcteliumC, vCache),
			// MetricsStore: metricsStore,
		})
		assert.Nil(t, err)
		err = srv.Run(ctx)
		assert.Nil(t, err)

		time.Sleep(1 * time.Second)

		c, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", svc.Spec.Port))
		assert.Nil(t, err)

		msg := utilrand.GetRandomBytesMust(32)

		_, err = c.Write(msg)
		assert.Nil(t, err)

		buf := make([]byte, 4096)
		n, err := c.Read(buf)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, msg, buf[:n])
		err = c.Close()
		assert.Nil(t, err)
	}
}
