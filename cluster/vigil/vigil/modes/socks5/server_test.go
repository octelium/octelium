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
	"fmt"
	"net"
	"testing"
	"time"

	"context"

	gosocks5 "github.com/things-go/go-socks5"
	xproxy "golang.org/x/net/proxy"

	"github.com/octelium/octelium/apis/main/corev1"
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
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

type echoServer struct {
	lis net.Listener
}

func newEchoServer(t *testing.T, port int) *echoServer {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	assert.Nil(t, err)

	s := &echoServer{lis: lis}

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return s
}

func (s *echoServer) close() {
	if s.lis != nil {
		s.lis.Close()
	}
}

type upstreamProxy struct {
	lis net.Listener
}

func newUpstreamProxy(t *testing.T, port int) *upstreamProxy {
	srv := gosocks5.NewServer(
		gosocks5.WithAuthMethods([]gosocks5.Authenticator{
			gosocks5.NoAuthAuthenticator{},
		}),
	)

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	assert.Nil(t, err)

	p := &upstreamProxy{lis: lis}

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go srv.ServeConn(conn)
		}
	}()

	return p
}

func (p *upstreamProxy) close() {
	if p.lis != nil {
		p.lis.Close()
	}
}

func socks5Dial(t *testing.T, proxyPort int, target string) (net.Conn, error) {
	dialer, err := xproxy.SOCKS5("tcp", fmt.Sprintf("localhost:%d", proxyPort), nil, xproxy.Direct)
	assert.Nil(t, err)
	return dialer.Dial("tcp", target)
}

func roundTrip(t *testing.T, conn net.Conn) {
	msg := utilrand.GetRandomBytesMust(32)

	_, err := conn.Write(msg)
	assert.Nil(t, err)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, msg, buf[:n])
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

	targetPort := tests.GetPort()
	targetSrv := newEchoServer(t, targetPort)
	defer targetSrv.close()

	upstreamPort := tests.GetPort()
	upstreamSrv := newUpstreamProxy(t, upstreamPort)
	defer upstreamSrv.close()

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			Port: uint32(tests.GetPort()),
			Mode: corev1.Service_Spec_SOCKS5,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("socks5://localhost:%d", upstreamPort),
					},
				},
				Type: &corev1.Service_Spec_Config_Socks5{
					Socks5: &corev1.Service_Spec_Config_SOCKS5{},
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

	srv, err := New(ctx, &modes.Opts{
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

	{
		conn, err := socks5Dial(t, int(svc.Spec.Port), fmt.Sprintf("localhost:%d", targetPort))
		assert.NotNil(t, err)
		if conn != nil {
			conn.Close()
		}
	}

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

	{
		conn, err := socks5Dial(t, int(svc.Spec.Port), fmt.Sprintf("localhost:%d", targetPort))
		assert.Nil(t, err, "%+v", err)
		roundTrip(t, conn)
		err = conn.Close()
		assert.Nil(t, err)
	}

	{
		conn, err := socks5Dial(t, int(svc.Spec.Port), fmt.Sprintf("127.0.0.1:%d", targetPort))
		assert.Nil(t, err, "%+v", err)
		roundTrip(t, conn)
		err = conn.Close()
		assert.Nil(t, err)
	}

	{
		conn, err := socks5Dial(t, int(svc.Spec.Port), fmt.Sprintf("localhost:%d", targetPort))
		assert.Nil(t, err, "%+v", err)
		for i := 0; i < 8; i++ {
			roundTrip(t, conn)
		}
		err = conn.Close()
		assert.Nil(t, err)
	}

	{
		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `ctx.request.socks5.connect.host == "blocked.example.com"`,
									},
								},
								Effect: corev1.Policy_Spec_Rule_DENY,
							},
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
		}

		svc, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svc)
		assert.Nil(t, err)
		vCache.SetService(svc)

		time.Sleep(1 * time.Second)

		{
			conn, err := socks5Dial(t, int(svc.Spec.Port), "blocked.example.com:80")
			assert.NotNil(t, err)
			if conn != nil {
				conn.Close()
			}
		}

		{
			conn, err := socks5Dial(t, int(svc.Spec.Port), fmt.Sprintf("localhost:%d", targetPort))
			assert.Nil(t, err, "%+v", err)
			roundTrip(t, conn)
			err = conn.Close()
			assert.Nil(t, err)
		}
	}

	err = srv.Close()
	assert.Nil(t, err)
}
