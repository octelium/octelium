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
	"fmt"
	"io"
	"net"
	"testing"
	"time"

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

type tstSrv struct {
	lis  net.Listener
	port int
}

func newTestServer(port int) *tstSrv {
	return &tstSrv{port: port}
}

func (s *tstSrv) run(t *testing.T) {
	var err error
	s.lis, err = net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	assert.Nil(t, err)

	go func() {
		for {
			conn, err := s.lis.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()

				_, err := ReadTPKT(conn)
				if err != nil {
					return
				}

				_, err = conn.Write([]byte{
					0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02,
					0x00, 0x00, 0x00,
				})
				if err != nil {
					return
				}

				io.Copy(conn, conn)
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

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			Port: uint32(tests.GetPort()),
			Mode: corev1.Service_Spec_RDP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("rdp://localhost:%d", upstreamPort),
					},
				},
				Type: &corev1.Service_Spec_Config_Rdp{
					Rdp: &corev1.Service_Spec_Config_RDP{},
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
	assert.Nil(t, srv.Run(ctx))
	defer srv.Close()

	time.Sleep(1 * time.Second)

	{
		conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", svc.Spec.Port))
		assert.Nil(t, err)

		_, err = conn.Write(buildX224ConnectionRequest(protocolSSL | protocolHybrid))
		assert.Nil(t, err)

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, io.EOF, err)
		conn.Close()
	}

	usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err)
	assert.Nil(t, usr.Connect())

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

	conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", svc.Spec.Port))
	assert.Nil(t, err)

	clientX224 := buildX224ConnectionRequest(protocolSSL | protocolHybrid)
	_, err = conn.Write(clientX224)
	assert.Nil(t, err)

	serverX224, err := ReadTPKT(conn)
	assert.Nil(t, err)
	selected, ok := rdpConfirmSelectedProtocol(serverX224)
	assert.True(t, ok)
	assert.Equal(t, protocolHybrid, selected)

	msg := utilrand.GetRandomBytesMust(32)
	_, err = conn.Write(msg)
	assert.Nil(t, err)

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	assert.Nil(t, err)
	assert.Equal(t, msg, buf)
	assert.Nil(t, conn.Close())
}
