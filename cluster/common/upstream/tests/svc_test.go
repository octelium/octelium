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

package upstreamtests

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/upstream"
	"github.com/stretchr/testify/assert"
)

func TestSetServiceUpstreams(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(fakeC.OcteliumC)

	t.Run("default", func(t *testing.T) {
		doTest := func() {
			usr, err := tstuser.NewUserWithType(fakeC.OcteliumC, adminSrv, usrSrv, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)

			network, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
			assert.Nil(t, err)

			svc := tests.GenService(network.Metadata.Name)

			svc.Spec.Config = &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{

					Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{
						Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{
							Endpoints: []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
								{
									Url:  "https://example.com",
									User: usr.Usr.Metadata.Name,
								},
							},
						},
					},
				},
			}
			svc.Spec.Port = 443

			svc, err = adminSrv.CreateService(ctx, svc)
			assert.Nil(t, err)

			svcK8s, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
				Name: svc.Metadata.Name,
			})
			assert.Nil(t, err)

			svcK8s.Status.Addresses = []*corev1.Service_Status_Address{
				{
					DualStackIP: &metav1.DualStackIP{
						Ipv4: "1.1.1.1",
						Ipv6: "::1",
					},
				},
			}

			svcK8s, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svcK8s)
			assert.Nil(t, err)

			conns, err := upstream.SetServiceUpstreams(ctx, fakeC.OcteliumC, svcK8s)
			assert.Nil(t, err)
			assert.Equal(t, 0, len(conns))

			err = usr.ConnectWithServeAll()
			assert.Nil(t, err, "%+v", err)

			conns, err = upstream.SetServiceUpstreams(ctx, fakeC.OcteliumC, svcK8s)
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, 1, len(conns))
			assert.Equal(t, usr.Session.Metadata.Uid, conns[0].Metadata.Uid)

			err = usr.ConnectWithServeAll()
			assert.Nil(t, err)

			conns, err = upstream.SetServiceUpstreams(ctx, fakeC.OcteliumC, svcK8s)
			assert.Nil(t, err)
			for _, conn := range conns {
				_, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, conn)
				assert.Nil(t, err)
			}

			assert.Equal(t, 1, len(conns))

			err = usr.Disconnect()
			assert.Nil(t, err, "%+v", err)
			conns, err = upstream.SetServiceUpstreams(ctx, fakeC.OcteliumC, svcK8s)
			for _, conn := range conns {
				_, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, conn)
				assert.Nil(t, err)
			}
			assert.Nil(t, err)
			assert.Equal(t, 0, len(conns))

			for i := 0; i < 10; i++ {
				tUsr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
				assert.Nil(t, err)
				err = tUsr.ConnectWithServeAll()
				assert.Nil(t, err)
				conns, err = upstream.SetServiceUpstreams(ctx, fakeC.OcteliumC, svcK8s)
				assert.Nil(t, err)
				assert.Equal(t, 0, len(conns))
			}

			svc.Spec.GetConfig().GetUpstream().GetLoadbalance().Endpoints[0].User = ""
			svc, err = adminSrv.UpdateService(ctx, svc)
			assert.Nil(t, err)
			svcK8s, err = fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
				Name: svc.Metadata.Name,
			})
			assert.Nil(t, err)

			conns, err = upstream.SetServiceUpstreams(ctx, fakeC.OcteliumC, svcK8s)
			assert.Nil(t, err)
			assert.Equal(t, 0, len(conns))
			for _, conn := range conns {
				_, err = fakeC.OcteliumC.CoreC().UpdateSession(ctx, conn)
				assert.Nil(t, err)
			}
		}

		ccStatuses := []*corev1.ClusterConfig_Status{
			{},
			{
				NetworkConfig: &corev1.ClusterConfig_Status_NetworkConfig{
					Mode: corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK,
				},
			},
			{
				NetworkConfig: &corev1.ClusterConfig_Status_NetworkConfig{
					Mode: corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY,
				},
			},
			{
				NetworkConfig: &corev1.ClusterConfig_Status_NetworkConfig{
					Mode: corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY,
				},
			},
		}

		for _, st := range ccStatuses {
			cc, err := fakeC.OcteliumC.CoreV1Utils().GetClusterConfig(ctx)
			assert.Nil(t, err)
			cc.Status.NetworkConfig = st.NetworkConfig
			_, err = fakeC.OcteliumC.CoreC().UpdateClusterConfig(ctx, cc)
			assert.Nil(t, err)
			doTest()
		}
	})

	t.Run("multi-session", func(t *testing.T) {
		usr, err := tstuser.NewUser(fakeC.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		network, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
		assert.Nil(t, err)

		svc := tests.GenService(network.Metadata.Name)

		svc.Spec.Config = &corev1.Service_Spec_Config{
			Upstream: &corev1.Service_Spec_Config_Upstream{

				Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{
					Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{
						Endpoints: []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
							{
								Url:  "https://example.com",
								User: usr.Usr.Metadata.Name,
							},
						},
					},
				},
			},
		}
		svc.Spec.Port = 443

		svc, err = adminSrv.CreateService(ctx, svc)
		assert.Nil(t, err)

		svcK8s, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
			Name: svc.Metadata.Name,
		})
		assert.Nil(t, err)

		svcK8s.Status.Addresses = []*corev1.Service_Status_Address{
			{
				DualStackIP: &metav1.DualStackIP{
					Ipv4: "1.1.1.1",
					Ipv6: "::1",
				},
			},
		}

		svcK8s, err = fakeC.OcteliumC.CoreC().UpdateService(ctx, svcK8s)
		assert.Nil(t, err)

		/*

			for i := 0; i < 10; i++ {

				sess, err := usr.NewSession()
				assert.Nil(t, err)


				err = usr.ConnectWithServeAll()
				assert.Nil(t, err)
				svcK8s, err = fakeC.OcteliumC.CoreC().GetService(context.Background(), &rmetav1.GetOptions{Uid: svcK8s.Metadata.Uid})
				assert.Nil(t, err)
				conns, err := upstream.SetServiceUpstreams(context.Background(), fakeC.OcteliumC, svcK8s)
				assert.Nil(t, err)
				assert.Equal(t, 1+i, len(conns))
			}

		*/

	})

}
