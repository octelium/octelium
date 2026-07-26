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

package user

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestConnect(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)
	{
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
		assert.Nil(t, err)

		usrT.Resync()

		_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
		assert.Nil(t, err)

		_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
		assert.Nil(t, err, "%+v", err)

		usrT.Resync()

		svc1, err := adminSrv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},

						User: usrT.Usr.Metadata.Name,
					},
				},
			},
		})
		assert.Nil(t, err)

		svc2, err := adminSrv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com:8443",
						},

						User: usrT.Usr.Metadata.Name,
					},
				},
			},
		})
		assert.Nil(t, err)

		resp, err := usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ServiceOptions: &userv1.ConnectRequest_Initialize_ServiceOptions{
				ServeAll: true,
			},
		})
		assert.Nil(t, err)

		assert.NotNil(t, resp.GetState())

		assert.Equal(t, 2, len(resp.GetState().ServiceOptions.Services))

		assert.Equal(t, svc1.Metadata.Name, resp.GetState().ServiceOptions.Services[0].Name)
		assert.Equal(t, svc2.Metadata.Name, resp.GetState().ServiceOptions.Services[1].Name)
	}

}

func TestDoInitConnectL3Mode(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	getSess := func(uid string) *corev1.Session {
		sess, err := tst.C.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: uid})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	tcs := []struct {
		req      userv1.ConnectRequest_Initialize_L3Mode
		expected corev1.Session_Status_Connection_L3Mode
		state    userv1.ConnectionState_L3Mode
	}{
		{
			req:      userv1.ConnectRequest_Initialize_BOTH,
			expected: corev1.Session_Status_Connection_BOTH,
			state:    userv1.ConnectionState_BOTH,
		},
		{
			req:      userv1.ConnectRequest_Initialize_V4,
			expected: corev1.Session_Status_Connection_V4,
			state:    userv1.ConnectionState_V4,
		},
		{
			req:      userv1.ConnectRequest_Initialize_V6,
			expected: corev1.Session_Status_Connection_V6,
			state:    userv1.ConnectionState_V6,
		},
	}

	for _, tc := range tcs {
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)

		resp, err := usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			L3Mode: tc.req,
		})
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, resp.GetState())
		assert.Equal(t, tc.state, resp.GetState().L3Mode)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.Equal(t, tc.expected, sess.Status.Connection.L3Mode)
	}
}

func TestDoInitConnectType(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	getSess := func(uid string) *corev1.Session {
		sess, err := tst.C.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: uid})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	tcs := []struct {
		req      userv1.ConnectRequest_Initialize_ConnectionType
		expected corev1.Session_Status_Connection_Type
	}{
		{
			req:      userv1.ConnectRequest_Initialize_UNSET,
			expected: corev1.Session_Status_Connection_WIREGUARD,
		},
		{
			req:      userv1.ConnectRequest_Initialize_WIREGUARD,
			expected: corev1.Session_Status_Connection_WIREGUARD,
		},
		{
			req:      userv1.ConnectRequest_Initialize_QUICV0,
			expected: corev1.Session_Status_Connection_QUICV0,
		},
	}

	for _, tc := range tcs {
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)

		resp, err := usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ConnectionType: tc.req,
		})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, resp.GetState().Mtu > 0)
		assert.NotEmpty(t, resp.GetState().X25519Key)
		assert.NotEmpty(t, resp.GetState().Ed25519Key)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.Equal(t, tc.expected, sess.Status.Connection.Type)
		assert.NotEmpty(t, sess.Status.Connection.X25519PublicKey)
		assert.NotEmpty(t, sess.Status.Connection.Ed25519PublicKey)
	}
}

func TestDoInitConnectEmbeddedServers(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	getSess := func(uid string) *corev1.Session {
		sess, err := tst.C.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: uid})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	newUsr := func() *tstuser.User {
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)
		return usrT
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ESSHEnable: true,
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.True(t, sess.Status.Connection.ESSHEnable)
		assert.Equal(t, int32(22022), sess.Status.Connection.ESSHPort)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ESSHEnable: true,
			ESSHPort:   2222,
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.Equal(t, int32(2222), sess.Status.Connection.ESSHPort)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ESSHPort: 2222,
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.False(t, sess.Status.Connection.ESSHEnable)
		assert.Equal(t, int32(0), sess.Status.Connection.ESSHPort)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ESSHEnable: true,
			ESSHPort:   70000,
		})
		assert.NotNil(t, err)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ESOCKS5Enable: true,
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.True(t, sess.Status.Connection.ESOCKS5Enable)
		assert.Equal(t, int32(1080), sess.Status.Connection.ESOCKS5Port)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ESOCKS5Enable: true,
			ESOCKS5Port:   1085,
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.Equal(t, int32(1085), sess.Status.Connection.ESOCKS5Port)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ESOCKS5Enable: true,
			ESOCKS5Port:   70000,
		})
		assert.NotNil(t, err)
	}
}

func TestDoInitConnectServiceOptions(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	getSess := func(uid string) *corev1.Session {
		sess, err := tst.C.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: uid})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	newUsr := func() *tstuser.User {
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)
		return usrT
	}

	newHostedSvc := func(user string) *corev1.Service {
		svc, err := adminSrv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						User: user,
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://example.com",
						},
					},
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
		return svc
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ServiceOptions: &userv1.ConnectRequest_Initialize_ServiceOptions{
				ServeAll: true,
			},
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.True(t, sess.Status.Connection.ServiceOptions.ServeAll)
		assert.Equal(t, int32(23000), sess.Status.Connection.ServiceOptions.PortStart)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ServiceOptions: &userv1.ConnectRequest_Initialize_ServiceOptions{
				ServeAll:  true,
				PortStart: 25000,
			},
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.Equal(t, int32(25000), sess.Status.Connection.ServiceOptions.PortStart)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ServiceOptions: &userv1.ConnectRequest_Initialize_ServiceOptions{
				PortStart: 70000,
			},
		})
		assert.NotNil(t, err)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.Nil(t, sess.Status.Connection.ServiceOptions)
	}

	{
		usrT := newUsr()
		var svcs []*userv1.ConnectRequest_Initialize_ServiceOptions_Service
		for i := 0; i < 257; i++ {
			svcs = append(svcs, &userv1.ConnectRequest_Initialize_ServiceOptions_Service{
				Name: utilrand.GetRandomStringCanonical(8),
			})
		}

		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ServiceOptions: &userv1.ConnectRequest_Initialize_ServiceOptions{
				Services: svcs,
			},
		})
		assert.NotNil(t, err)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ServiceOptions: &userv1.ConnectRequest_Initialize_ServiceOptions{
				Services: []*userv1.ConnectRequest_Initialize_ServiceOptions_Service{
					{Name: utilrand.GetRandomStringCanonical(8)},
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.Equal(t, 0, len(sess.Status.Connection.ServiceOptions.RequestedServices))
	}

	{
		usrT := newUsr()
		svc1 := newHostedSvc(usrT.Usr.Metadata.Name)
		newHostedSvc(usrT.Usr.Metadata.Name)

		resp, err := usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ServiceOptions: &userv1.ConnectRequest_Initialize_ServiceOptions{
				Services: []*userv1.ConnectRequest_Initialize_ServiceOptions_Service{
					{Name: svc1.Metadata.Name},
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.Equal(t, 1, len(sess.Status.Connection.ServiceOptions.RequestedServices))
		assert.Equal(t, svc1.Metadata.Uid,
			sess.Status.Connection.ServiceOptions.RequestedServices[0].ServiceRef.Uid)

		assert.NotNil(t, resp.GetState().ServiceOptions)
		assert.Equal(t, 1, len(resp.GetState().ServiceOptions.Services))
		assert.Equal(t, svc1.Metadata.Name, resp.GetState().ServiceOptions.Services[0].Name)
	}

	{
		usrT := newUsr()
		svc1 := newHostedSvc(usrT.Usr.Metadata.Name)
		svc2 := newHostedSvc(usrT.Usr.Metadata.Name)

		resp, err := usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			ServiceOptions: &userv1.ConnectRequest_Initialize_ServiceOptions{
				ServeAll: true,
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, len(resp.GetState().ServiceOptions.Services))

		names := []string{}
		for _, itm := range resp.GetState().ServiceOptions.Services {
			names = append(names, itm.Name)
			assert.True(t, itm.Port > 0)
		}
		assert.Contains(t, names, svc1.Metadata.Name)
		assert.Contains(t, names, svc2.Metadata.Name)
	}
}

func TestDoInitConnectPublishedServices(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	getSess := func(uid string) *corev1.Session {
		sess, err := tst.C.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: uid})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	newUsr := func() *tstuser.User {
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)
		return usrT
	}

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},
			},
		},
	})
	assert.Nil(t, err, "%+v", err)

	invalids := []*userv1.ConnectRequest_Initialize_PublishedService{
		{
			Name: svc.Metadata.Name,
			Port: 0,
		},
		{
			Name: svc.Metadata.Name,
			Port: 70000,
		},
		{
			Name:    svc.Metadata.Name,
			Port:    8080,
			Address: "not-an-ip",
		},
	}

	for _, published := range invalids {
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			PublishedServices: []*userv1.ConnectRequest_Initialize_PublishedService{published},
		})
		assert.NotNil(t, err, "%+v", published)
	}

	{
		usrT := newUsr()
		var published []*userv1.ConnectRequest_Initialize_PublishedService
		for i := 0; i < 129; i++ {
			published = append(published, &userv1.ConnectRequest_Initialize_PublishedService{
				Name: svc.Metadata.Name,
				Port: 8080,
			})
		}

		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			PublishedServices: published,
		})
		assert.NotNil(t, err)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			PublishedServices: []*userv1.ConnectRequest_Initialize_PublishedService{
				{
					Name: utilrand.GetRandomStringCanonical(8),
					Port: 8080,
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.Equal(t, 0, len(sess.Status.Connection.PublishedServices))
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			PublishedServices: []*userv1.ConnectRequest_Initialize_PublishedService{
				{
					Name: svc.Metadata.Name,
					Port: 8080,
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.Equal(t, 1, len(sess.Status.Connection.PublishedServices))
		assert.Equal(t, int32(8080), sess.Status.Connection.PublishedServices[0].Port)
		assert.Equal(t, "localhost", sess.Status.Connection.PublishedServices[0].Address)
		assert.Equal(t, svc.Metadata.Uid, sess.Status.Connection.PublishedServices[0].ServiceRef.Uid)
	}

	{
		usrT := newUsr()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			PublishedServices: []*userv1.ConnectRequest_Initialize_PublishedService{
				{
					Name:    svc.Metadata.Name,
					Port:    9090,
					Address: "10.0.0.5",
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.Equal(t, "10.0.0.5", sess.Status.Connection.PublishedServices[0].Address)
	}
}

func TestDoInitConnectSessionStatus(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err, "%+v", err)

	getSess := func() *corev1.Session {
		sess, err := tst.C.OcteliumC.CoreC().GetSession(ctx,
			&rmetav1.GetOptions{Uid: usrT.Session.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	{
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{
			IgnoreDNS: true,
		})
		assert.Nil(t, err, "%+v", err)

		sess := getSess()
		assert.True(t, sess.Status.IsConnected)
		assert.True(t, sess.Status.Connection.IgnoreDNS)
		assert.NotNil(t, sess.Status.Connection.StartedAt)
		assert.Equal(t, uint32(1), sess.Status.TotalConnections)
		assert.True(t, len(sess.Status.Connection.Addresses) > 0)
	}

	{
		usrT.Resync()
		_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
		assert.Nil(t, err, "%+v", err)

		usrT.Resync()
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
		assert.Nil(t, err, "%+v", err)

		sess := getSess()
		assert.Equal(t, uint32(2), sess.Status.TotalConnections)
		assert.False(t, sess.Status.Connection.IgnoreDNS)
	}
}

func TestCheckIfCanConnect(t *testing.T) {
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	{
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)

		i, err := userctx.GetUserCtx(usrT.Ctx())
		assert.Nil(t, err, "%+v", err)
		assert.Nil(t, checkIfCanConnect(i))
	}

	{
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err, "%+v", err)

		i, err := userctx.GetUserCtx(usrT.Ctx())
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, checkIfCanConnect(i))
	}

	{
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_WORKLOAD, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)

		i, err := userctx.GetUserCtx(usrT.Ctx())
		assert.Nil(t, err, "%+v", err)
		assert.Nil(t, checkIfCanConnect(i))
	}
}

func TestDisconnectStatus(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err, "%+v", err)

	getSess := func() *corev1.Session {
		sess, err := tst.C.OcteliumC.CoreC().GetSession(ctx,
			&rmetav1.GetOptions{Uid: usrT.Session.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	{
		usrT.Resync()
		_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
		assert.Nil(t, err, "%+v", err)

		sess := getSess()
		assert.False(t, sess.Status.IsConnected)
		assert.Nil(t, sess.Status.Connection)
		assert.Equal(t, 0, len(sess.Status.LastConnections))
	}

	{
		_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
		assert.Nil(t, err, "%+v", err)

		usrT.Resync()
		_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
		assert.Nil(t, err, "%+v", err)

		sess := getSess()
		assert.False(t, sess.Status.IsConnected)
		assert.Nil(t, sess.Status.Connection)
		assert.Equal(t, 1, len(sess.Status.LastConnections))
		assert.NotNil(t, sess.Status.LastConnections[0].StartedAt)
		assert.NotNil(t, sess.Status.LastConnections[0].EndedAt)
	}

	{
		usrT.Resync()
		_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
		assert.Nil(t, err, "%+v", err)

		sess := getSess()
		assert.Equal(t, 1, len(sess.Status.LastConnections))
	}

	{
		for i := 0; i < 3; i++ {
			usrT.Resync()
			_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
			assert.Nil(t, err, "%+v", err)

			usrT.Resync()
			_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
			assert.Nil(t, err, "%+v", err)
		}

		sess := getSess()
		assert.Equal(t, 4, len(sess.Status.LastConnections))
		assert.Equal(t, uint32(4), sess.Status.TotalConnections)
	}
}

func TestDisconnectInvalidSessionType(t *testing.T) {
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
	assert.Nil(t, err, "%+v", err)

	_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
	assert.NotNil(t, err)
}

func TestDisconnectRemovedSession(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err, "%+v", err)

	_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
	assert.Nil(t, err, "%+v", err)

	usrT.Resync()

	_, err = tst.C.OcteliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{
		Uid: usrT.Session.Metadata.Uid,
	})
	assert.Nil(t, err, "%+v", err)

	_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
	assert.NotNil(t, err)
}
