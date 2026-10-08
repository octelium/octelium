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
	"io"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cclusterv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func TestDoDisconnectConnection(t *testing.T) {
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
		sess, err := tst.C.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: usrT.Session.Metadata.Uid,
		})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	_, oldConn, err := usrSrv.doInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, oldConn)

	usrT.Resync()
	oldCtx, err := userctx.GetUserCtx(usrT.Ctx())
	assert.Nil(t, err, "%+v", err)

	_, err = usrSrv.doDisconnect(usrT.Ctx(), oldCtx)
	assert.Nil(t, err, "%+v", err)

	usrT.Resync()
	_, newConn, err := usrSrv.doInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, newConn)
	assert.False(t, isSameConnection(oldConn, newConn))

	resourceVersion := getSess().Metadata.ResourceVersion

	_, err = usrSrv.doDisconnectConnection(ctx, oldCtx, oldConn)
	assert.Nil(t, err, "%+v", err)

	sess := getSess()
	assert.True(t, sess.Status.IsConnected)
	assert.NotNil(t, sess.Status.Connection)
	assert.True(t, isSameConnection(sess.Status.Connection, newConn))
	assert.Equal(t, resourceVersion, sess.Metadata.ResourceVersion)

	usrT.Resync()
	newCtx, err := userctx.GetUserCtx(usrT.Ctx())
	assert.Nil(t, err, "%+v", err)

	_, err = usrSrv.doDisconnectConnection(ctx, newCtx, newConn)
	assert.Nil(t, err, "%+v", err)

	sess = getSess()
	assert.False(t, sess.Status.IsConnected)
	assert.Nil(t, sess.Status.Connection)
}

type failingCoreC struct {
	rcorev1.ResourceServiceClient

	mu               sync.Mutex
	updateSessionErr error
	getServiceFn     func() error
}

func (c *failingCoreC) setErrs(updateSessionErr, getServiceErr error) {
	c.setHooks(updateSessionErr, func() error {
		return getServiceErr
	})
}

func (c *failingCoreC) setHooks(updateSessionErr error, getServiceFn func() error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateSessionErr = updateSessionErr
	c.getServiceFn = getServiceFn
}

func (c *failingCoreC) UpdateSession(ctx context.Context,
	in *corev1.Session, opts ...grpc.CallOption) (*corev1.Session, error) {
	c.mu.Lock()
	err := c.updateSessionErr
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}

	return c.ResourceServiceClient.UpdateSession(ctx, in, opts...)
}

func (c *failingCoreC) GetService(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Service, error) {
	c.mu.Lock()
	fn := c.getServiceFn
	c.mu.Unlock()
	if fn != nil && in.Name == "dns.octelium" {
		if err := fn(); err != nil {
			return nil, err
		}
	}

	return c.ResourceServiceClient.GetService(ctx, in, opts...)
}

type failingOcteliumC struct {
	octeliumc.ClientInterface
	coreC *failingCoreC
}

func (c *failingOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

func TestDoInitConnectReleaseAddresses(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	coreC := &failingCoreC{
		ResourceServiceClient: tst.C.OcteliumC.CoreC(),
	}
	octeliumC := &failingOcteliumC{
		ClientInterface: tst.C.OcteliumC,
		coreC:           coreC,
	}

	usrSrv := NewServer(octeliumC)
	_, adminSrv := newFakeServers(tst.C)

	getActiveIndexes := func() []uint32 {
		cfg, err := tst.C.OcteliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: "sys:conn-info"})
		assert.Nil(t, err, "%+v", err)

		ret := &cclusterv1.ClusterConnInfo{}
		err = pbutils.StructToMessage(cfg.Data.GetAttrs(), ret)
		assert.Nil(t, err, "%+v", err)
		return append(ret.ActiveIndexesWG, ret.ActiveIndexesQUIC...)
	}

	tcs := []struct {
		name             string
		updateSessionErr error
		getServiceErr    error
		isReleased       bool
	}{
		{
			name:             "resource-changed",
			updateSessionErr: status.Error(codes.OutOfRange, "changed"),
			isReleased:       true,
		},
		{
			name:             "not-found",
			updateSessionErr: status.Error(codes.NotFound, "removed"),
			isReleased:       true,
		},
		{
			name:          "connection-state",
			getServiceErr: status.Error(codes.Internal, "internal"),
			isReleased:    true,
		},
		{
			name:             "unavailable",
			updateSessionErr: status.Error(codes.Unavailable, "unavailable"),
			isReleased:       false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err, "%+v", err)

			before := getActiveIndexes()

			coreC.setErrs(tc.updateSessionErr, tc.getServiceErr)
			_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
			coreC.setErrs(nil, nil)
			assert.NotNil(t, err)

			after := getActiveIndexes()
			if tc.isReleased {
				assert.ElementsMatch(t, before, after)
			} else {
				assert.Equal(t, len(before)+1, len(after))
			}

			sess, err := tst.C.OcteliumC.CoreC().GetSession(ctx,
				&rmetav1.GetOptions{Uid: usrT.Session.Metadata.Uid})
			assert.Nil(t, err, "%+v", err)
			assert.False(t, sess.Status.IsConnected)
			assert.Nil(t, sess.Status.Connection)
		})
	}

	{
		usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err, "%+v", err)

		before := getActiveIndexes()

		_, conn, err := usrSrv.doInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(conn.Addresses))
		assert.Equal(t, len(before)+1, len(getActiveIndexes()))
	}
}

func TestDoInitConnectCanceledContext(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	coreC := &failingCoreC{
		ResourceServiceClient: tst.C.OcteliumC.CoreC(),
	}
	octeliumC := &failingOcteliumC{
		ClientInterface: tst.C.OcteliumC,
		coreC:           coreC,
	}

	usrSrv := NewServer(octeliumC)
	_, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err, "%+v", err)

	reqCtx, cancel := context.WithCancel(usrT.Ctx())
	defer cancel()

	coreC.setHooks(nil, func() error {
		cancel()
		return status.Error(codes.Canceled, "canceled")
	})
	_, err = usrSrv.DoInitConnect(reqCtx, &userv1.ConnectRequest_Initialize{})
	coreC.setErrs(nil, nil)
	assert.NotNil(t, err)
	assert.NotNil(t, reqCtx.Err())

	cfg, err := tst.C.OcteliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: "sys:conn-info"})
	assert.Nil(t, err, "%+v", err)

	connInfo := &cclusterv1.ClusterConnInfo{}
	err = pbutils.StructToMessage(cfg.Data.GetAttrs(), connInfo)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 0, len(connInfo.ActiveIndexesWG))
}

func TestDisconnectReleaseAddresses(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	coreC := &failingCoreC{
		ResourceServiceClient: tst.C.OcteliumC.CoreC(),
	}
	octeliumC := &failingOcteliumC{
		ClientInterface: tst.C.OcteliumC,
		coreC:           coreC,
	}

	usrSrv := NewServer(octeliumC)
	_, adminSrv := newFakeServers(tst.C)

	getActiveIndexes := func() []uint32 {
		cfg, err := tst.C.OcteliumC.CoreC().GetConfig(ctx, &rmetav1.GetOptions{Name: "sys:conn-info"})
		assert.Nil(t, err, "%+v", err)

		ret := &cclusterv1.ClusterConnInfo{}
		err = pbutils.StructToMessage(cfg.Data.GetAttrs(), ret)
		assert.Nil(t, err, "%+v", err)
		return append(ret.ActiveIndexesWG, ret.ActiveIndexesQUIC...)
	}

	getSess := func(uid string) *corev1.Session {
		sess, err := tst.C.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{Uid: uid})
		assert.Nil(t, err, "%+v", err)
		return sess
	}

	usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err, "%+v", err)

	_, err = usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 1, len(getActiveIndexes()))

	{
		usrT.Resync()
		coreC.setErrs(status.Error(codes.OutOfRange, "changed"), nil)
		_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
		coreC.setErrs(nil, nil)
		assert.NotNil(t, err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.True(t, sess.Status.IsConnected)
		assert.Equal(t, 1, len(sess.Status.Connection.Addresses))
		assert.Equal(t, 1, len(getActiveIndexes()))
	}

	{
		usrT.Resync()
		reqCtx, cancel := context.WithCancel(usrT.Ctx())
		_, err = usrSrv.Disconnect(reqCtx, &userv1.DisconnectRequest{})
		cancel()
		assert.Nil(t, err, "%+v", err)

		sess := getSess(usrT.Session.Metadata.Uid)
		assert.False(t, sess.Status.IsConnected)
		assert.Nil(t, sess.Status.Connection)
		assert.Equal(t, 0, len(getActiveIndexes()))
	}
}

type fakeInitializeStream struct {
	grpc.ServerStream
	ctx   context.Context
	msgCh chan *userv1.ConnectRequest
	errCh chan error
}

func newFakeInitializeStream(ctx context.Context) *fakeInitializeStream {
	return &fakeInitializeStream{
		ctx:   ctx,
		msgCh: make(chan *userv1.ConnectRequest, 1),
		errCh: make(chan error, 1),
	}
}

func (s *fakeInitializeStream) Context() context.Context {
	return s.ctx
}

func (s *fakeInitializeStream) Send(msg *userv1.ConnectResponse) error {
	return nil
}

func (s *fakeInitializeStream) Recv() (*userv1.ConnectRequest, error) {
	select {
	case msg := <-s.msgCh:
		return msg, nil
	case err := <-s.errCh:
		return nil, err
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func TestRecvConnectInitialize(t *testing.T) {

	{
		stream := newFakeInitializeStream(context.Background())
		stream.msgCh <- &userv1.ConnectRequest{
			Type: &userv1.ConnectRequest_Initialize_{
				Initialize: &userv1.ConnectRequest_Initialize{
					L3Mode: userv1.ConnectRequest_Initialize_V6,
				},
			},
		}

		msg, err := recvConnectInitialize(stream, time.Second)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, userv1.ConnectRequest_Initialize_V6, msg.GetInitialize().L3Mode)
	}

	{
		stream := newFakeInitializeStream(context.Background())

		go func() {
			time.Sleep(50 * time.Millisecond)
			stream.msgCh <- &userv1.ConnectRequest{
				Type: &userv1.ConnectRequest_Initialize_{
					Initialize: &userv1.ConnectRequest_Initialize{},
				},
			}
		}()

		msg, err := recvConnectInitialize(stream, 5*time.Second)
		assert.Nil(t, err, "%+v", err)
		assert.NotNil(t, msg.GetInitialize())
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stream := newFakeInitializeStream(ctx)

		startedAt := time.Now()
		_, err := recvConnectInitialize(stream, 100*time.Millisecond)
		assert.NotNil(t, err)
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))
		assert.True(t, time.Since(startedAt) < 5*time.Second)
	}

	{
		ctx, cancel := context.WithCancel(context.Background())
		stream := newFakeInitializeStream(ctx)

		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		_, err := recvConnectInitialize(stream, time.Minute)
		assert.NotNil(t, err)
		assert.Equal(t, codes.Canceled, status.Code(err))
	}

	{
		stream := newFakeInitializeStream(context.Background())
		stream.errCh <- io.EOF

		_, err := recvConnectInitialize(stream, time.Minute)
		assert.NotNil(t, err)
	}
}

func TestGetLastSeenUpdateInterval(t *testing.T) {
	intervals := make(map[time.Duration]bool)
	for range 1000 {
		interval := getLastSeenUpdateInterval()
		assert.True(t, interval >= lastSeenUpdateInterval)
		assert.True(t, interval <= lastSeenUpdateInterval+lastSeenUpdateJitter)
		intervals[interval] = true
	}

	assert.True(t, len(intervals) > 1)
}

func TestSetConnectionLastSeen(t *testing.T) {
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

	_, oldConn, err := usrSrv.doInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, getSess().Status.Connection.LastSeenAt)

	isActive, err := usrSrv.setConnectionLastSeen(ctx, usrT.Session.Metadata.Uid, oldConn)
	assert.Nil(t, err, "%+v", err)
	assert.True(t, isActive)
	assert.NotNil(t, getSess().Status.Connection.LastSeenAt)

	usrT.Resync()
	_, err = usrSrv.Disconnect(usrT.Ctx(), &userv1.DisconnectRequest{})
	assert.Nil(t, err, "%+v", err)

	isActive, err = usrSrv.setConnectionLastSeen(ctx, usrT.Session.Metadata.Uid, oldConn)
	assert.Nil(t, err, "%+v", err)
	assert.False(t, isActive)

	usrT.Resync()
	_, newConn, err := usrSrv.doInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
	assert.Nil(t, err, "%+v", err)

	resourceVersion := getSess().Metadata.ResourceVersion

	isActive, err = usrSrv.setConnectionLastSeen(ctx, usrT.Session.Metadata.Uid, oldConn)
	assert.Nil(t, err, "%+v", err)
	assert.False(t, isActive)
	assert.Equal(t, resourceVersion, getSess().Metadata.ResourceVersion)

	isActive, err = usrSrv.setConnectionLastSeen(ctx, usrT.Session.Metadata.Uid, newConn)
	assert.Nil(t, err, "%+v", err)
	assert.True(t, isActive)
	assert.NotEqual(t, resourceVersion, getSess().Metadata.ResourceVersion)

	_, err = tst.C.OcteliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{
		Uid: usrT.Session.Metadata.Uid,
	})
	assert.Nil(t, err, "%+v", err)

	isActive, err = usrSrv.setConnectionLastSeen(ctx, usrT.Session.Metadata.Uid, newConn)
	assert.Nil(t, err, "%+v", err)
	assert.False(t, isActive)
}

type countingCoreV1Utils struct {
	octeliumc.CoreV1Utils

	mu                    sync.Mutex
	getClusterConfigCalls int
}

func (c *countingCoreV1Utils) GetClusterConfig(ctx context.Context) (*corev1.ClusterConfig, error) {
	c.mu.Lock()
	c.getClusterConfigCalls++
	c.mu.Unlock()

	return c.CoreV1Utils.GetClusterConfig(ctx)
}

type countingOcteliumC struct {
	octeliumc.ClientInterface
	utils *countingCoreV1Utils
}

func (c *countingOcteliumC) CoreV1Utils() octeliumc.CoreV1Utils {
	return c.utils
}

func TestDoInitConnectGetClusterConfig(t *testing.T) {
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	utils := &countingCoreV1Utils{
		CoreV1Utils: tst.C.OcteliumC.CoreV1Utils(),
	}

	usrSrv := NewServer(&countingOcteliumC{
		ClientInterface: tst.C.OcteliumC,
		utils:           utils,
	})
	_, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
		corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err, "%+v", err)

	resp, err := usrSrv.DoInitConnect(usrT.Ctx(), &userv1.ConnectRequest_Initialize{})
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 1, len(resp.GetState().Addresses))
	assert.NotNil(t, resp.GetState().Dns)

	utils.mu.Lock()
	defer utils.mu.Unlock()
	assert.Equal(t, 1, utils.getClusterConfigCalls)
}
