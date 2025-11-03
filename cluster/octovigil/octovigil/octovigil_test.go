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

package octovigil

import (
	"context"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestIsAuthorized(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	jwkCtl, err := jwkctl.NewJWKController(ctx, fakeC.OcteliumC)
	assert.Nil(t, err)

	getReq := func(sess *corev1.Session, svc *corev1.Service) *coctovigilv1.DownstreamRequest {
		// zap.L().Debug("Req Session", zap.Any("ses", sess))
		if sess.Status.Type == corev1.Session_Status_CLIENT {

			return &coctovigilv1.DownstreamRequest{
				Source: &coctovigilv1.DownstreamRequest_Source{
					Address: func() string {
						if sess.Status.Connection.Addresses[0].V4 != "" {
							return umetav1.ToDualStackNetwork(sess.Status.Connection.Addresses[0]).ToIP().Ipv4
						}
						return umetav1.ToDualStackNetwork(sess.Status.Connection.Addresses[0]).ToIP().Ipv6
					}(),
				},
			}

		} else {
			accessToken, err := jwkCtl.CreateAccessToken(sess)
			assert.Nil(t, err)

			ret := &coctovigilv1.DownstreamRequest{
				Source: &coctovigilv1.DownstreamRequest_Source{
					Address: "1.2.3.4",
				},
				Request: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Http{
						Http: &corev1.RequestContext_Request_HTTP{
							Headers: map[string]string{
								"x-octelium-auth": accessToken,
							},
						},
					},
				},
			}

			return ret

		}
	}

	getReqHTTP := func(sess *corev1.Session, svc *corev1.Service, path, method string) *coctovigilv1.DownstreamRequest {

		ret := getReq(sess, svc)
		if ret.Request == nil {
			ret.Request = &corev1.RequestContext_Request{}
		}

		if ret.Request.GetHttp() == nil {
			ret.Request.Type = &corev1.RequestContext_Request_Http{
				Http: &corev1.RequestContext_Request_HTTP{},
			}
		}

		ret.Request.GetHttp().Path = path
		ret.Request.GetHttp().Method = method

		return ret
	}

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usrSrv := user.NewServer(tst.C.OcteliumC)

	network, err := adminSrv.CreateNamespace(ctx, tests.GenNamespace())
	assert.Nil(t, err)

	networkK8s, err := fakeC.OcteliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{Name: network.Metadata.Name})
	assert.Nil(t, err)

	_, err = fakeC.OcteliumC.CoreC().UpdateNamespace(ctx, networkK8s)
	assert.Nil(t, err)

	testIsAuthorized := func(srv *Server, svc *corev1.Service, req *coctovigilv1.DownstreamRequest) *coctovigilv1.AuthenticateAndAuthorizeResponse {

		i, err := srv.AuthenticateAndAuthorize(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: svc,
			Request: req,
		})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, i.IsAuthenticated)
		assert.True(t, i.IsAuthorized)

		return i
	}

	testIsUnauthorized := func(srv *Server, svc *corev1.Service, req *coctovigilv1.DownstreamRequest) *coctovigilv1.AuthenticateAndAuthorizeResponse {

		i, err := srv.AuthenticateAndAuthorize(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: svc,
			Request: req,
		})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, i.IsAuthenticated)
		assert.False(t, i.IsAuthorized)

		return i
	}

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(network.Metadata.Name))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		usr.Resync()

		srv.cache.SetSession(usr.Session)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))
		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))

		grp, err := adminSrv.CreateGroup(ctx, tests.GenGroup())
		assert.Nil(t, err)

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: fmt.Sprintf(`"%s" in ctx.user.spec.groups`, grp.Metadata.Name),
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))

		usr.Usr.Spec.Groups = append(usr.Usr.Spec.Groups, grp.Metadata.Name)
		_, err = adminSrv.UpdateUser(ctx, usr.Usr)
		assert.Nil(t, err)
		usr.Resync()
		srv.cache.SetUser(usr.Usr)

		testIsAuthorized(srv, svc, getReq(usr.Session, svc))

		{
			usr.Usr.Spec.IsDisabled = true

			_, err = adminSrv.UpdateUser(ctx, usr.Usr)
			assert.Nil(t, err)
			usr.Resync()
			srv.cache.SetUser(usr.Usr)

			testIsUnauthorized(srv, svc, getReq(usr.Session, svc))

			usr.Usr.Spec.IsDisabled = false

			_, err = adminSrv.UpdateUser(ctx, usr.Usr)
			assert.Nil(t, err)
			usr.Resync()
			srv.cache.SetUser(usr.Usr)

			testIsAuthorized(srv, svc, getReq(usr.Session, svc))
		}

		testIsAuthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))
		testIsAuthorized(srv, svc, getReqHTTP(usr.Session, svc, "/path", "POST"))

		grp2, err := adminSrv.CreateGroup(ctx, tests.GenGroup())
		assert.Nil(t, err)

		usr.Usr.Spec.Groups = []string{
			grp2.Metadata.Name,
		}
		_, err = adminSrv.UpdateUser(ctx, usr.Usr)
		assert.Nil(t, err)
		usr.Resync()
		srv.cache.SetUser(usr.Usr)

		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))
		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/path", "POST"))

		svc.Spec.Authorization.InlinePolicies = append(svc.Spec.Authorization.InlinePolicies,
			&corev1.InlinePolicy{
				Spec: &corev1.Policy_Spec{
					Rules: []*corev1.Policy_Spec_Rule{
						{
							Effect: corev1.Policy_Spec_Rule_ALLOW,
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: fmt.Sprintf(`"%s" in ctx.user.spec.groups`, grp2.Metadata.Name),
								},
							},
						},
					},
				},
			})
		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		testIsAuthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))
		testIsAuthorized(srv, svc, getReqHTTP(usr.Session, svc, "/path", "POST"))

	}

	{
		// Deviceless container

		svcReq := tests.GenService(network.Metadata.Name)
		svcReq.Spec.IsPublic = true
		svcReq.Spec.Mode = corev1.Service_Spec_HTTP

		svcReq.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `1 == 1`,
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err := adminSrv.CreateService(ctx, svcReq)
		assert.Nil(t, err, "%+v", err)
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svcV)

		usr, err := tstuser.NewUserWorkloadClientless(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetSession(usr.Session)

		testIsAuthorized(srv, svc, getReq(usr.Session, svc))
		testIsAuthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))
	}

	{
		// Locked Session

		svcReq := tests.GenService(network.Metadata.Name)
		svcReq.Spec.IsPublic = true
		svcReq.Spec.Mode = corev1.Service_Spec_HTTP

		svcReq.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `1 == 1`,
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err := adminSrv.CreateService(ctx, svcReq)
		assert.Nil(t, err, "%+v", err)
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svcV)

		usr, err := tstuser.NewUserWorkloadClientless(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		usr.Session.Status.IsLocked = true

		usr.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usr.Session)
		assert.Nil(t, err)

		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetSession(usr.Session)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))
		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))
	}

	{
		// Locked User

		svcReq := tests.GenService(network.Metadata.Name)
		svcReq.Spec.IsPublic = true
		svcReq.Spec.Mode = corev1.Service_Spec_HTTP

		svcReq.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `1 == 1`,
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err := adminSrv.CreateService(ctx, svcReq)
		assert.Nil(t, err, "%+v", err)
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svcV)

		usr, err := tstuser.NewUserWorkloadClientless(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		usr.Usr.Status.IsLocked = true

		usr.Usr, err = srv.octeliumC.CoreC().UpdateUser(ctx, usr.Usr)
		assert.Nil(t, err)

		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetSession(usr.Session)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))
		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))
	}

	{
		// AuthenticatorAction - required authentication

		svcReq := tests.GenService(network.Metadata.Name)
		svcReq.Spec.IsPublic = true
		svcReq.Spec.Mode = corev1.Service_Spec_HTTP

		svcReq.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `1 == 1`,
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err := adminSrv.CreateService(ctx, svcReq)
		assert.Nil(t, err, "%+v", err)
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svcV)

		usr, err := tstuser.NewUserWorkloadClientless(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		usr.Session.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATION_REQUIRED

		usr.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usr.Session)
		assert.Nil(t, err)

		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetSession(usr.Session)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))
		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))
	}

	{
		// AuthenticatorAction - required registration

		svcReq := tests.GenService(network.Metadata.Name)
		svcReq.Spec.IsPublic = true
		svcReq.Spec.Mode = corev1.Service_Spec_HTTP

		svcReq.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `1 == 1`,
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err := adminSrv.CreateService(ctx, svcReq)
		assert.Nil(t, err, "%+v", err)
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svcV)

		usr, err := tstuser.NewUserWorkloadClientless(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)

		usr.Session.Status.AuthenticatorAction = corev1.Session_Status_REGISTRATION_REQUIRED

		usr.Session, err = srv.octeliumC.CoreC().UpdateSession(ctx, usr.Session)
		assert.Nil(t, err)

		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetSession(usr.Session)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))
		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))
	}

	{
		// Deviceless code

		svcReq := tests.GenService(network.Metadata.Name)
		svcReq.Spec.IsPublic = true
		svcReq.Spec.Mode = corev1.Service_Spec_HTTP
		svcReq.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `1 == 1`,
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err := adminSrv.CreateService(ctx, svcReq)
		assert.Nil(t, err)
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svcV)

		usr, err := tstuser.NewUserWorkloadClientless(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		srv.cache.SetSession(usr.Session)

		testIsAuthorized(srv, svc, getReq(usr.Session, svc))
		testIsAuthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))

	}

	/*
		{
			svc, err := adminSrv.CreateService(ctx, tests.GenService(network.Metadata.Name))
			assert.Nil(t, err)

			srv, err := New(ctx, tst.C.OcteliumC)
			assert.Nil(t, err)
			srv.cache.SetService(svc)

			usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, []string{"admin"})
			assert.Nil(t, err)

			srv.cache.SetUser(usr.Usr)
			usr.Resync()

			err = usr.Connect()
			usr.Resync()

			srv.cache.SetSession(usr.Session)
			srv.cache.SetUser(usr.Usr)
			assert.Nil(t, err, "%+v", err)

			testIsAuthorized(srv, svc, getReq(usr.Session, svc))

			{
				webSess, err := usr.NewSessionWithType(corev1.Session_Status_CLIENTLESS)
				assert.Nil(t, err)
				srv.cache.SetSession(webSess)

				svc.Spec.IsPublic = true
				testIsAuthorized(srv, svc, getReq(webSess, svc))
				svc.Spec.IsPublic = false
			}
		}
	*/

	{

		svc, err := adminSrv.CreateService(ctx, tests.GenService(network.Metadata.Name))
		assert.Nil(t, err)

		// os.Setenv("OCTELIUM_SVC_UID", svc.Metadata.Uid)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetSession(usr.Session)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `1 == 1`,
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		testIsAuthorized(srv, svc, getReq(usr.Session, svc))

		{
			usr.Device.Spec.State = corev1.Device_Spec_REJECTED
			usr.Device, err = fakeC.OcteliumC.CoreC().UpdateDevice(ctx, usr.Device)
			assert.Nil(t, err)

			srv.cache.SetDevice(usr.Device)

			testIsUnauthorized(srv, svc, getReq(usr.Session, svc))

			usr.Device.Spec.State = corev1.Device_Spec_PENDING
			usr.Device, err = fakeC.OcteliumC.CoreC().UpdateDevice(ctx, usr.Device)
			assert.Nil(t, err)

			srv.cache.SetDevice(usr.Device)

			testIsUnauthorized(srv, svc, getReq(usr.Session, svc))

			usr.Device.Spec.State = corev1.Device_Spec_STATE_UNKNOWN
			usr.Device, err = fakeC.OcteliumC.CoreC().UpdateDevice(ctx, usr.Device)
			assert.Nil(t, err)

			srv.cache.SetDevice(usr.Device)

			testIsUnauthorized(srv, svc, getReq(usr.Session, svc))

			usr.Device.Spec.State = corev1.Device_Spec_ACTIVE
			usr.Device, err = fakeC.OcteliumC.CoreC().UpdateDevice(ctx, usr.Device)
			assert.Nil(t, err)

			srv.cache.SetDevice(usr.Device)

			testIsAuthorized(srv, svc, getReq(usr.Session, svc))
		}

		grp, err := adminSrv.CreateGroup(ctx, tests.GenGroup())
		assert.Nil(t, err)

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: fmt.Sprintf(`"%s" in ctx.user.spec.groups`, grp.Metadata.Name),
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))

		usr.Usr.Spec.Groups = []string{
			grp.Metadata.Name,
		}
		usr.Usr, err = adminSrv.UpdateUser(ctx, usr.Usr)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		testIsAuthorized(srv, svc, getReq(usr.Session, svc))

	}

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(network.Metadata.Name))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetSession(usr.Session)

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Opa{
										Opa: &corev1.Condition_OPA{
											Type: &corev1.Condition_OPA_Inline{
												Inline: `
package octelium.condition
										
default match = false
										
match {
	input.ctx.session.status.userRef.name == input.ctx.user.metadata.name
	startswith(input.ctx.request.http.path, "/path1")
}
												`,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		testIsAuthorized(srv, svc, getReqHTTP(usr.Session, svc, "/path1/sub1", "GET"))
		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/path2/sub1", "GET"))
	}

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(network.Metadata.Name))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetSession(usr.Session)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))
		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))

		grp, err := adminSrv.CreateGroup(ctx, tests.GenGroup())
		assert.Nil(t, err)

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: fmt.Sprintf(`"%s" in ctx.user.spec.groups`, grp.Metadata.Name),
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))

		usr.Usr.Spec.Groups = append(usr.Usr.Spec.Groups, grp.Metadata.Name)
		_, err = adminSrv.UpdateUser(ctx, usr.Usr)
		assert.Nil(t, err)
		usr.Resync()
		srv.cache.SetUser(usr.Usr)

		testIsAuthorized(srv, svc, getReq(usr.Session, svc))

		grpV, err := srv.octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{Uid: grp.Metadata.Uid})
		assert.Nil(t, err)

		grpV.Spec.Authorization = &corev1.Group_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_DENY,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: fmt.Sprintf(`ctx.service.status.namespaceRef.name == "%s"`, network.Metadata.Name),
									},
								},
							},
						},
					},
				},
			},
		}

		grpV, err = srv.octeliumC.CoreC().UpdateGroup(ctx, grpV)
		assert.Nil(t, err)
		srv.cache.SetGroup(grpV)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))

		grpV.Spec.Authorization = &corev1.Group_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: fmt.Sprintf(`ctx.service.status.namespaceRef.name == "%s"`, network.Metadata.Name),
									},
								},
							},
						},
					},
				},
			},
		}

		grpV, err = srv.octeliumC.CoreC().UpdateGroup(ctx, grpV)
		assert.Nil(t, err)
		srv.cache.SetGroup(grpV)

		testIsAuthorized(srv, svc, getReq(usr.Session, svc))

		svc.Spec.Authorization = nil
		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetService(svc)

		testIsAuthorized(srv, svc, getReq(usr.Session, svc))

		grpV.Spec.Authorization = nil
		grpV, err = srv.octeliumC.CoreC().UpdateGroup(ctx, grpV)
		assert.Nil(t, err)
		srv.cache.SetGroup(grpV)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))
	}

	{

		svc, err := adminSrv.CreateService(ctx, tests.GenService(network.Metadata.Name))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetSession(usr.Session)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))
		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `1== 1`,
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		testIsAuthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))
		testIsAuthorized(srv, svc, getReqHTTP(usr.Session, svc, "/path", "POST"))

	}

	{

		svc, err := adminSrv.CreateService(ctx, tests.GenService(network.Metadata.Name))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetSession(usr.Session)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))
		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))

		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_DENY,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_MatchAny{
										MatchAny: true,
									},
								},
							},
							{
								Effect:   corev1.Policy_Spec_Rule_ALLOW,
								Priority: -1,
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

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		testIsAuthorized(srv, svc, getReq(usr.Session, svc))
		testIsAuthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))

		svc.Spec.Authorization.InlinePolicies[0].Spec.Rules = append(
			svc.Spec.Authorization.InlinePolicies[0].Spec.Rules, &corev1.Policy_Spec_Rule{
				Effect:   corev1.Policy_Spec_Rule_DENY,
				Priority: -1,
				Condition: &corev1.Condition{
					Type: &corev1.Condition_MatchAny{
						MatchAny: true,
					},
				},
			})
		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		testIsUnauthorized(srv, svc, getReq(usr.Session, svc))
		testIsUnauthorized(srv, svc, getReqHTTP(usr.Session, svc, "/", "GET"))
	}
}

func TestAuthenticateFailure(t *testing.T) {

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
	// usrSrv := user.NewServer(tst.C.OcteliumC)

	{

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		_, err = srv.Authenticate(ctx, nil)
		assert.NotNil(t, err)
	}

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		_, err = srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: svc,
		})
		assert.NotNil(t, err)
	}

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		_, err = srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: svc,
			Request: &coctovigilv1.DownstreamRequest{
				Source: &coctovigilv1.DownstreamRequest_Source{},
			},
		})
		assert.NotNil(t, err)
	}

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		_, err = srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: svc,
			Request: &coctovigilv1.DownstreamRequest{
				Source: &coctovigilv1.DownstreamRequest_Source{
					Address: "1.2.3.4",
				},
			},
		})
		assert.NotNil(t, err)
	}

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		_, err = srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: svc,
			Request: &coctovigilv1.DownstreamRequest{
				Source: &coctovigilv1.DownstreamRequest_Source{
					Address: "1.2.3.4.5",
				},
			},
		})
		assert.NotNil(t, err)
	}

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		_, err = srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: svc,
			Request: &coctovigilv1.DownstreamRequest{
				Source: &coctovigilv1.DownstreamRequest_Source{},
				Request: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Http{
						Http: &corev1.RequestContext_Request_HTTP{},
					},
				},
			},
		})
		assert.NotNil(t, err)
	}

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		_, err = srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: svc,
			Request: &coctovigilv1.DownstreamRequest{
				Source: &coctovigilv1.DownstreamRequest_Source{},
				Request: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Http{
						Http: &corev1.RequestContext_Request_HTTP{
							Headers: map[string]string{
								"x-octelium-auth": "",
							},
						},
					},
				},
			},
		})
		assert.NotNil(t, err)
	}
}

func TestAuthenticate(t *testing.T) {

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
	usrSrv := user.NewServer(tst.C.OcteliumC)

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		usr.Resync()

		srv.cache.SetSession(usr.Session)

		{
			res, err := srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: svc,
				Request: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: umetav1.ToDualStackNetwork(usr.Session.Status.Connection.Addresses[0]).ToIP().Ipv4,
					},
				},
			})
			assert.Nil(t, err)

			assert.Equal(t, res.Session.Metadata.Uid, usr.Session.Metadata.Uid)
			assert.Equal(t, res.User.Metadata.Uid, usr.Usr.Metadata.Uid)
			assert.Equal(t, res.Device.Metadata.Uid, usr.Device.Metadata.Uid)
		}
		{
			res, err := srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: svc,
				Request: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: umetav1.ToDualStackNetwork(usr.Session.Status.Connection.Addresses[0]).ToIP().Ipv6,
					},
				},
			})
			assert.Nil(t, err)

			assert.Equal(t, res.Session.Metadata.Uid, usr.Session.Metadata.Uid)
			assert.Equal(t, res.User.Metadata.Uid, usr.Usr.Metadata.Uid)
			assert.Equal(t, res.Device.Metadata.Uid, usr.Device.Metadata.Uid)
		}

		{
			res, err := srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: svc,
				Request: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: umetav1.ToDualStackNetwork(usr.Session.Status.Connection.Addresses[0]).ToIP().Ipv4,
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{
								Headers: map[string]string{
									"authorization": fmt.Sprintf("Bearer %s", utilrand.GetRandomString(8)),
								},
							},
						},
					},
				},
			})
			assert.Nil(t, err)

			assert.Equal(t, res.Session.Metadata.Uid, usr.Session.Metadata.Uid)
			assert.Equal(t, res.User.Metadata.Uid, usr.Usr.Metadata.Uid)
			assert.Equal(t, res.Device.Metadata.Uid, usr.Device.Metadata.Uid)
		}

		{
			res, err := srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: svc,
				Request: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: umetav1.ToDualStackNetwork(usr.Session.Status.Connection.Addresses[0]).ToIP().Ipv4,
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{
								Headers: map[string]string{
									"x-octelium-auth": utilrand.GetRandomString(8),
								},
							},
						},
					},
				},
			})
			assert.Nil(t, err)

			assert.Equal(t, res.Session.Metadata.Uid, usr.Session.Metadata.Uid)
			assert.Equal(t, res.User.Metadata.Uid, usr.Usr.Metadata.Uid)
			assert.Equal(t, res.Device.Metadata.Uid, usr.Device.Metadata.Uid)
		}
	}

	{

		// Not a public Service
		svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		usr, err := tstuser.NewUserWithSessType(tst.C.OcteliumC, adminSrv, usrSrv, nil, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		srv.cache.SetSession(usr.Session)

		accessToken, err := srv.jwkCtl.CreateAccessToken(usr.Session)
		assert.Nil(t, err)

		{
			_, err := srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: svc,
				Request: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "1.2.3.4",
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{
								Headers: map[string]string{
									"x-octelium-auth": accessToken,
								},
							},
						},
					},
				},
			})
			assert.NotNil(t, err)
		}
	}

	{

		// Now, a public Service
		svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
		assert.Nil(t, err)

		svc.Spec.IsPublic = true

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		srv.cache.SetSession(usr.Session)

		accessToken, err := srv.jwkCtl.CreateAccessToken(usr.Session)
		assert.Nil(t, err)

		{
			res, err := srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: svc,
				Request: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "1.2.3.4",
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{
								Headers: map[string]string{
									"x-octelium-auth": accessToken,
								},
							},
						},
					},
				},
			})
			assert.Nil(t, err)

			assert.Equal(t, res.Session.Metadata.Uid, usr.Session.Metadata.Uid)
			assert.Equal(t, res.User.Metadata.Uid, usr.Usr.Metadata.Uid)
			assert.Equal(t, res.Device.Metadata.Uid, usr.Device.Metadata.Uid)
		}

		{
			res, err := srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: svc,
				Request: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "1.2.3.4",
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{
								Headers: map[string]string{
									"x-octelium-auth": accessToken,
								},
							},
						},
					},
				},
			})
			assert.Nil(t, err)

			assert.Equal(t, res.Session.Metadata.Uid, usr.Session.Metadata.Uid)
			assert.Equal(t, res.User.Metadata.Uid, usr.Usr.Metadata.Uid)
			assert.Equal(t, res.Device.Metadata.Uid, usr.Device.Metadata.Uid)
		}

		{
			res, err := srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: svc,
				Request: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{
						Address: "1.2.3.4",
					},
					Request: &corev1.RequestContext_Request{
						Type: &corev1.RequestContext_Request_Http{
							Http: &corev1.RequestContext_Request_HTTP{
								Headers: map[string]string{
									"cookie": fmt.Sprintf("key=val; octelium_auth=%s", accessToken),
								},
							},
						},
					},
				},
			})
			assert.Nil(t, err)

			assert.Equal(t, res.Session.Metadata.Uid, usr.Session.Metadata.Uid)
			assert.Equal(t, res.User.Metadata.Uid, usr.Usr.Metadata.Uid)
			assert.Equal(t, res.Device.Metadata.Uid, usr.Device.Metadata.Uid)
		}
	}

}

func TestServiceConfig(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	type tstCase struct {
		spec *corev1.Service_Spec
		res  string
	}
	tstCases := []tstCase{
		{
			spec: &corev1.Service_Spec{},
			res:  "",
		},
		{
			spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								RemoveRequestHeaders: []string{
									"x-hdr-1234567",
									"x-hdr-abcdefg",
								},
							},
						},
					},
				},
			},
			res: "",
		},
		{
			spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								RemoveRequestHeaders: []string{
									"x-hdr-1234567",
									"x-hdr-abcdefg",
								},
							},
						},
					},
				},
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{},
			},
			res: "",
		},

		{
			spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								RemoveRequestHeaders: []string{
									"x-hdr-1",
									"x-hdr-2",
								},
							},
						},
					},
				},
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "cfg-1",

							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Header: &corev1.Service_Spec_Config_HTTP_Header{
										RemoveRequestHeaders: []string{
											"x-hdr-3",
											"x-hdr-4",
										},
									},
								},
							},
						},
					},
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{
								ConfigName: "cfg-1",
							},
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `2 < 1`,
								},
							},
						},
					},
				},
			},
			res: "",
		},

		{
			spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								RemoveRequestHeaders: []string{
									"x-hdr-1",
									"x-hdr-2",
								},
							},
						},
					},
				},
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "cfg-1",

							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Header: &corev1.Service_Spec_Config_HTTP_Header{
										RemoveRequestHeaders: []string{
											"x-hdr-3",
											"x-hdr-4",
										},
									},
								},
							},
						},
					},
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{
								ConfigName: "cfg-1",
							},
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `2 > 1`,
								},
							},
						},
					},
				},
			},
			res: "cfg-1",
		},

		{
			spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								RemoveRequestHeaders: []string{
									"x-hdr-1",
									"x-hdr-2",
								},
							},
						},
					},
				},
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "cfg-1",

							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Header: &corev1.Service_Spec_Config_HTTP_Header{
										RemoveRequestHeaders: []string{
											"x-hdr-3",
											"x-hdr-4",
										},
									},
								},
							},
						},
					},
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{
								ConfigName: "cfg-1",
							},
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `2 > 1`,
								},
							},
						},
						{
							Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{
								ConfigName: "cfg-2",
							},
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `2 > 1`,
								},
							},
						},
					},
				},
			},
			res: "cfg-1",
		},

		{
			spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								RemoveRequestHeaders: []string{
									"x-hdr-1",
									"x-hdr-2",
								},
							},
						},
					},
				},
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "cfg-1",

							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Header: &corev1.Service_Spec_Config_HTTP_Header{
										RemoveRequestHeaders: []string{
											"x-hdr-3",
											"x-hdr-4",
										},
									},
								},
							},
						},
					},
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{
								ConfigName: "cfg-1",
							},
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `2 < 1`,
								},
							},
						},
						{
							Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{
								ConfigName: "cfg-2",
							},
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `2 > 1`,
								},
							},
						},
					},
				},
			},
			res: "cfg-2",
		},

		{
			spec: &corev1.Service_Spec{
				Config: &corev1.Service_Spec_Config{
					Type: &corev1.Service_Spec_Config_Http{
						Http: &corev1.Service_Spec_Config_HTTP{
							Header: &corev1.Service_Spec_Config_HTTP_Header{
								RemoveRequestHeaders: []string{
									"x-hdr-1",
									"x-hdr-2",
								},
							},
						},
					},
				},
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "cfg-1",

							Type: &corev1.Service_Spec_Config_Http{
								Http: &corev1.Service_Spec_Config_HTTP{
									Header: &corev1.Service_Spec_Config_HTTP_Header{
										RemoveRequestHeaders: []string{
											"x-hdr-3",
											"x-hdr-4",
										},
									},
								},
							},
						},
					},
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{
								ConfigName: "cfg-1",
							},
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `2 < 1`,
								},
							},
						},
						{
							Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{
								ConfigName: "cfg-2",
							},
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `4 < 3`,
								},
							},
						},
					},
				},
			},
			res: "",
		},
	}

	srv, err := New(ctx, tst.C.OcteliumC)
	assert.Nil(t, err)

	{
		usr := &corev1.User{
			Metadata: &metav1.Metadata{
				Name: "usr-1",
			},
			Spec: &corev1.User_Spec{
				Type:   corev1.User_Spec_HUMAN,
				Groups: []string{"grp-1"},
			},
		}

		for _, tstCase := range tstCases {
			reqCtx := &corev1.RequestContext{
				Service: &corev1.Service{
					Metadata: &metav1.Metadata{
						Name: "svc-1",
					},
					Spec: tstCase.spec,
				},
				User: usr,
			}

			req := &coctovigilv1.AuthenticateAndAuthorizeResponse{
				RequestContext: reqCtx,
			}
			err := srv.setServiceConfig(ctx, req)
			assert.Nil(t, err)
			assert.Equal(t, tstCase.res, req.ServiceConfigName)
		}
	}
}
