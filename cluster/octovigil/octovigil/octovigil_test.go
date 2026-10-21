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
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/ccctl"
	"github.com/octelium/octelium/cluster/common/jwkctl"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/octovigil/octovigil/acache"
	devicecontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/devices"
	groupcontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/groups"
	nscontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/namespaces"
	policycontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/policies"
	ptctl "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/policytemplates"
	svccontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/services"
	sesscontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/sessions"
	usercontroller "github.com/octelium/octelium/cluster/octovigil/octovigil/controllers/users"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestIsAuthorized(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	jwkCtl, err := jwkctl.NewJWKController(ctx, fakeC.OcteliumC, nil)
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
										
match if {
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

	{
		// Additional

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

		pol, err := srv.octeliumC.CoreC().CreatePolicy(ctx, &corev1.Policy{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					{
						Condition: &corev1.Condition{
							Type: &corev1.Condition_MatchAny{
								MatchAny: true,
							},
						},
						Effect: corev1.Policy_Spec_Rule_DENY,
					},
				},
			},
		})
		assert.Nil(t, err)

		assert.Nil(t, srv.cache.SetPolicy(pol))

		{
			i, err := srv.AuthenticateAndAuthorize(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: svc,
				Request: getReq(usr.Session, svc),
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, i.IsAuthenticated)
			assert.True(t, i.IsAuthorized)
		}

		{
			i, err := srv.AuthenticateAndAuthorize(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: svc,
				Request: getReq(usr.Session, svc),
				Additional: &coctovigilv1.Authorization{
					InlinePolicies: []*corev1.InlinePolicy{
						{
							Spec: &corev1.Policy_Spec{
								Rules: []*corev1.Policy_Spec_Rule{
									{
										Condition: &corev1.Condition{
											Type: &corev1.Condition_MatchAny{
												MatchAny: true,
											},
										},
										Effect: corev1.Policy_Spec_Rule_DENY,
									},
								},
							},
						},
					},
				},
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, i.IsAuthenticated)
			assert.False(t, i.IsAuthorized)

			assert.NotNil(t, i.AuthorizationDecisionReason.Details.GetPolicyMatch().GetInlinePolicy())
		}

		{
			i, err := srv.AuthenticateAndAuthorize(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: svc,
				Request: getReq(usr.Session, svc),
				Additional: &coctovigilv1.Authorization{
					Policies: []string{pol.Metadata.Name},
				},
			})
			assert.Nil(t, err, "%+v", err)
			assert.True(t, i.IsAuthenticated)
			assert.False(t, i.IsAuthorized)

			assert.NotNil(t, i.AuthorizationDecisionReason.Details.GetPolicyMatch().GetPolicy())
			assert.Equal(t, pol.Metadata.Uid,
				i.AuthorizationDecisionReason.Details.GetPolicyMatch().GetPolicy().PolicyRef.Uid)
		}
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

func TestAuthenticateCacheMiss(t *testing.T) {

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

	svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
	assert.Nil(t, err)
	svc.Spec.IsPublic = true

	getReq := func(accessToken string) *coctovigilv1.DoAuthenticateAndAuthorizeRequest {
		return &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
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
		}
	}

	{
		// Session, User and Device are not cached yet
		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)

		accessToken, err := srv.jwkCtl.CreateAccessToken(usr.Session)
		assert.Nil(t, err)

		res, err := srv.Authenticate(ctx, getReq(accessToken))
		assert.Nil(t, err)

		assert.Equal(t, res.Session.Metadata.Uid, usr.Session.Metadata.Uid)
		assert.Equal(t, res.User.Metadata.Uid, usr.Usr.Metadata.Uid)
		assert.Equal(t, res.Device.Metadata.Uid, usr.Device.Metadata.Uid)

		_, err = srv.cache.GetSession(usr.Session.Metadata.Uid)
		assert.True(t, srv.cache.IsErrNotFound(err))
		_, err = srv.cache.GetUser(usr.Usr.Metadata.Uid)
		assert.True(t, srv.cache.IsErrNotFound(err))

		_, err = tst.C.OcteliumC.CoreC().DeleteSession(ctx, &rmetav1.DeleteOptions{
			Uid: usr.Session.Metadata.Uid,
		})
		assert.Nil(t, err)

		_, err = srv.Authenticate(ctx, getReq(accessToken))
		assert.True(t, errors.Is(err, UnauthenticatedErr))
	}

	{
		// The cached Session is stale after the access token is refreshed
		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENTLESS)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)
		srv.cache.SetSession(usr.Session)

		oldAccessToken, err := srv.jwkCtl.CreateAccessToken(usr.Session)
		assert.Nil(t, err)

		sess, err := tst.C.OcteliumC.CoreC().GetSession(ctx, &rmetav1.GetOptions{
			Uid: usr.Session.Metadata.Uid,
		})
		assert.Nil(t, err)
		sess.Status.Authentication.TokenID = vutils.UUIDv4()
		sess, err = tst.C.OcteliumC.CoreC().UpdateSession(ctx, sess)
		assert.Nil(t, err)

		accessToken, err := srv.jwkCtl.CreateAccessToken(sess)
		assert.Nil(t, err)

		res, err := srv.Authenticate(ctx, getReq(accessToken))
		assert.Nil(t, err)
		assert.Equal(t, sess.Status.Authentication.TokenID, res.Session.Status.Authentication.TokenID)
		assert.Equal(t, res.User.Metadata.Uid, usr.Usr.Metadata.Uid)

		cachedSess, err := srv.cache.GetSession(usr.Session.Metadata.Uid)
		assert.Nil(t, err)
		assert.Equal(t, usr.Session.Status.Authentication.TokenID, cachedSess.Status.Authentication.TokenID)

		srv.cache.SetSession(sess)

		_, err = srv.Authenticate(ctx, getReq(oldAccessToken))
		assert.True(t, errors.Is(err, UnauthenticatedErr))

		res, err = srv.Authenticate(ctx, getReq(accessToken))
		assert.Nil(t, err)
		assert.Equal(t, sess.Status.Authentication.TokenID, res.Session.Status.Authentication.TokenID)
	}

	{
		// Client addresses are only resolved from the cache
		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		err = usr.Connect()
		assert.Nil(t, err, "%+v", err)
		usr.Resync()

		_, err = srv.Authenticate(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: svc,
			Request: &coctovigilv1.DownstreamRequest{
				Source: &coctovigilv1.DownstreamRequest_Source{
					Address: umetav1.ToDualStackNetwork(usr.Session.Status.Connection.Addresses[0]).ToIP().Ipv4,
				},
			},
		})
		assert.True(t, errors.Is(err, UnauthenticatedErr))
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

	{
		svc, err := srv.coreSrv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Port: 8080,
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_MatchAny{
									MatchAny: true,
								},
							},

							Type: &corev1.Service_Spec_DynamicConfig_Rule_Eval{
								Eval: `{"upstream": {"url": "https://" + ctx.service.metadata.uid + ".example.com" }}`,
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		req := &coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext: &corev1.RequestContext{
				Service: svc,
			},
		}
		err = srv.setServiceConfig(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, fmt.Sprintf("https://%s.example.com", svc.Metadata.Uid), req.Config.Upstream.GetUrl())
	}

	{
		svc, err := srv.coreSrv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.default", utilrand.GetRandomStringCanonical(8)),
			},
			Spec: &corev1.Service_Spec{
				Port: 8080,
				Mode: corev1.Service_Spec_HTTP,
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
						{
							Condition: &corev1.Condition{
								Type: &corev1.Condition_MatchAny{
									MatchAny: true,
								},
							},

							Type: &corev1.Service_Spec_DynamicConfig_Rule_Opa{
								Opa: `
package octelium.eval

result := {
	"upstream": {
		"url": sprintf("https://%s.example.com", [input.ctx.service.metadata.uid])
	}
}`,
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		req := &coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext: &corev1.RequestContext{
				Service: svc,
			},
		}
		err = srv.setServiceConfig(ctx, req)
		assert.Nil(t, err)
		assert.Equal(t, fmt.Sprintf("https://%s.example.com", svc.Metadata.Uid), req.Config.Upstream.GetUrl())
	}
}

func TestIsAuthorizedAnonymous(t *testing.T) {

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
		assert.False(t, i.IsAuthenticated)
		assert.True(t, i.IsAuthorized)

		return i
	}

	testIsUnauthorized := func(srv *Server, svc *corev1.Service, req *coctovigilv1.DownstreamRequest) *coctovigilv1.AuthenticateAndAuthorizeResponse {

		i, err := srv.AuthenticateAndAuthorize(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: svc,
			Request: req,
		})
		assert.Nil(t, err, "%+v", err)
		assert.False(t, i.IsAuthenticated)
		assert.False(t, i.IsAuthorized)

		return i
	}

	{
		svc, err := adminSrv.CreateService(ctx, tests.GenService(network.Metadata.Name))
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		svc.Spec.IsAnonymous = true
		svc.Spec.IsPublic = true
		svc.Spec.Mode = corev1.Service_Spec_HTTP
		svc.Spec.Authorization = &corev1.Service_Spec_Authorization{
			EnableAnonymous: true,
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `ctx.request.http.path.startsWith("/v1")`,
									},
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetService(svc)

		testIsAuthorized(srv, svc, &coctovigilv1.DownstreamRequest{
			Request: &corev1.RequestContext_Request{
				Type: &corev1.RequestContext_Request_Http{
					Http: &corev1.RequestContext_Request_HTTP{
						Path: `/v1/my/path`,
					},
				},
			},
		})

		{
			res := testIsUnauthorized(srv, svc, &coctovigilv1.DownstreamRequest{
				Request: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Http{
						Http: &corev1.RequestContext_Request_HTTP{
							Path: `/v2/my/path`,
						},
					},
				},
			})

			assert.Equal(t,
				corev1.AccessLog_Entry_Common_Reason_NO_POLICY_MATCH, res.AuthorizationDecisionReason.Type)
		}

		svc.Spec.Authorization.InlinePolicies = nil
		svc.Spec.Authorization.Policies = nil
		svc.Spec.Authorization.EnableAnonymous = true

		svc, err = adminSrv.UpdateService(ctx, svc)
		assert.Nil(t, err, "%+v", err)
		srv.cache.SetService(svc)

		{
			res := testIsUnauthorized(srv, svc, &coctovigilv1.DownstreamRequest{
				Request: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Http{
						Http: &corev1.RequestContext_Request_HTTP{
							Path: `/v1/my/path`,
						},
					},
				},
			})

			assert.Equal(t,
				corev1.AccessLog_Entry_Common_Reason_NO_POLICY_MATCH, res.AuthorizationDecisionReason.Type)
		}

		{
			res := testIsUnauthorized(srv, svc, &coctovigilv1.DownstreamRequest{
				Request: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Http{
						Http: &corev1.RequestContext_Request_HTTP{
							Path: `/v2/my/path`,
						},
					},
				},
			})

			assert.Equal(t,
				corev1.AccessLog_Entry_Common_Reason_NO_POLICY_MATCH, res.AuthorizationDecisionReason.Type)
		}
	}

}

func TestAccessTokenHeaders(t *testing.T) {
	srv := &Server{}
	for _, tc := range []struct {
		name    string
		headers map[string]string
		token   string
		isErr   bool
	}{
		{"Nil", nil, "", true},
		{"Empty", map[string]string{}, "", true},
		{"Custom", map[string]string{"x-octelium-auth": "custom"}, "custom", false},
		{"CustomFirst", map[string]string{"x-octelium-auth": "custom", "cookie": "octelium_auth=cookie", "authorization": "Bearer bearer"}, "custom", false},
		{"EmptyCustom", map[string]string{"x-octelium-auth": "", "cookie": "octelium_auth=cookie"}, "cookie", false},
		{"Cookie", map[string]string{"cookie": "other=value; octelium_auth=cookie; final=value"}, "cookie", false},
		{"QuotedCookie", map[string]string{"cookie": `octelium_auth="cookie"`}, "cookie", false},
		{"CookieFirst", map[string]string{"cookie": "octelium_auth=cookie", "authorization": "Bearer bearer"}, "cookie", false},
		{"EmptyCookie", map[string]string{"cookie": "octelium_auth=", "authorization": "Bearer bearer"}, "bearer", false},
		{"UnrelatedCookie", map[string]string{"cookie": "other=value", "authorization": "Bearer bearer"}, "bearer", false},
		{"Bearer", map[string]string{"authorization": "Bearer bearer"}, "bearer", false},
		{"EmptyBearer", map[string]string{"authorization": "Bearer "}, "", false},
		{"BearerWhitespace", map[string]string{"authorization": "Bearer  token "}, " token ", false},
		{"MissingBearerSpace", map[string]string{"authorization": "Bearer"}, "", true},
		{"Basic", map[string]string{"authorization": "Basic dXNlcjpwYXNz"}, "", true},
		{"LowercaseScheme", map[string]string{"authorization": "bearer token"}, "", true},
		{"DifferentCookieName", map[string]string{"cookie": "octelium_auth_extra=token"}, "", true},
		{"InvalidCookie", map[string]string{"cookie": "octelium_auth=bad\x00token"}, "", true},
		{"CaseSensitiveHeader", map[string]string{"Authorization": "Bearer token"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := srv.getAccessTokenFromHTTPHeader(tc.headers)
			assert.Equal(t, tc.isErr, err != nil)
			assert.Equal(t, tc.token, token)
		})
	}
}

func TestClientAddressBoundaries(t *testing.T) {
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	v6 := netip.MustParsePrefix("fd00::/64")
	srv := &Server{v4Prefix: &v4, v6Prefix: &v6}
	for _, tc := range []struct {
		address string
		match   bool
	}{
		{"100.64.0.0", true}, {"100.127.255.255", true}, {"100.63.255.255", false}, {"100.128.0.0", false},
		{"fd00::", true}, {"fd00::ffff:ffff:ffff:ffff", true}, {"fd00:0:0:1::", false}, {"fe80::1", false},
		{"", false}, {"100.64.0.2/32", false}, {"100.64.0.2:80", false}, {"[fd00::2]:80", false},
		{"::ffff:100.64.0.2", false}, {"127.0.0.1", false}, {"100.64.0.2\x00", false}, {" 100.64.0.2", false},
	} {
		t.Run(tc.address, func(t *testing.T) {
			assert.Equal(t, tc.match, srv.isAddressFromClient(tc.address))
		})
	}
	assert.False(t, (&Server{}).isAddressFromClient("100.64.0.2"))
	assert.False(t, (&Server{}).isAddressFromClient("fd00::2"))
}

func TestAuthorizationGuards(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*corev1.RequestContext)
		reason  corev1.AccessLog_Entry_Common_Reason_Type
		allowed bool
		isErr   bool
	}{
		{"Allowed", func(req *corev1.RequestContext) {}, corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH, true, false},
		{"MissingUser", func(req *corev1.RequestContext) { req.User = nil }, 0, false, true},
		{"MissingSession", func(req *corev1.RequestContext) { req.Session = nil }, 0, false, true},
		{"MissingService", func(req *corev1.RequestContext) { req.Service = nil }, 0, false, true},
		{"SessionUnknown", func(req *corev1.RequestContext) { req.Session.Spec.State = corev1.Session_Spec_STATE_UNKNOWN }, corev1.AccessLog_Entry_Common_Reason_SESSION_NOT_ACTIVE, false, false},
		{"SessionPending", func(req *corev1.RequestContext) { req.Session.Spec.State = corev1.Session_Spec_PENDING }, corev1.AccessLog_Entry_Common_Reason_SESSION_NOT_ACTIVE, false, false},
		{"SessionRejected", func(req *corev1.RequestContext) { req.Session.Spec.State = corev1.Session_Spec_REJECTED }, corev1.AccessLog_Entry_Common_Reason_SESSION_NOT_ACTIVE, false, false},
		{"SessionExpired", func(req *corev1.RequestContext) {
			req.Session.Spec.ExpiresAt = timestamppb.New(time.Now().Add(-time.Hour))
		}, corev1.AccessLog_Entry_Common_Reason_SESSION_EXPIRED, false, false},
		{"TokenExpired", func(req *corev1.RequestContext) {
			req.Session.Status.Authentication.SetAt = timestamppb.New(time.Now().Add(-time.Hour))
			req.Session.Status.Authentication.AccessTokenDuration = &metav1.Duration{Type: &metav1.Duration_Seconds{Seconds: 1}}
		}, corev1.AccessLog_Entry_Common_Reason_ACCESS_TOKEN_EXPIRED, false, false},
		{"SessionLocked", func(req *corev1.RequestContext) { req.Session.Status.IsLocked = true }, corev1.AccessLog_Entry_Common_Reason_SESSION_LOCKED, false, false},
		{"UserLocked", func(req *corev1.RequestContext) { req.User.Status.IsLocked = true }, corev1.AccessLog_Entry_Common_Reason_USER_LOCKED, false, false},
		{"AuthenticationRequired", func(req *corev1.RequestContext) {
			req.Session.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATION_REQUIRED
		}, corev1.AccessLog_Entry_Common_Reason_AUTHENTICATOR_AUTHENTICATION_REQUIRED, false, false},
		{"RegistrationRequired", func(req *corev1.RequestContext) {
			req.Session.Status.AuthenticatorAction = corev1.Session_Status_REGISTRATION_REQUIRED
		}, corev1.AccessLog_Entry_Common_Reason_AUTHENTICATOR_REGISTRATION_REQUIRED, false, false},
		{"AuthenticationRecommended", func(req *corev1.RequestContext) {
			req.Session.Status.AuthenticatorAction = corev1.Session_Status_AUTHENTICATION_RECOMMENDED
		}, corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH, true, false},
		{"RegistrationRecommended", func(req *corev1.RequestContext) {
			req.Session.Status.AuthenticatorAction = corev1.Session_Status_REGISTRATION_RECOMMENDED
		}, corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH, true, false},
		{"UnknownAuthenticatorAction", func(req *corev1.RequestContext) { req.Session.Status.AuthenticatorAction = 100 }, 0, false, true},
		{"DeviceInactive", func(req *corev1.RequestContext) { req.Device.Spec.State = corev1.Device_Spec_STATE_UNKNOWN }, corev1.AccessLog_Entry_Common_Reason_DEVICE_NOT_ACTIVE, false, false},
		{"DeviceLocked", func(req *corev1.RequestContext) { req.Device.Status.IsLocked = true }, corev1.AccessLog_Entry_Common_Reason_DEVICE_LOCKED, false, false},
		{"UserDisabled", func(req *corev1.RequestContext) { req.User.Spec.IsDisabled = true }, corev1.AccessLog_Entry_Common_Reason_USER_DEACTIVATED, false, false},
		{"ClientlessPrivateService", func(req *corev1.RequestContext) { req.Session.Status.Type = corev1.Session_Status_CLIENTLESS }, corev1.AccessLog_Entry_Common_Reason_SESSION_CLIENT_TYPE_INVALID, false, false},
		{"Deviceless", func(req *corev1.RequestContext) { req.Device = nil }, corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH, true, false},
		{"ScopeRestricted", func(req *corev1.RequestContext) {
			req.Session.Status.Scopes = []*corev1.Scope{{Type: &corev1.Scope_Service_{Service: &corev1.Scope_Service{
				Type: &corev1.Scope_Service_Filter_{Filter: &corev1.Scope_Service_Filter{Names: []string{"other.namespace"}}},
			}}}}
		}, corev1.AccessLog_Entry_Common_Reason_SCOPE_UNAUTHORIZED, false, false},
		{"NoPolicy", func(req *corev1.RequestContext) { req.Service.Spec.Authorization = nil }, corev1.AccessLog_Entry_Common_Reason_NO_POLICY_MATCH, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, coreC := newAuthorizationService(t)
			di, err := srv.s.GetDownstreamInfo(t.Context(), "100.64.0.2")
			assert.Nil(t, err)
			req := proto.Clone(srv.s.getReqCtx(di, nil, coreC.service)).(*corev1.RequestContext)
			tc.mutate(req)
			resp, err := srv.s.DoAuthorize(t.Context(), req, nil)
			assert.Equal(t, tc.isErr, err != nil)
			if tc.isErr {
				assert.Nil(t, resp)
				return
			}
			if !assert.NotNil(t, resp) {
				return
			}
			assert.Equal(t, tc.allowed, resp.IsAuthorized)
			assert.Equal(t, tc.reason, resp.Reason.Type)
			if tc.reason == corev1.AccessLog_Entry_Common_Reason_SESSION_NOT_ACTIVE {
				assert.Equal(t, req.Session.Spec.State, resp.Reason.Details.GetSessionNotActive().State)
			}
		})
	}
}

func TestAuthorizationAnonymousIdentity(t *testing.T) {
	srv, coreC := newAuthorizationService(t)
	coreC.service.Spec.IsAnonymous = true
	coreC.service.Spec.Authorization.EnableAnonymous = true
	request := &coctovigilv1.AuthenticateAndAuthorizeRequest{
		ServiceUID: "service", Request: &coctovigilv1.DownstreamRequest{},
	}
	resp, err := srv.AuthenticateAndAuthorize(t.Context(), request)
	if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
		return
	}
	assert.False(t, resp.IsAuthenticated)
	assert.True(t, resp.IsAuthorized)
	assert.Nil(t, resp.RequestContext.User)
	assert.Nil(t, resp.RequestContext.Device)
	assert.Nil(t, resp.RequestContext.Session)
	assert.Empty(t, resp.RequestContext.Groups)
	assert.Equal(t, coreC.namespace, resp.RequestContext.Namespace)
	coreC.service.Spec.Authorization.EnableAnonymous = false
	resp, err = srv.AuthenticateAndAuthorize(t.Context(), request)
	assert.Nil(t, err)
	assert.False(t, resp.IsAuthenticated)
	assert.False(t, resp.IsAuthorized)
	coreC.service.Spec.Authorization.EnableAnonymous = true
	request.Additional = &coctovigilv1.Authorization{InlinePolicies: []*corev1.InlinePolicy{{
		Name: "deny", Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{
			Effect: corev1.Policy_Spec_Rule_DENY, Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
		}}},
	}}}
	resp, err = srv.AuthenticateAndAuthorize(t.Context(), request)
	assert.Nil(t, err)
	assert.False(t, resp.IsAuthorized)
	assert.Equal(t, "deny", resp.AuthorizationDecisionReason.Details.GetPolicyMatch().GetInlinePolicy().Name)
}

func TestDynamicServiceConfigErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rule  *corev1.Service_Spec_DynamicConfig_Rule
		isErr bool
	}{
		{"ConditionError", &corev1.Service_Spec_DynamicConfig_Rule{Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: "ctx.service =="}}}, false},
		{"EvalError", &corev1.Service_Spec_DynamicConfig_Rule{Type: &corev1.Service_Spec_DynamicConfig_Rule_Eval{Eval: "ctx.service =="}}, false},
		{"EvalWrongType", &corev1.Service_Spec_DynamicConfig_Rule{Type: &corev1.Service_Spec_DynamicConfig_Rule_Eval{Eval: `42`}}, false},
		{"EvalUnmarshal", &corev1.Service_Spec_DynamicConfig_Rule{Type: &corev1.Service_Spec_DynamicConfig_Rule_Eval{Eval: `{"upstream": 42}`}}, false},
		{"EvalInvalidConfig", &corev1.Service_Spec_DynamicConfig_Rule{Type: &corev1.Service_Spec_DynamicConfig_Rule_Eval{Eval: `{"upstream": {"url": "invalid"}}`}}, true},
		{"OPAError", &corev1.Service_Spec_DynamicConfig_Rule{Type: &corev1.Service_Spec_DynamicConfig_Rule_Opa{Opa: "not valid rego"}}, false},
		{"OPAWrongType", &corev1.Service_Spec_DynamicConfig_Rule{Type: &corev1.Service_Spec_DynamicConfig_Rule_Opa{Opa: "package octelium.eval\nresult := 42"}}, false},
		{"OPAUnmarshal", &corev1.Service_Spec_DynamicConfig_Rule{Type: &corev1.Service_Spec_DynamicConfig_Rule_Opa{Opa: "package octelium.eval\nresult := {\"upstream\": 42}"}}, false},
		{"OPAInvalidConfig", &corev1.Service_Spec_DynamicConfig_Rule{Type: &corev1.Service_Spec_DynamicConfig_Rule_Opa{Opa: "package octelium.eval\nresult := {\"upstream\": {\"url\": \"invalid\"}}"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, coreC := newAuthorizationService(t)
			if tc.rule.Condition == nil {
				tc.rule.Condition = &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}
			}
			coreC.service.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Rules: []*corev1.Service_Spec_DynamicConfig_Rule{
				tc.rule,
				{Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
					Type: &corev1.Service_Spec_DynamicConfig_Rule_ConfigName{ConfigName: "fallback"}},
			}}
			resp := &coctovigilv1.AuthenticateAndAuthorizeResponse{RequestContext: &corev1.RequestContext{Service: coreC.service}}
			err := srv.s.setServiceConfig(t.Context(), resp)
			assert.Equal(t, tc.isErr, err != nil)
			assert.Nil(t, resp.Config)
			if tc.isErr {
				assert.Empty(t, resp.ServiceConfigName)
			} else {
				assert.Equal(t, "fallback", resp.ServiceConfigName)
			}
		})
	}
	for _, expression := range []string{`{"parent": "missing"}`, `{"upstream": {"url": "http://example.com"}}`} {
		srv, coreC := newAuthorizationService(t)
		coreC.service.Spec.DynamicConfig = &corev1.Service_Spec_DynamicConfig{Rules: []*corev1.Service_Spec_DynamicConfig_Rule{{
			Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
			Type:      &corev1.Service_Spec_DynamicConfig_Rule_Eval{Eval: expression},
		}}}
		resp := &coctovigilv1.AuthenticateAndAuthorizeResponse{RequestContext: &corev1.RequestContext{Service: coreC.service}}
		err := srv.s.setServiceConfig(t.Context(), resp)
		if strings.Contains(expression, "upstream") {
			assert.Nil(t, err)
			assert.Equal(t, "http://example.com", resp.Config.Upstream.GetUrl())
		} else {
			assert.NotNil(t, err)
		}
	}
}

type authorizationController[T proto.Message] interface {
	OnAdd(context.Context, T) error
	OnUpdate(context.Context, T, T) error
	OnDelete(context.Context, T) error
}

func testAuthorizationController[T proto.Message](t *testing.T, controller authorizationController[T],
	original, updated T, keys []string, get func(string) (T, error)) {
	t.Helper()
	assert.Nil(t, controller.OnAdd(t.Context(), original))
	for _, key := range keys {
		got, err := get(key)
		assert.Nil(t, err)
		assert.True(t, proto.Equal(original, got))
	}
	assert.Nil(t, controller.OnUpdate(t.Context(), updated, original))
	for _, key := range keys {
		got, err := get(key)
		assert.Nil(t, err)
		assert.True(t, proto.Equal(updated, got))
	}
	assert.Nil(t, controller.OnDelete(t.Context(), updated))
	assert.Nil(t, controller.OnDelete(t.Context(), updated))
	for _, key := range keys {
		_, err := get(key)
		assert.ErrorIs(t, err, acache.ErrNotFound)
	}
}

func TestAuthorizationControllers(t *testing.T) {
	srv, _ := newAuthorizationService(t)
	cache := srv.s.GetCache()
	assert.Same(t, srv.s.cache, cache)
	md := &metav1.Metadata{Uid: "uid", Name: "name"}
	updated := &metav1.Metadata{Uid: "uid", Name: "name", DisplayName: "updated"}
	t.Run("User", func(t *testing.T) {
		testAuthorizationController(t, usercontroller.NewController(cache),
			&corev1.User{Metadata: md}, &corev1.User{Metadata: updated, Spec: &corev1.User_Spec{IsDisabled: true}},
			[]string{"uid"}, cache.GetUser)
	})
	t.Run("Device", func(t *testing.T) {
		testAuthorizationController(t, devicecontroller.NewController(cache),
			&corev1.Device{Metadata: md}, &corev1.Device{Metadata: updated, Status: &corev1.Device_Status{IsLocked: true}},
			[]string{"uid"}, cache.GetDevice)
	})
	t.Run("Service", func(t *testing.T) {
		testAuthorizationController(t, svccontroller.NewController(cache),
			&corev1.Service{Metadata: md}, &corev1.Service{Metadata: updated, Spec: &corev1.Service_Spec{IsPublic: true}},
			[]string{"uid"}, cache.GetService)
	})
	t.Run("Group", func(t *testing.T) {
		testAuthorizationController(t, groupcontroller.NewController(cache),
			&corev1.Group{Metadata: md}, &corev1.Group{Metadata: updated},
			[]string{"uid", "name"}, cache.GetGroup)
	})
	t.Run("Policy", func(t *testing.T) {
		testAuthorizationController(t, policycontroller.NewController(cache),
			&corev1.Policy{Metadata: md}, &corev1.Policy{Metadata: updated, Spec: &corev1.Policy_Spec{IsDisabled: true}},
			[]string{"uid", "name"}, cache.GetPolicy)
	})
	t.Run("Namespace", func(t *testing.T) {
		testAuthorizationController(t, nscontroller.NewController(cache),
			&corev1.Namespace{Metadata: md}, &corev1.Namespace{Metadata: updated},
			[]string{"uid", "name"}, cache.GetNamespace)
	})
	t.Run("Session", func(t *testing.T) {
		original := &corev1.Session{Metadata: md, Status: &corev1.Session_Status{}}
		updated := &corev1.Session{Metadata: updated, Status: &corev1.Session_Status{IsLocked: true,
			Connection: &corev1.Session_Status_Connection{Addresses: []*metav1.DualStackNetwork{{V4: "100.64.0.99/32"}}},
		}}
		testAuthorizationController(t, sesscontroller.NewController(cache), original, updated,
			[]string{"uid", "name"}, cache.GetSession)
		_, err := cache.GetSession("100.64.0.99")
		assert.ErrorIs(t, err, acache.ErrNotFound)
	})
	assert.Nil(t, srv.s.Close())
	assert.Nil(t, srv.s.Close())
}

type failingPolicyTriggerCtl struct {
	err error
}

func (c *failingPolicyTriggerCtl) SetPolicyTrigger(trigger *corev1.PolicyTrigger) error {
	return c.err
}

func (c *failingPolicyTriggerCtl) DeletePolicyTrigger(trigger *corev1.PolicyTrigger) error {
	return c.err
}

func TestPolicyTriggerController(t *testing.T) {
	srv, _ := newAuthorizationService(t)
	ctl := ptctl.NewController(srv.s.GetPolicyTriggerCtl())
	trigger := &corev1.PolicyTrigger{Metadata: &metav1.Metadata{Uid: "trigger"}, Status: &corev1.PolicyTrigger_Status{}}
	assert.Nil(t, ctl.OnAdd(t.Context(), trigger))
	assert.Same(t, trigger, srv.s.policyTriggerCtl.ptMap["trigger"])
	updated := proto.Clone(trigger).(*corev1.PolicyTrigger)
	updated.Status.IsDisabled = true
	assert.Nil(t, ctl.OnUpdate(t.Context(), updated, trigger))
	assert.Same(t, updated, srv.s.policyTriggerCtl.ptMap["trigger"])
	assert.Nil(t, ctl.OnDelete(t.Context(), updated))
	assert.Nil(t, ctl.OnDelete(t.Context(), updated))
	assert.Empty(t, srv.s.policyTriggerCtl.ptMap)
	errTst := errors.New("trigger update failed")
	failing := ptctl.NewController(&failingPolicyTriggerCtl{err: errTst})
	assert.ErrorIs(t, failing.OnAdd(t.Context(), trigger), errTst)
	assert.ErrorIs(t, failing.OnUpdate(t.Context(), updated, trigger), errTst)
	assert.ErrorIs(t, failing.OnDelete(t.Context(), updated), errTst)
}

func TestAuthenticationTokenIntegrity(t *testing.T) {
	tst, err := tests.Initialize(nil)
	if !assert.Nil(t, err) {
		return
	}
	t.Cleanup(func() { tst.Destroy() })
	jwk, err := jwkctl.NewJWKController(t.Context(), tst.C.OcteliumC, nil)
	if !assert.Nil(t, err) {
		return
	}
	for _, mode := range []string{"Header", "Cookie", "Bearer", "Malformed", "Tampered", "RefreshToken", "ExpiredSession", "RefreshCache", "RevokedToken", "MissingSession", "Unavailable"} {
		t.Run(mode, func(t *testing.T) {
			srv, coreC := newAuthorizationService(t)
			srv.s.jwkCtl = jwk
			coreC.service.Spec.IsPublic = true
			downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
			session := downstream.session
			session.Status.Authentication.TokenID = vutils.UUIDv4()
			session.Status.Authentication.SetAt = timestamppb.New(time.Now())
			session.Status.Authentication.AccessTokenDuration = &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 1}}
			session.Status.Authentication.RefreshTokenDuration = &metav1.Duration{Type: &metav1.Duration_Hours{Hours: 2}}
			token, err := jwk.CreateAccessToken(session)
			if !assert.Nil(t, err) {
				return
			}
			headers := map[string]string{"x-octelium-auth": token}
			switch mode {
			case "Cookie":
				headers = map[string]string{"cookie": "octelium_auth=" + token}
			case "Bearer":
				headers = map[string]string{"authorization": "Bearer " + token}
			case "Malformed":
				headers["x-octelium-auth"] = "invalid\x00token"
			case "Tampered":
				headers["x-octelium-auth"] = token[:len(token)-1] + "!"
			case "RefreshToken":
				headers["x-octelium-auth"], err = jwk.CreateRefreshToken(session)
				assert.Nil(t, err)
			case "ExpiredSession":
				session.Spec.ExpiresAt = timestamppb.New(time.Now().Add(-time.Hour))
			case "RefreshCache", "RevokedToken", "MissingSession", "Unavailable":
				cached := proto.Clone(session).(*corev1.Session)
				cached.Status.Authentication.TokenID = vutils.UUIDv4()
				assert.Nil(t, srv.s.cache.SetSession(cached))
				switch mode {
				case "RevokedToken":
					session.Status.Authentication.TokenID = vutils.UUIDv4()
				case "MissingSession":
					downstream.errs["session"] = status.Error(codes.NotFound, "Session not found")
				case "Unavailable":
					downstream.errs["session"] = status.Error(codes.Unavailable, "Session backend unavailable")
				}
			}
			di, err := srv.s.Authenticate(t.Context(), &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: coreC.service,
				Request: &coctovigilv1.DownstreamRequest{
					Source: &coctovigilv1.DownstreamRequest_Source{Address: "192.0.2.1"},
					Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
						Http: &corev1.RequestContext_Request_HTTP{Headers: headers},
					}},
				},
			})
			switch mode {
			case "Header", "Cookie", "Bearer", "RefreshCache":
				assert.Nil(t, err)
				if assert.NotNil(t, di) {
					assert.Equal(t, session.Metadata.Uid, di.Session.Metadata.Uid)
				}
			case "Unavailable":
				assert.Nil(t, di)
				assert.NotNil(t, err)
				assert.False(t, errors.Is(err, UnauthenticatedErr))
			default:
				assert.Nil(t, di)
				assert.ErrorIs(t, err, UnauthenticatedErr)
			}
		})
	}
}

func TestClientlessForwardedAddress(t *testing.T) {
	tst, err := tests.Initialize(nil)
	if !assert.Nil(t, err) {
		return
	}
	t.Cleanup(func() { tst.Destroy() })
	cc, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(t.Context())
	assert.Nil(t, err)
	if cc.Spec.Ingress == nil {
		cc.Spec.Ingress = &corev1.ClusterConfig_Spec_Ingress{}
	}
	cc.Spec.Ingress.UseForwardedForHeader = true
	_, err = tst.C.OcteliumC.CoreC().UpdateClusterConfig(t.Context(), cc)
	assert.Nil(t, err)
	controller, err := ccctl.New(t.Context(), tst.C.OcteliumC, nil)
	assert.Nil(t, err)
	for _, address := range []string{"", "192.0.2.1", "192.0.2.2"} {
		t.Run(address, func(t *testing.T) {
			srv, coreC := newAuthorizationService(t)
			srv.s.ccCtl = controller
			coreC.service.Spec.IsPublic = true
			downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
			downstream.session.Status.Type = corev1.Session_Status_CLIENTLESS
			downstream.session.Status.Authentication.Info = &corev1.Session_Status_Authentication_Info{
				Downstream: &corev1.Session_Status_Authentication_Info_Downstream{IpAddress: "192.0.2.1"},
			}
			di, err := srv.s.GetDownstreamInfo(t.Context(), downstream.session.Metadata.Uid)
			assert.Nil(t, err)
			req := srv.s.getReqCtx(di, &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
				Http: &corev1.RequestContext_Request_HTTP{Headers: map[string]string{
					strings.ToLower(vutils.GetDownstreamIPHeaderCanonical()): address,
				}},
			}}, coreC.service)
			resp, err := srv.s.DoAuthorize(t.Context(), req, nil)
			assert.Nil(t, err)
			assert.Equal(t, address != "192.0.2.2", resp.IsAuthorized)
		})
	}
}

type constructorUtils struct {
	config *corev1.ClusterConfig
	calls  int
	failAt int
	err    error
}

func (c *constructorUtils) GetClusterConfig(ctx context.Context) (*corev1.ClusterConfig, error) {
	c.calls++
	if c.calls == c.failAt {
		return nil, c.err
	}
	return c.config, nil
}

type constructorOcteliumC struct {
	octeliumc.ClientInterface
	utils octeliumc.CoreV1Utils
}

func (c *constructorOcteliumC) CoreV1Utils() octeliumc.CoreV1Utils {
	return c.utils
}

func TestNewServerConfiguration(t *testing.T) {
	tst, err := tests.Initialize(nil)
	if !assert.Nil(t, err) {
		return
	}
	t.Cleanup(func() { tst.Destroy() })
	base, err := tst.C.OcteliumC.CoreV1Utils().GetClusterConfig(t.Context())
	assert.Nil(t, err)
	for _, tc := range []struct {
		name  string
		v4    string
		v6    string
		isErr bool
	}{
		{"IPv4Only", "100.64.0.0/10", "", false},
		{"IPv6Only", "", "fd00::/64", false},
		{"DualStack", "100.64.0.0/10", "fd00::/64", false},
		{"NoPrefixes", "", "", false},
		{"InvalidIPv4", "not-a-prefix", "fd00::/64", true},
		{"InvalidIPv6", "100.64.0.0/10", "fd00::/129", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc := proto.Clone(base).(*corev1.ClusterConfig)
			cc.Status.Network.ClusterNetwork.V4 = tc.v4
			cc.Status.Network.ClusterNetwork.V6 = tc.v6
			client := &constructorOcteliumC{ClientInterface: tst.C.OcteliumC, utils: &constructorUtils{config: cc}}
			srv, err := New(t.Context(), client)
			assert.Equal(t, tc.isErr, err != nil)
			if tc.isErr {
				assert.Nil(t, srv)
				return
			}
			if !assert.NotNil(t, srv) {
				return
			}
			assert.Equal(t, base.Status.Domain, srv.domain)
			assert.Equal(t, tc.v4 != "", srv.v4Prefix != nil)
			assert.Equal(t, tc.v6 != "", srv.v6Prefix != nil)
			assert.NotNil(t, srv.GetCache())
			assert.NotNil(t, srv.GetPolicyTriggerCtl())
			assert.Nil(t, srv.Close())
		})
	}
	for _, step := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("ClusterConfigFailure%d", step), func(t *testing.T) {
			errTst := errors.New("could not load ClusterConfig")
			client := &constructorOcteliumC{ClientInterface: tst.C.OcteliumC,
				utils: &constructorUtils{config: base, failAt: step, err: errTst}}
			srv, err := New(t.Context(), client)
			assert.Nil(t, srv)
			assert.ErrorIs(t, err, errTst)
		})
	}
}

func TestPublicServiceMissingAuthentication(t *testing.T) {
	for _, request := range []*coctovigilv1.DownstreamRequest{
		{},
		{Request: &corev1.RequestContext_Request{}},
		{Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{Http: &corev1.RequestContext_Request_HTTP{}}}},
	} {
		srv, coreC := newAuthorizationService(t)
		coreC.service.Spec.IsPublic = true
		di, err := srv.s.Authenticate(t.Context(), &coctovigilv1.DoAuthenticateAndAuthorizeRequest{Service: coreC.service, Request: request})
		assert.Nil(t, di)
		assert.ErrorIs(t, err, UnauthenticatedErr)
		assert.Empty(t, coreC.calls)
	}
	srv, _ := newAuthorizationService(t)
	di, err := srv.s.Authenticate(t.Context(), &coctovigilv1.DoAuthenticateAndAuthorizeRequest{})
	assert.Nil(t, di)
	assert.ErrorIs(t, err, UnauthenticatedErr)
}

func TestAuthenticateAndAuthorizeInvalidRequest(t *testing.T) {
	for _, field := range []string{"Request", "Service"} {
		t.Run(field, func(t *testing.T) {
			srv, coreC := newAuthorizationService(t)
			req := &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
				Service: proto.Clone(coreC.service).(*corev1.Service), Request: &coctovigilv1.DownstreamRequest{},
			}
			switch field {
			case "Request":
				req = nil
			case "Service":
				req.Service = nil
			}
			assert.NotPanics(t, func() {
				resp, err := srv.s.AuthenticateAndAuthorize(t.Context(), req)
				assert.Nil(t, resp)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			})
			assert.Empty(t, coreC.calls)
		})
	}
}

func TestAuthorizeNilRequestContext(t *testing.T) {
	srv, coreC := newAuthorizationService(t)
	assert.NotPanics(t, func() {
		resp, err := srv.s.DoAuthorize(t.Context(), nil, nil)
		assert.Nil(t, resp)
		assert.NotNil(t, err)
	})
	assert.Empty(t, coreC.calls)
}
