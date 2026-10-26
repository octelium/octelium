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
	"errors"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGetDecision(t *testing.T) {

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

	genSvcWithNS := func(ns string, auth *corev1.Service_Spec_Authorization) *corev1.Service {
		svc, err := adminSrv.CreateService(ctx, &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), ns),
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
				Authorization: auth,
			},
		})
		assert.Nil(t, err)
		return svc
	}

	genSvc := func(auth *corev1.Service_Spec_Authorization) *corev1.Service {
		return genSvcWithNS("default", auth)
	}

	genGroup := func(auth *corev1.Group_Spec_Authorization) *corev1.Group {
		ret, err := adminSrv.CreateGroup(ctx, &corev1.Group{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Group_Spec{

				Authorization: auth,
			},
		})
		assert.Nil(t, err)
		return ret
	}

	genPolicy := func(spec *corev1.Policy_Spec) *corev1.Policy {
		ret, err := adminSrv.CreatePolicy(ctx, &corev1.Policy{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: spec,
		})
		assert.Nil(t, err)
		return ret
	}

	genPolicyWithParent := func(spec *corev1.Policy_Spec, parent *corev1.Policy) *corev1.Policy {
		ret, err := adminSrv.CreatePolicy(ctx, &corev1.Policy{
			Metadata: &metav1.Metadata{
				Name: fmt.Sprintf("%s.%s", utilrand.GetRandomStringCanonical(8), parent.Metadata.Name),
			},
			Spec: spec,
		})
		assert.Nil(t, err)
		return ret
	}

	genNamespace := func(auth *corev1.Namespace_Spec_Authorization) *corev1.Namespace {
		ret, err := adminSrv.CreateNamespace(ctx, &corev1.Namespace{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Namespace_Spec{

				Authorization: auth,
			},
		})
		assert.Nil(t, err)
		return ret
	}

	t.Run("no policies", func(t *testing.T) {
		svc, err := adminSrv.CreateService(ctx, tests.GenService(""))
		assert.Nil(t, err)
		svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svcV)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
	})

	t.Run("svc allow", func(t *testing.T) {
		svc := genSvc(&corev1.Service_Spec_Authorization{
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
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)

		{
			svc.Spec.Authorization.InlinePolicies[0].Spec.IsDisabled = true
			srv.cache.SetService(svc)

			resp, err := srv.getDecision(ctx, &getDecisionReq{
				i: &corev1.RequestContext{
					Service: svc,
					Session: usr.Session,
					User:    usr.Usr,
					Device:  usr.Device,
					Groups:  usr.MustGetGroups(ctx),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
		}

		{
			svc.Spec.Authorization.InlinePolicies[0].Spec.IsDisabled = false
			srv.cache.SetService(svc)

			resp, err := srv.getDecision(ctx, &getDecisionReq{
				i: &corev1.RequestContext{
					Service: svc,
					Session: usr.Session,
					User:    usr.Usr,
					Device:  usr.Device,
					Groups:  usr.MustGetGroups(ctx),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
			assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
		}
	})

	t.Run("svc allow condition", func(t *testing.T) {

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		svc := genSvc(&corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{

									Type: &corev1.Condition_All_{
										All: &corev1.Condition_All{
											Of: []*corev1.Condition{
												{
													Type: &corev1.Condition_Match{
														Match: fmt.Sprintf(`ctx.user.metadata.name == "%s"`, usr.Usr.Metadata.Name),
													},
												},
												{
													Type: &corev1.Condition_Match{
														Match: fmt.Sprintf(`ctx.user.metadata.uid == "%s"`, usr.Usr.Metadata.Uid),
													},
												},
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

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("svc allow condition with attrs", func(t *testing.T) {

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		attrs, err := structpb.NewStruct(map[string]any{
			"k1": "v1",
			"k2": "v2",
		})
		assert.Nil(t, err)

		svc := genSvc(&corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Attrs: attrs,
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{

									Type: &corev1.Condition_All_{
										All: &corev1.Condition_All{
											Of: []*corev1.Condition{
												{
													Type: &corev1.Condition_Match{
														Match: fmt.Sprintf(`ctx.user.metadata.name == "%s"`, usr.Usr.Metadata.Name),
													},
												},
												{
													Type: &corev1.Condition_Match{
														Match: fmt.Sprintf(`ctx.user.metadata.uid == "%s"`, usr.Usr.Metadata.Uid),
													},
												},
												{
													Type: &corev1.Condition_Match{
														Match: `attrs.k1 == "v1"`,
													},
												},
												{
													Type: &corev1.Condition_Match{
														Match: `attrs.k2 in ["v2", "v3"]`,
													},
												},
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

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("svc allow and deny", func(t *testing.T) {
		svc := genSvc(&corev1.Service_Spec_Authorization{
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
							{
								Effect: corev1.Policy_Spec_Rule_DENY,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
	})

	t.Run("svc deny/group allow", func(t *testing.T) {
		svc := genSvc(&corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_DENY,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		grp := genGroup(&corev1.Group_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		})

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, []string{
			grp.Metadata.Name,
		},
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
	})

	t.Run("group allow", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		grp := genGroup(&corev1.Group_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		})

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, []string{
			grp.Metadata.Name,
		},
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("group allow/user deny", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		grp := genGroup(&corev1.Group_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		})

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, []string{
			grp.Metadata.Name,
		},
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		usr.Usr.Spec.Authorization = &corev1.User_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_DENY,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		}
		usr.Usr, err = adminSrv.UpdateUser(ctx, usr.Usr)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
	})

	t.Run("user allow", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		usr.Usr.Spec.Authorization = &corev1.User_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		}
		usr.Usr, err = adminSrv.UpdateUser(ctx, usr.Usr)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("allow namespace", func(t *testing.T) {

		ns := genNamespace(&corev1.Namespace_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		})
		svc := genSvcWithNS(ns.Metadata.Name, nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("deny namespace/allow svc", func(t *testing.T) {

		ns := genNamespace(&corev1.Namespace_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_DENY,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		})
		svc := genSvcWithNS(ns.Metadata.Name, &corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
	})

	t.Run("no inline", func(t *testing.T) {
		p1 := genPolicy(&corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})

		svc := genSvc(&corev1.Service_Spec_Authorization{
			Policies: []string{p1.Metadata.Name},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		{
			resp, err := srv.getDecision(ctx, &getDecisionReq{
				i: &corev1.RequestContext{
					Service: svc,
					Session: usr.Session,
					User:    usr.Usr,
					Device:  usr.Device,
					Groups:  usr.MustGetGroups(ctx),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
			assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
		}

		{
			p1.Spec.IsDisabled = true
			srv.cache.SetPolicy(p1)

			resp, err := srv.getDecision(ctx, &getDecisionReq{
				i: &corev1.RequestContext{
					Service: svc,
					Session: usr.Session,
					User:    usr.Usr,
					Device:  usr.Device,
					Groups:  usr.MustGetGroups(ctx),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
			assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)

			p1.Spec.IsDisabled = false
			srv.cache.SetPolicy(p1)
		}

		p2 := genPolicy(&corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_DENY,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})

		svc.Spec.Authorization.Policies = append(svc.Spec.Authorization.Policies, p2.Metadata.Name)

		{
			resp, err := srv.getDecision(ctx, &getDecisionReq{
				i: &corev1.RequestContext{
					Service: svc,
					Session: usr.Session,
					User:    usr.Usr,
					Device:  usr.Device,
					Groups:  usr.MustGetGroups(ctx),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
			assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
		}

		{
			p2.Spec.IsDisabled = true
			srv.cache.SetPolicy(p2)

			resp, err := srv.getDecision(ctx, &getDecisionReq{
				i: &corev1.RequestContext{
					Service: svc,
					Session: usr.Session,
					User:    usr.Usr,
					Device:  usr.Device,
					Groups:  usr.MustGetGroups(ctx),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
			assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)

			p2.Spec.IsDisabled = false
			srv.cache.SetPolicy(p2)
		}
	})

	t.Run("inline AND no inline", func(t *testing.T) {
		p1 := genPolicy(&corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})

		svc := genSvc(&corev1.Service_Spec_Authorization{
			Policies: []string{p1.Metadata.Name},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		{
			resp, err := srv.getDecision(ctx, &getDecisionReq{
				i: &corev1.RequestContext{
					Service: svc,
					Session: usr.Session,
					User:    usr.Usr,
					Device:  usr.Device,
					Groups:  usr.MustGetGroups(ctx),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
			assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
		}

		svc.Spec.Authorization.InlinePolicies = []*corev1.InlinePolicy{
			{
				Spec: &corev1.Policy_Spec{
					Rules: []*corev1.Policy_Spec_Rule{
						{
							Effect: corev1.Policy_Spec_Rule_DENY,
							Condition: &corev1.Condition{
								Type: &corev1.Condition_Match{
									Match: `2 > 1`,
								},
							},
						},
					},
				},
			},
		}

		{
			resp, err := srv.getDecision(ctx, &getDecisionReq{
				i: &corev1.RequestContext{
					Service: svc,
					Session: usr.Session,
					User:    usr.Usr,
					Device:  usr.Device,
					Groups:  usr.MustGetGroups(ctx),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
			assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
		}
	})

	t.Run("session allow", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		usr.Session.Spec.Authorization = &corev1.Session_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		}

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("session allow/svc deny", func(t *testing.T) {
		svc := genSvc(&corev1.Service_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_DENY,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		usr.Session.Spec.Authorization = &corev1.Session_Spec_Authorization{
			InlinePolicies: []*corev1.InlinePolicy{
				{
					Spec: &corev1.Policy_Spec{
						Rules: []*corev1.Policy_Spec_Rule{
							{
								Effect: corev1.Policy_Spec_Rule_ALLOW,
								Condition: &corev1.Condition{
									Type: &corev1.Condition_Match{
										Match: `2 > 1`,
									},
								},
							},
						},
					},
				},
			},
		}

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
	})

	t.Run("import basic", func(t *testing.T) {

		p1 := genPolicy(&corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})

		p2 := genPolicyWithParent(&corev1.Policy_Spec{}, p1)
		svc := genSvc(&corev1.Service_Spec_Authorization{
			Policies: []string{p2.Metadata.Name},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
		assert.Equal(t, p1.Metadata.Uid,
			resp.reason.GetDetails().GetPolicyMatch().GetPolicy().PolicyRef.Uid)
	})

	t.Run("import with attrs", func(t *testing.T) {

		p1Attrs, err := structpb.NewStruct(map[string]any{
			"k1": "v11",
		})
		assert.Nil(t, err)
		p1 := genPolicy(&corev1.Policy_Spec{
			Attrs: p1Attrs,
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{

						Type: &corev1.Condition_All_{
							All: &corev1.Condition_All{
								Of: []*corev1.Condition{
									{
										Type: &corev1.Condition_Match{
											Match: `2 > 1`,
										},
									},
									{
										Type: &corev1.Condition_Match{
											Match: `attrs.k1 == "v11"`,
										},
									},
								},
							},
						},
					},
				},
			},
		})

		p2 := genPolicyWithParent(&corev1.Policy_Spec{}, p1)
		svc := genSvc(&corev1.Service_Spec_Authorization{
			Policies: []string{p2.Metadata.Name},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
		assert.Equal(t, p1.Metadata.Uid,
			resp.reason.GetDetails().GetPolicyMatch().GetPolicy().PolicyRef.Uid)
	})

	/*
		t.Run("import in inline", func(t *testing.T) {

			p1 := genPolicy(&corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					{
						Effect: corev1.Policy_Spec_Rule_ALLOW,
						Conditions: []*metav1.Condition{
							{
								Type: &metav1.Condition_All_{
									All: &metav1.Condition_All{
										Expressions: []string{
											`2 > 1`,
										},
									},
								},
							},
						},
					},
				},
			})

			svc := genSvc(&corev1.Service_Spec_Authorization{
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							ImportRulesFromPolicies: []string{p1.Metadata.Name},
						},
					},
				},
			})

			srv, err := New(ctx, tst.C.OcteliumC)
			assert.Nil(t, err)
			srv.cache.SetService(svc)

			usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)
			srv.cache.SetUser(usr.Usr)

			resp, err := srv.getDecision(ctx, &getDecisionReq{
				i: &corev1.RequestContext{
					Service: svc,
					Session: usr.Session,
					User:    usr.Usr,
					Device:  usr.Device,
					Groups:  usr.MustGetGroups(ctx),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
			assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
		})
	*/

	/*
		t.Run("import circular", func(t *testing.T) {

			p1 := genPolicy(&corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{
					{
						Effect: corev1.Policy_Spec_Rule_ALLOW,
						Conditions: []*metav1.Condition{
							{
								Type: &metav1.Condition_All_{
									All: &metav1.Condition_All{
										Expressions: []string{
											`2 > 1`,
										},
									},
								},
							},
						},
					},
				},
			})

			p2 := genPolicy(&corev1.Policy_Spec{
				ImportRulesFromPolicies: []string{p1.Metadata.Name},
			})

			p1.Spec.ImportRulesFromPolicies = []string{
				p2.Metadata.Name,
			}
			p1, err = tst.C.OcteliumC.CoreC().UpdatePolicy(ctx, p1)
			assert.Nil(t, err)

			svc := genSvc(&corev1.Service_Spec_Authorization{
				Policies: []string{p2.Metadata.Name},
			})

			srv, err := New(ctx, tst.C.OcteliumC)
			assert.Nil(t, err)
			srv.cache.SetService(svc)

			usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)
			srv.cache.SetUser(usr.Usr)

			resp, err := srv.getDecision(ctx, &getDecisionReq{
				i: &corev1.RequestContext{
					Service: svc,
					Session: usr.Session,
					User:    usr.Usr,
					Device:  usr.Device,
					Groups:  usr.MustGetGroups(ctx),
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
			assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
			assert.Equal(t, p2.Metadata.Uid,
				resp.reason.GetDetails().GetPolicyMatch().GetPolicy().PolicyRef.Uid)
		})
	*/

	t.Run("enforcement ignore", func(t *testing.T) {

		p1 := genPolicy(&corev1.Policy_Spec{
			EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{
				{
					Effect: corev1.Policy_Spec_EnforcementRule_IGNORE,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})

		svc := genSvc(&corev1.Service_Spec_Authorization{
			Policies: []string{p1.Metadata.Name},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
	})

	t.Run("enforcement ignore with attrs ", func(t *testing.T) {

		p1Attrs, err := structpb.NewStruct(map[string]any{
			"k1": "v12",
		})
		assert.Nil(t, err)

		p1 := genPolicy(&corev1.Policy_Spec{
			Attrs: p1Attrs,
			EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{
				{
					Effect: corev1.Policy_Spec_EnforcementRule_IGNORE,
					Condition: &corev1.Condition{

						Type: &corev1.Condition_All_{
							All: &corev1.Condition_All{
								Of: []*corev1.Condition{
									{
										Type: &corev1.Condition_Match{
											Match: `2 > 1`,
										},
									},
									{
										Type: &corev1.Condition_Match{
											Match: `attrs.k1 == "v12"`,
										},
									},
								},
							},
						},
					},
				},
			},
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})

		svc := genSvc(&corev1.Service_Spec_Authorization{
			Policies: []string{p1.Metadata.Name},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
	})

	t.Run("enforcement ignore AND enforce", func(t *testing.T) {

		p1 := genPolicy(&corev1.Policy_Spec{
			EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
					Effect: corev1.Policy_Spec_EnforcementRule_IGNORE,
				},
				{
					Effect: corev1.Policy_Spec_EnforcementRule_ENFORCE,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})

		svc := genSvc(&corev1.Service_Spec_Authorization{
			Policies: []string{p1.Metadata.Name},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("import with enforcement in child", func(t *testing.T) {

		p1 := genPolicy(&corev1.Policy_Spec{

			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})

		p2 := genPolicyWithParent(&corev1.Policy_Spec{
			EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{
				{
					Effect: corev1.Policy_Spec_EnforcementRule_IGNORE,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		}, p1)
		svc := genSvc(&corev1.Service_Spec_Authorization{
			Policies: []string{p2.Metadata.Name},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
		assert.Equal(t, p1.Metadata.Uid,
			resp.reason.GetDetails().GetPolicyMatch().GetPolicy().PolicyRef.Uid)
	})

	t.Run("import with enforcement in both parent and child", func(t *testing.T) {

		p1 := genPolicy(&corev1.Policy_Spec{
			EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{
				{
					Effect: corev1.Policy_Spec_EnforcementRule_IGNORE,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})

		p2 := genPolicyWithParent(&corev1.Policy_Spec{
			EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{
				{
					Effect: corev1.Policy_Spec_EnforcementRule_IGNORE,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		}, p1)
		svc := genSvc(&corev1.Service_Spec_Authorization{
			Policies: []string{p2.Metadata.Name},
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
	})

	t.Run("override", func(t *testing.T) {
		svc := genSvc(&corev1.Service_Spec_Authorization{
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
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)

		svc.Spec.Authorization.InlinePolicies[0].Spec.Rules = append(
			svc.Spec.Authorization.InlinePolicies[0].Spec.Rules,
			&corev1.Policy_Spec_Rule{
				Effect: corev1.Policy_Spec_Rule_DENY,
				Condition: &corev1.Condition{
					Type: &corev1.Condition_MatchAny{
						MatchAny: true,
					},
				},
			},
		)

		srv.cache.SetService(svc)

		resp, err = srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)

		svc.Spec.Authorization.InlinePolicies[0].Spec.Rules = append(
			svc.Spec.Authorization.InlinePolicies[0].Spec.Rules,
			&corev1.Policy_Spec_Rule{
				Effect:   corev1.Policy_Spec_Rule_ALLOW,
				Priority: -1,
				Condition: &corev1.Condition{
					Type: &corev1.Condition_MatchAny{
						MatchAny: true,
					},
				},
			},
		)

		srv.cache.SetService(svc)

		resp, err = srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)

		svc.Spec.Authorization.InlinePolicies[0].Spec.Rules = append(
			svc.Spec.Authorization.InlinePolicies[0].Spec.Rules,
			&corev1.Policy_Spec_Rule{
				Effect:   corev1.Policy_Spec_Rule_DENY,
				Priority: -1,
				Condition: &corev1.Condition{
					Type: &corev1.Condition_MatchAny{
						MatchAny: true,
					},
				},
			},
		)

		srv.cache.SetService(svc)

		resp, err = srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)

		svc.Spec.Authorization.InlinePolicies[0].Spec.Rules = append(
			svc.Spec.Authorization.InlinePolicies[0].Spec.Rules,
			&corev1.Policy_Spec_Rule{
				Effect:   corev1.Policy_Spec_Rule_ALLOW,
				Priority: 2,
				Condition: &corev1.Condition{
					Type: &corev1.Condition_MatchAny{
						MatchAny: true,
					},
				},
			},
		)

		srv.cache.SetService(svc)

		resp, err = srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)

		svc.Spec.Authorization.InlinePolicies[0].Spec.Rules = append(
			svc.Spec.Authorization.InlinePolicies[0].Spec.Rules,
			&corev1.Policy_Spec_Rule{
				Effect:   corev1.Policy_Spec_Rule_ALLOW,
				Priority: -2,
				Condition: &corev1.Condition{
					Type: &corev1.Condition_MatchAny{
						MatchAny: true,
					},
				},
			},
		)

		srv.cache.SetService(svc)

		resp, err = srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("policyTrigger", func(t *testing.T) {
		svc := genSvc(&corev1.Service_Spec_Authorization{
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
		})

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		resp, err := srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)

		ownerRef := umetav1.GetObjectReference(usr.Usr)
		err = srv.policyTriggerCtl.SetPolicyTrigger(&corev1.PolicyTrigger{
			Metadata: &metav1.Metadata{
				Uid:  vutils.UUIDv4(),
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.PolicyTrigger_Spec{},
			Status: &corev1.PolicyTrigger_Status{
				OwnerRef: ownerRef,
				PreCondition: &corev1.PolicyTrigger_Status_PreCondition{
					Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{
						MatchAny: true,
					},
				},
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
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)

		resp, err = srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
		assert.Equal(t, resp.reason.GetDetails().GetPolicyMatch().GetInlinePolicy().ResourceRef.Uid, ownerRef.Uid)

		err = srv.policyTriggerCtl.SetPolicyTrigger(&corev1.PolicyTrigger{
			Metadata: &metav1.Metadata{
				Uid:  vutils.UUIDv4(),
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.PolicyTrigger_Spec{},
			Status: &corev1.PolicyTrigger_Status{
				OwnerRef: ownerRef,
				PreCondition: &corev1.PolicyTrigger_Status_PreCondition{
					Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{
						MatchAny: true,
					},
				},
				InlinePolicies: []*corev1.InlinePolicy{
					{
						Spec: &corev1.Policy_Spec{
							Rules: []*corev1.Policy_Spec_Rule{
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
			},
		})
		assert.Nil(t, err)

		resp, err = srv.getDecision(ctx, &getDecisionReq{
			i: &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
		assert.Equal(t, resp.reason.GetDetails().GetPolicyMatch().GetInlinePolicy().ResourceRef.Uid, ownerRef.Uid)
	})
}

func TestGetDecisionRule(t *testing.T) {

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

	genSvc := func(auth *corev1.Service_Spec_Authorization) *corev1.Service {
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
				Authorization: auth,
			},
		})
		assert.Nil(t, err)
		return svc
	}

	/*
		genGroup := func(auth *corev1.Group_Spec_Authorization) *corev1.Group {
			ret, err := adminSrv.CreateGroup(ctx, &corev1.Group{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
				Spec: &corev1.Group_Spec{

					Authorization: auth,
				},
			})
			assert.Nil(t, err)
			return ret
		}
	*/

	t.Run("empty rule allow", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
	})

	t.Run("empty rule deny", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
	})

	t.Run("matchAny allow", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{
							MatchAny: true,
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("matchAny deny", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_DENY,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{
							MatchAny: true,
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
	})

	t.Run("match allow", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	/*
		t.Run("conflicting conditions", func(t *testing.T) {
			svc := genSvc(nil)

			srv, err := New(ctx, tst.C.OcteliumC)
			assert.Nil(t, err)
			srv.cache.SetService(svc)

			usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)
			srv.cache.SetUser(usr.Usr)

			reqCtx := &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			}

			reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
			assert.Nil(t, err)
			resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
				reqCtxMap: reqCtxMap,
				rule: &policyRule{
					rule: &corev1.Policy_Spec_Rule{
						Effect: corev1.Policy_Spec_Rule_ALLOW,
						Conditions: []*metav1.Condition{
							{
								Type: &metav1.Condition_Match{
									Match: "2 > 1",
								},
							},
							{
								Type: &metav1.Condition_Any_{
									Any: &metav1.Condition_Any{
										Expressions: []string{
											"2 < 1",
										},
									},
								},
							},
						},
					},
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
		})
	*/

	/*
		t.Run("conflicting conditions 2", func(t *testing.T) {
			svc := genSvc(nil)

			srv, err := New(ctx, tst.C.OcteliumC)
			assert.Nil(t, err)
			srv.cache.SetService(svc)

			usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)
			srv.cache.SetUser(usr.Usr)

			reqCtx := &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			}

			reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
			assert.Nil(t, err)
			resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
				reqCtxMap: reqCtxMap,
				rule: &policyRule{
					rule: &corev1.Policy_Spec_Rule{
						Effect: corev1.Policy_Spec_Rule_ALLOW,
						Condition: &corev1.Condition{
							Type: &corev1.Condition_Match{
								Match: `2 > 1`,
							},
						},

					},
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
		})
	*/

	t.Run("conditions basic", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("condition not", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Not{
							Not: `2 < 1`,
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("condition all", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{

						Type: &corev1.Condition_All_{
							All: &corev1.Condition_All{
								Of: []*corev1.Condition{
									{
										Type: &corev1.Condition_Match{
											Match: `2 > 1`,
										},
									},
									{
										Type: &corev1.Condition_Match{
											Match: `3 > 2`,
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
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("conditions any", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{

						Type: &corev1.Condition_Any_{
							Any: &corev1.Condition_Any{
								Of: []*corev1.Condition{
									{
										Type: &corev1.Condition_Match{
											Match: `2 > 1`,
										},
									},
									{
										Type: &corev1.Condition_Match{
											Match: `2 > 3`,
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
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("conditions deny", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_DENY,

					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `2 > 1`,
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
	})

	/*
		t.Run("conflicting all conditions", func(t *testing.T) {
			svc := genSvc(nil)

			srv, err := New(ctx, tst.C.OcteliumC)
			assert.Nil(t, err)
			srv.cache.SetService(svc)

			usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
				corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
			assert.Nil(t, err)
			srv.cache.SetUser(usr.Usr)

			reqCtx := &corev1.RequestContext{
				Service: svc,
				Session: usr.Session,
				User:    usr.Usr,
				Device:  usr.Device,
				Groups:  usr.MustGetGroups(ctx),
			}

			reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
			assert.Nil(t, err)
			resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
				reqCtxMap: reqCtxMap,
				rule: &policyRule{
					rule: &corev1.Policy_Spec_Rule{
						Effect: corev1.Policy_Spec_Rule_ALLOW,
						Conditions: []*metav1.Condition{
							{
								Type: &metav1.Condition_All_{
									All: &metav1.Condition_All{
										Expressions: []string{
											`2 > 1`,
										},
									},
								},
							},
							{
								Type: &metav1.Condition_All_{
									All: &metav1.Condition_All{
										Expressions: []string{
											`2 < 1`,
										},
									},
								},
							},
						},
					},
				},
			})
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
		})
	*/

	t.Run("opa allow", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_ALLOW,

					Condition: &corev1.Condition{
						Type: &corev1.Condition_Opa{
							Opa: &corev1.Condition_OPA{
								Type: &corev1.Condition_OPA_Inline{
									Inline: `
package octelium.condition

default match = false
match if {
	2 > 1
}
									`,
								},
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
		assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
	})

	t.Run("opa no match", func(t *testing.T) {
		svc := genSvc(nil)

		srv, err := New(ctx, tst.C.OcteliumC)
		assert.Nil(t, err)
		srv.cache.SetService(svc)

		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)
		srv.cache.SetUser(usr.Usr)

		reqCtx := &corev1.RequestContext{
			Service: svc,
			Session: usr.Session,
			User:    usr.Usr,
			Device:  usr.Device,
			Groups:  usr.MustGetGroups(ctx),
		}

		reqCtxMap, err := pbutils.ConvertToMap(reqCtx)
		assert.Nil(t, err)
		resp, err := srv.getDecisionRule(ctx, &getDecisionRuleReq{
			reqCtxMap: reqCtxMap,
			rule: &policyRule{
				rule: &corev1.Policy_Spec_Rule{
					Effect: corev1.Policy_Spec_Rule_ALLOW,

					Condition: &corev1.Condition{
						Type: &corev1.Condition_Opa{
							Opa: &corev1.Condition_OPA{
								Type: &corev1.Condition_OPA_Inline{
									Inline: `
package octelium.condition

default match = false
match if {
	2 < 1
}
									`,
								},
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, matchDecisionMATCH_NO, resp.decision)
	})

}

func TestEvaluatePolicyCollection(t *testing.T) {
	srv, coreC := newAuthorizationService(t)
	allow := coreC.service.Spec.Authorization.InlinePolicies[0].Spec.Rules[0]
	attrs, err := structpb.NewStruct(map[string]any{"owner": "alice"})
	assert.Nil(t, err)
	invalidAttrs := &structpb.Struct{Fields: map[string]*structpb.Value{"\xff": structpb.NewStringValue("invalid")}}
	ignore := &corev1.Policy_Spec_EnforcementRule{
		Effect:    corev1.Policy_Spec_EnforcementRule_IGNORE,
		Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}},
	}
	coreC.policies = map[string]*corev1.Policy{
		"base":       {Metadata: &metav1.Metadata{Name: "base", Uid: "base-uid"}, Spec: &corev1.Policy_Spec{Attrs: attrs, Rules: []*corev1.Policy_Spec_Rule{allow}}},
		"base.child": {Metadata: &metav1.Metadata{Name: "base.child", Uid: "child-uid"}, Spec: &corev1.Policy_Spec{IsDisabled: true}},
		"ignored":    {Metadata: &metav1.Metadata{Name: "ignored", Uid: "ignored-uid"}, Spec: &corev1.Policy_Spec{EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{ignore}}},
		"invalid":    {Metadata: &metav1.Metadata{Name: "invalid", Uid: "invalid-uid"}, Spec: &corev1.Policy_Spec{Attrs: invalidAttrs}},
	}
	req := &coctovigilv1.EvaluateRequest{
		Policies: []string{"base.child", "base", "base.child", "ignored", "invalid", "missing"},
		InlinePolicies: []*coctovigilv1.EvaluateRequest_InlinePolicy{
			{Policy: &corev1.InlinePolicy{Name: "disabled", Spec: &corev1.Policy_Spec{IsDisabled: true}}},
			{Policy: &corev1.InlinePolicy{Name: "ignored", Spec: &corev1.Policy_Spec{EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{ignore}}}},
			{Policy: &corev1.InlinePolicy{Name: "invalid", Spec: &corev1.Policy_Spec{Attrs: invalidAttrs}}},
			{Policy: &corev1.InlinePolicy{Name: "inline", Spec: &corev1.Policy_Spec{Attrs: attrs, Rules: []*corev1.Policy_Spec_Rule{allow}}},
				ResourceRef: &metav1.ObjectReference{Uid: "owner", Name: "owner"}},
		},
	}
	for range 2 {
		rules, err := srv.s.getEvaluatePolicyRules(t.Context(), req, map[string]any{})
		if !assert.Nil(t, err) || !assert.Len(t, rules, 2) {
			return
		}
		assert.Equal(t, "base-uid", rules[0].policyRef.Uid)
		assert.Equal(t, "alice", rules[0].attrs["owner"])
		assert.Equal(t, "inline", rules[1].inline.name)
		assert.Equal(t, "owner", rules[1].inline.resourceRef.Uid)
		assert.Equal(t, "alice", rules[1].attrs["owner"])
	}
	var calls int
	for _, call := range coreC.calls {
		if call == "policy:base" {
			calls++
		}
	}
	assert.Equal(t, 1, calls)
	_, err = srv.s.getEvaluatePolicyRules(t.Context(), &coctovigilv1.EvaluateRequest{Policies: []string{"invalid..name"}}, nil)
	assert.NotNil(t, err)
	resp, err := srv.Evaluate(t.Context(), &coctovigilv1.EvaluateRequest{Policies: []string{"invalid..name"}})
	assert.Nil(t, resp)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestResourcePolicyCollection(t *testing.T) {
	srv, coreC := newAuthorizationService(t)
	allow := coreC.service.Spec.Authorization.InlinePolicies[0].Spec.Rules[0]
	invalidAttrs := &structpb.Struct{Fields: map[string]*structpb.Value{"bad": structpb.NewStringValue("\xff")}}
	coreC.policies["disabled"] = &corev1.Policy{Metadata: &metav1.Metadata{Name: "disabled"}, Spec: &corev1.Policy_Spec{IsDisabled: true}}
	coreC.policies["invalid"] = &corev1.Policy{Metadata: &metav1.Metadata{Name: "invalid"}, Spec: &corev1.Policy_Spec{Attrs: invalidAttrs}}
	ignore := &corev1.Policy_Spec_EnforcementRule{Effect: corev1.Policy_Spec_EnforcementRule_IGNORE,
		Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}}
	coreC.policies["ignored"] = &corev1.Policy{Metadata: &metav1.Metadata{Name: "ignored"}, Spec: &corev1.Policy_Spec{EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{ignore}}}
	var used []string
	rules, err := srv.s.getResourcePolicyRules(t.Context(), &corev1.RequestContext{}, nil,
		[]string{"disabled", "invalid", "ignored"}, []*corev1.InlinePolicy{
			{Spec: &corev1.Policy_Spec{IsDisabled: true}},
			{Spec: &corev1.Policy_Spec{Attrs: invalidAttrs}},
			{Spec: &corev1.Policy_Spec{EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{ignore}}},
			{Name: "active", Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{allow}}},
		}, &metav1.ObjectReference{Uid: "owner"}, &used)
	if !assert.Nil(t, err) || !assert.Len(t, rules, 1) {
		return
	}
	assert.Equal(t, "active", rules[0].inline.name)
	assert.Equal(t, "owner", rules[0].inline.resourceRef.Uid)
	assert.Empty(t, used)
}

func TestAuthorizationPolicyNameErrors(t *testing.T) {
	for _, resource := range []string{"service", "namespace", "user", "group", "session", "device", "additional"} {
		t.Run(resource, func(t *testing.T) {
			srv, coreC := newAuthorizationService(t)
			di, err := srv.s.GetDownstreamInfo(t.Context(), "100.64.0.2")
			assert.Nil(t, err)
			req := srv.s.getReqCtx(di, nil, coreC.service)
			names := []string{"invalid..name"}
			var additional *coctovigilv1.Authorization
			switch resource {
			case "service":
				req.Service.Spec.Authorization.Policies = names
			case "namespace":
				req.Namespace.Spec.Authorization = &corev1.Namespace_Spec_Authorization{Policies: names}
			case "user":
				req.User.Spec.Authorization = &corev1.User_Spec_Authorization{Policies: names}
			case "group":
				req.Groups[0].Spec.Authorization = &corev1.Group_Spec_Authorization{Policies: names}
			case "session":
				req.Session.Spec.Authorization = &corev1.Session_Spec_Authorization{Policies: names}
			case "device":
				req.Device.Spec.Authorization = &corev1.Device_Spec_Authorization{Policies: names}
			case "additional":
				additional = &coctovigilv1.Authorization{Policies: names}
			}
			resp, err := srv.s.DoAuthorize(t.Context(), req, additional)
			assert.NotNil(t, err)
			assert.Nil(t, resp)
		})
	}
}

func TestEnforcementRuleEdges(t *testing.T) {
	srv, _ := newAuthorizationService(t)
	for _, tc := range []struct {
		name  string
		rules []*corev1.Policy_Spec_EnforcementRule
		want  bool
	}{
		{"NoCondition", []*corev1.Policy_Spec_EnforcementRule{{Effect: corev1.Policy_Spec_EnforcementRule_IGNORE}}, true},
		{"UnknownEffect", []*corev1.Policy_Spec_EnforcementRule{{Effect: 100}}, true},
		{"IgnoreNoMatch", []*corev1.Policy_Spec_EnforcementRule{{Effect: corev1.Policy_Spec_EnforcementRule_IGNORE, Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: false}}}}, true},
		{"IgnoreError", []*corev1.Policy_Spec_EnforcementRule{{Effect: corev1.Policy_Spec_EnforcementRule_IGNORE, Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: "ctx =="}}}}, true},
		{"EnforceError", []*corev1.Policy_Spec_EnforcementRule{{Effect: corev1.Policy_Spec_EnforcementRule_ENFORCE, Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: "ctx =="}}}}, true},
		{"EnforceNoMatch", []*corev1.Policy_Spec_EnforcementRule{{Effect: corev1.Policy_Spec_EnforcementRule_ENFORCE, Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: false}}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isEnforced, err := srv.s.shouldEnforcePolicy(t.Context(), &shouldEnforcePolicyReq{spec: &corev1.Policy_Spec{EnforcementRules: tc.rules}})
			assert.Nil(t, err)
			assert.Equal(t, tc.want, isEnforced)
		})
	}
}

func TestIsBodyCondition(t *testing.T) {
	match := func(arg string) *corev1.Condition {
		return &corev1.Condition{Type: &corev1.Condition_Match{Match: arg}}
	}
	matchAny := &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}
	opa := func(arg string) *corev1.Condition {
		return &corev1.Condition{Type: &corev1.Condition_Opa{Opa: &corev1.Condition_OPA{Type: &corev1.Condition_OPA_Inline{Inline: arg}}}}
	}

	for _, tc := range []struct {
		condition *corev1.Condition
		want      bool
	}{
		{match(`ctx.request.http.bodyMap.amount > 100`), true},
		{match(`ctx.request.mcp.http.bodyMap.params.arguments.amount > 100`), true},
		{match(`string(ctx.request.http.body).contains("delete")`), true},
		{match(`ctx.request.http["bodyMap"].amount > 100`), true},
		{&corev1.Condition{Type: &corev1.Condition_Not{Not: `has(ctx.request.llm.http.bodyMap)`}}, true},
		{&corev1.Condition{Type: &corev1.Condition_All_{All: &corev1.Condition_All{Of: []*corev1.Condition{matchAny, match(`ctx.request.http.bodyMap.x == 1`)}}}}, true},
		{&corev1.Condition{Type: &corev1.Condition_Any_{Any: &corev1.Condition_Any{Of: []*corev1.Condition{
			{Type: &corev1.Condition_None_{None: &corev1.Condition_None{Of: []*corev1.Condition{match(`ctx.request.http.body == b""`)}}}},
		}}}}, true},
		{opa("package octelium.condition\n\nmatch if {\n\tinput.ctx.request.http.bodyMap.amount > 100\n}\n"), true},

		{match(`ctx.request.http.path == "/admin"`), false},
		{match(`ctx.user.metadata.name == "nobody"`), false},
		{match(`ctx.request.mcp.name == "delete" && ctx.request.http.size > 100`), false},
		{&corev1.Condition{Type: &corev1.Condition_All_{All: &corev1.Condition_All{Of: []*corev1.Condition{matchAny, match(`ctx.request.http.path == "/"`)}}}}, false},
		{opa("package octelium.condition\n\nmatch if {\n\tinput.ctx.request.http.path == \"/\"\n}\n"), false},
		{matchAny, false},
		{nil, false},
	} {
		assert.Equal(t, tc.want, isBodyCondition(tc.condition), "%v", tc.condition)
	}

	bodyPreCondition := &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_Condition{Condition: match(`ctx.request.http.bodyMap.x == 1`)}}
	pathPreCondition := &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_Condition{Condition: match(`ctx.request.http.path == "/"`)}}

	assert.True(t, isBodyPreCondition(bodyPreCondition))
	assert.False(t, isBodyPreCondition(pathPreCondition))
	assert.True(t, isBodyPreCondition(&corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_All_{
		All: &corev1.PolicyTrigger_Status_PreCondition_All{Of: []*corev1.PolicyTrigger_Status_PreCondition{pathPreCondition, {
			Type: &corev1.PolicyTrigger_Status_PreCondition_Any_{Any: &corev1.PolicyTrigger_Status_PreCondition_Any{Of: []*corev1.PolicyTrigger_Status_PreCondition{bodyPreCondition}}},
		}}},
	}}))
	assert.False(t, isBodyPreCondition(&corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{MatchAny: true}}))
	assert.False(t, isBodyPreCondition(nil))
}

func TestIsBodyOmitted(t *testing.T) {
	httpC := &corev1.RequestContext_Request_HTTP{IsBodyOmitted: true}

	for _, req := range []*corev1.RequestContext_Request{
		{Type: &corev1.RequestContext_Request_Http{Http: httpC}},
		{Type: &corev1.RequestContext_Request_Mcp{Mcp: &corev1.RequestContext_Request_MCP{Http: httpC}}},
		{Type: &corev1.RequestContext_Request_Llm{Llm: &corev1.RequestContext_Request_LLM{Http: httpC}}},
	} {
		assert.True(t, isBodyOmitted(&corev1.RequestContext{Request: req}))
	}

	assert.False(t, isBodyOmitted(&corev1.RequestContext{Request: &corev1.RequestContext_Request{
		Type: &corev1.RequestContext_Request_Http{Http: &corev1.RequestContext_Request_HTTP{}}}}))
	assert.False(t, isBodyOmitted(&corev1.RequestContext{}))
	assert.False(t, isBodyOmitted(nil))
}

func TestPolicyBodyOmitted(t *testing.T) {
	srv, _ := newAuthorizationService(t)

	rule := func(name string, priority int32, effect corev1.Policy_Spec_Rule_Effect, arg string) *policyRule {
		condition := &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}
		if arg != "" {
			condition = &corev1.Condition{Type: &corev1.Condition_Match{Match: arg}}
		}
		return &policyRule{rule: &corev1.Policy_Spec_Rule{Name: name, Priority: priority, Effect: effect, Condition: condition}}
	}

	withBody := map[string]any{"request": map[string]any{"http": map[string]any{
		"path": "/", "bodyMap": map[string]any{"amount": int64(5)},
	}}}
	withoutBody := map[string]any{"request": map[string]any{"http": map[string]any{
		"path": "/", "isBodyOmitted": true,
	}}}

	for _, tc := range []struct {
		name          string
		rules         []*policyRule
		reqCtxMap     map[string]any
		isBodyOmitted bool
		effect        corev1.Policy_Spec_Rule_Effect
		ruleName      string
	}{
		{"DenyBodyWithBody",
			[]*policyRule{rule("deny-body", 0, corev1.Policy_Spec_Rule_DENY, `ctx.request.http.bodyMap.amount > 100`), rule("allow-rest", 1, corev1.Policy_Spec_Rule_ALLOW, "")},
			withBody, false, corev1.Policy_Spec_Rule_ALLOW, "allow-rest"},
		{"DenyBodyOmitted",
			[]*policyRule{rule("deny-body", 0, corev1.Policy_Spec_Rule_DENY, `ctx.request.http.bodyMap.amount > 100`), rule("allow-rest", 1, corev1.Policy_Spec_Rule_ALLOW, "")},
			withoutBody, true, corev1.Policy_Spec_Rule_DENY, "deny-body"},
		{"AllowBodyWithBody",
			[]*policyRule{rule("allow-body", 0, corev1.Policy_Spec_Rule_ALLOW, `ctx.request.http.bodyMap.amount < 100`), rule("deny-rest", 1, corev1.Policy_Spec_Rule_DENY, "")},
			withBody, false, corev1.Policy_Spec_Rule_ALLOW, "allow-body"},
		{"AllowBodyOmitted",
			[]*policyRule{rule("allow-body", 0, corev1.Policy_Spec_Rule_ALLOW, `!has(ctx.request.http.bodyMap) || ctx.request.http.bodyMap.amount < 100`), rule("deny-rest", 1, corev1.Policy_Spec_Rule_DENY, "")},
			withoutBody, true, corev1.Policy_Spec_Rule_DENY, "deny-rest"},
		{"NonBodyRuleOmitted",
			[]*policyRule{rule("deny-admin", 0, corev1.Policy_Spec_Rule_DENY, `ctx.request.http.path == "/admin"`), rule("allow-rest", 1, corev1.Policy_Spec_Rule_ALLOW, "")},
			withoutBody, true, corev1.Policy_Spec_Rule_ALLOW, "allow-rest"},
		{"OmittedFlagRule",
			[]*policyRule{rule("deny-omitted", 0, corev1.Policy_Spec_Rule_DENY, `ctx.request.http.isBodyOmitted`), rule("allow-rest", 1, corev1.Policy_Spec_Rule_ALLOW, "")},
			withoutBody, true, corev1.Policy_Spec_Rule_DENY, "deny-omitted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := srv.s.doGetDecision(t.Context(), tc.reqCtxMap, tc.rules, tc.isBodyOmitted)
			assert.Nil(t, err)
			assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
			assert.Equal(t, tc.effect, resp.effect)
			assert.Equal(t, tc.ruleName, resp.reason.Details.GetPolicyMatch().RuleName)
		})
	}

	{
		spec := &corev1.Policy_Spec{EnforcementRules: []*corev1.Policy_Spec_EnforcementRule{{
			Effect:    corev1.Policy_Spec_EnforcementRule_IGNORE,
			Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: `ctx.request.http.bodyMap.env == "dev"`}},
		}}}

		isEnforced, err := srv.s.shouldEnforcePolicy(t.Context(), &shouldEnforcePolicyReq{spec: spec, reqCtxMap: withBody})
		assert.Nil(t, err)
		assert.True(t, isEnforced)

		_, err = srv.s.shouldEnforcePolicy(t.Context(), &shouldEnforcePolicyReq{spec: spec, reqCtxMap: withoutBody, isBodyOmitted: true})
		assert.NotNil(t, err)
	}

	{
		i := &corev1.RequestContext{Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
			Http: &corev1.RequestContext_Request_HTTP{Path: "/", IsBodyOmitted: true},
		}}}
		pt := &corev1.PolicyTrigger{Status: &corev1.PolicyTrigger_Status{PreCondition: &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_Condition{Condition: &corev1.Condition{
				Type: &corev1.Condition_Match{Match: `ctx.request.http.bodyMap.env == "prod"`},
			}},
		}}}

		var usedPolicies []string
		rules, err := srv.s.getRulesFromPolicyTrigger(t.Context(), i, withoutBody, pt, &usedPolicies)
		assert.NotNil(t, err)
		assert.Nil(t, rules)

		i.Request.GetHttp().IsBodyOmitted = false
		rules, err = srv.s.getRulesFromPolicyTrigger(t.Context(), i, withBody, pt, &usedPolicies)
		assert.Nil(t, err)
		assert.Nil(t, rules)
	}
}

func TestPolicyLookupCache(t *testing.T) {
	srv, coreC := newAuthorizationService(t)
	coreC.policies["policy"] = &corev1.Policy{Metadata: &metav1.Metadata{Name: "policy", Uid: "policy-uid"}, Spec: &corev1.Policy_Spec{}}
	assert.Nil(t, srv.s.cache.DeleteNamespace(coreC.namespace))
	for range 2 {
		policy, err := srv.s.getPolicyFromName(t.Context(), "policy")
		assert.Nil(t, err)
		assert.Same(t, coreC.policies["policy"], policy)
		ns, err := srv.s.getNamespaceFromName(t.Context(), "namespace")
		assert.Nil(t, err)
		assert.Same(t, coreC.namespace, ns)
	}
	assert.Equal(t, []string{"policy:policy", "namespace:namespace"}, coreC.calls)
	assert.Nil(t, srv.s.cache.DeletePolicy(coreC.policies["policy"]))
	assert.Nil(t, srv.s.cache.DeleteNamespace(coreC.namespace))
	coreC.errs["policy:policy"] = status.Error(codes.Unavailable, "lookup failed")
	coreC.errs["namespace"] = status.Error(codes.Unavailable, "lookup failed")
	policy, err := srv.s.getPolicyFromName(t.Context(), "policy")
	assert.Nil(t, policy)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	ns, err := srv.s.getNamespaceFromName(t.Context(), "namespace")
	assert.Nil(t, ns)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestPolicyPriorityRange(t *testing.T) {
	srv, _ := newAuthorizationService(t)
	for allowPriority := int32(-4); allowPriority <= 4; allowPriority++ {
		for denyPriority := int32(-4); denyPriority <= 4; denyPriority++ {
			for _, reverse := range []bool{false, true} {
				allow := &policyRule{rule: &corev1.Policy_Spec_Rule{Name: "allow", Priority: allowPriority, Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}}}
				deny := &policyRule{rule: &corev1.Policy_Spec_Rule{Name: "deny", Priority: denyPriority, Effect: corev1.Policy_Spec_Rule_DENY,
					Condition: &corev1.Condition{Type: &corev1.Condition_MatchAny{MatchAny: true}}}}
				rules := []*policyRule{allow, deny}
				if reverse {
					rules[0], rules[1] = rules[1], rules[0]
				}
				resp, err := srv.s.doGetDecision(t.Context(), nil, rules, false)
				if !assert.Nil(t, err) {
					return
				}
				assert.Equal(t, matchDecisionMATCH_YES, resp.decision)
				if allowPriority < denyPriority {
					assert.Equal(t, corev1.Policy_Spec_Rule_ALLOW, resp.effect)
					assert.Equal(t, "allow", resp.reason.Details.GetPolicyMatch().RuleName)
				} else {
					assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.effect)
					assert.Equal(t, "deny", resp.reason.Details.GetPolicyMatch().RuleName)
				}
			}
		}
	}
}

func TestPolicyCollectionAcrossResources(t *testing.T) {
	srv, coreC := newAuthorizationService(t)
	inline := coreC.service.Spec.Authorization.InlinePolicies[0]
	coreC.policies["shared"] = &corev1.Policy{Metadata: &metav1.Metadata{Name: "shared", Uid: "shared-policy"}, Spec: inline.Spec}
	di, err := srv.s.GetDownstreamInfo(t.Context(), "100.64.0.2")
	assert.Nil(t, err)
	req := srv.s.getReqCtx(di, nil, coreC.service)
	names := []string{"shared", "shared"}
	policies := []*corev1.InlinePolicy{inline}
	req.Service.Spec.Authorization = &corev1.Service_Spec_Authorization{Policies: names, InlinePolicies: policies}
	req.Namespace.Spec.Authorization = &corev1.Namespace_Spec_Authorization{Policies: names, InlinePolicies: policies}
	req.User.Spec.Authorization = &corev1.User_Spec_Authorization{Policies: names, InlinePolicies: policies}
	for _, group := range req.Groups {
		group.Spec.Authorization = &corev1.Group_Spec_Authorization{Policies: names, InlinePolicies: policies}
	}
	req.Session.Spec.Authorization = &corev1.Session_Spec_Authorization{Policies: names, InlinePolicies: policies}
	req.Device.Spec.Authorization = &corev1.Device_Spec_Authorization{Policies: names, InlinePolicies: policies}
	rules, err := srv.s.getAllRules(t.Context(), &getDecisionReq{
		i: req, additional: &coctovigilv1.Authorization{Policies: names, InlinePolicies: policies},
	}, pbutils.MustConvertToMap(req))
	if !assert.Nil(t, err) || !assert.Len(t, rules, 9) {
		return
	}
	var standalone int
	var owners []string
	for _, rule := range rules {
		if rule.policyRef != nil {
			standalone++
			assert.Equal(t, "shared-policy", rule.policyRef.Uid)
		} else {
			assert.Equal(t, inline.Name, rule.inline.name)
			owners = append(owners, rule.inline.resourceRef.GetUid())
		}
	}
	assert.Equal(t, 1, standalone)
	assert.ElementsMatch(t, []string{"service", "namespace", "user", "group1", "group2", req.Session.Metadata.Uid, "device", ""}, owners)
}

func TestUnavailablePoliciesCannotGrantAccess(t *testing.T) {
	for _, code := range []codes.Code{codes.NotFound, codes.Unavailable, codes.PermissionDenied, codes.DeadlineExceeded} {
		t.Run(code.String(), func(t *testing.T) {
			srv, coreC := newAuthorizationService(t)
			coreC.service.Spec.Authorization = &corev1.Service_Spec_Authorization{Policies: []string{"missing"}}
			coreC.errs["policy:missing"] = status.Error(code, "Policy lookup failed")
			resp, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
				ServiceUID: "service", Request: &coctovigilv1.DownstreamRequest{Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2"}},
			})
			if err == nil && assert.NotNil(t, resp) {
				assert.False(t, resp.IsAuthorized)
			}
		})
	}
}

func assertAuthorizationLookupError(t *testing.T, srv *internalService, coreC *authorizationCoreC,
	additional *coctovigilv1.Authorization, lookupErr error) {
	t.Helper()
	downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
	di, err := srv.s.GetDownstreamInfo(t.Context(), downstream.session.Metadata.Uid)
	assert.Nil(t, err)
	req := srv.s.getReqCtx(di, nil, coreC.service)
	resp, err := srv.s.DoAuthorize(t.Context(), req, additional)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, lookupErr)
	authenticated, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
		ServiceUID: coreC.service.Metadata.Uid, Additional: additional,
		Request: &coctovigilv1.DownstreamRequest{Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2"}},
	})
	assert.Nil(t, authenticated)
	assert.Equal(t, codes.Internal, status.Code(err))
	authorized, err := srv.Authorize(t.Context(), &coctovigilv1.AuthorizeRequest{
		ServiceUID: coreC.service.Metadata.Uid, SessionUID: downstream.session.Metadata.Uid, Additional: additional,
	})
	assert.Nil(t, authorized)
	assert.ErrorIs(t, err, lookupErr)
}

func TestPolicyLookupFailuresOverrideAllow(t *testing.T) {
	lookupErrors := []error{context.Canceled, context.DeadlineExceeded, errors.New("Policy lookup failed")}
	for _, code := range []codes.Code{codes.Unavailable, codes.Internal, codes.PermissionDenied, codes.ResourceExhausted, codes.DeadlineExceeded, codes.Canceled} {
		lookupErrors = append(lookupErrors, status.Error(code, "Policy lookup failed"))
	}
	for _, resource := range []string{"service", "namespace", "user", "group", "session", "device", "additional", "trigger", "parent"} {
		for _, anonymous := range []bool{false, true} {
			if anonymous && (resource == "user" || resource == "group" || resource == "session" || resource == "device") {
				continue
			}
			for idx, lookupErr := range lookupErrors {
				t.Run(fmt.Sprintf("%s/Anonymous%t/Error%d", resource, anonymous, idx), func(t *testing.T) {
					srv, coreC := newAuthorizationService(t)
					coreC.service.Spec.IsAnonymous = anonymous
					coreC.service.Spec.Authorization.EnableAnonymous = anonymous
					deny := pbutils.Clone(coreC.service.Spec.Authorization.InlinePolicies[0].Spec).(*corev1.Policy_Spec)
					deny.Rules[0].Effect = corev1.Policy_Spec_Rule_DENY
					coreC.policies["deny"] = &corev1.Policy{Metadata: &metav1.Metadata{Uid: "deny-policy", Name: "deny"}, Spec: deny}
					coreC.errs["policy:deny"] = lookupErr
					downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
					names := []string{"deny"}
					var additional *coctovigilv1.Authorization
					switch resource {
					case "service":
						coreC.service.Spec.Authorization.Policies = names
					case "namespace":
						coreC.namespace.Spec.Authorization = &corev1.Namespace_Spec_Authorization{Policies: names}
					case "user":
						downstream.user.Spec.Authorization = &corev1.User_Spec_Authorization{Policies: names}
					case "group":
						downstream.groups[0].Spec.Authorization = &corev1.Group_Spec_Authorization{Policies: names}
					case "session":
						downstream.session.Spec.Authorization = &corev1.Session_Spec_Authorization{Policies: names}
					case "device":
						downstream.device.Spec.Authorization = &corev1.Device_Spec_Authorization{Policies: names}
					case "additional":
						additional = &coctovigilv1.Authorization{Policies: names}
					case "trigger":
						assert.Nil(t, srv.s.policyTriggerCtl.SetPolicyTrigger(&corev1.PolicyTrigger{
							Metadata: &metav1.Metadata{Uid: "trigger"},
							Status: &corev1.PolicyTrigger_Status{Policies: names,
								PreCondition: &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{MatchAny: true}},
							},
						}))
					case "parent":
						coreC.service.Spec.Authorization.Policies = []string{"child.deny"}
						coreC.policies["child.deny"] = &corev1.Policy{Metadata: &metav1.Metadata{Name: "child.deny", Uid: "child"}, Spec: &corev1.Policy_Spec{}}
					}
					assertAuthorizationLookupError(t, srv, coreC, additional, lookupErr)
					_, err := srv.s.cache.GetPolicy("deny")
					assert.NotNil(t, err)
					delete(coreC.errs, "policy:deny")
					di, err := srv.s.GetDownstreamInfo(t.Context(), downstream.session.Metadata.Uid)
					assert.Nil(t, err)
					req := srv.s.getReqCtx(di, nil, coreC.service)
					for range 2 {
						resp, err := srv.s.DoAuthorize(t.Context(), req, additional)
						if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
							return
						}
						if assert.False(t, resp.IsAuthorized) {
							assert.Equal(t, "deny-policy", resp.Reason.Details.GetPolicyMatch().GetPolicy().PolicyRef.Uid)
						}
						coreC.errs["policy:deny"] = lookupErr
					}
				})
			}
		}
	}
}

func TestNamespaceLookupFailuresOverrideAllow(t *testing.T) {
	lookupErrors := []error{context.Canceled, context.DeadlineExceeded, errors.New("Namespace lookup failed")}
	for _, code := range []codes.Code{codes.NotFound, codes.Unavailable, codes.Internal, codes.PermissionDenied, codes.DeadlineExceeded, codes.Canceled} {
		lookupErrors = append(lookupErrors, status.Error(code, "Namespace lookup failed"))
	}
	for _, anonymous := range []bool{false, true} {
		for idx, lookupErr := range lookupErrors {
			t.Run(fmt.Sprintf("Anonymous%t/Error%d", anonymous, idx), func(t *testing.T) {
				srv, coreC := newAuthorizationService(t)
				coreC.service.Spec.IsAnonymous = anonymous
				coreC.service.Spec.Authorization.EnableAnonymous = anonymous
				deny := pbutils.Clone(coreC.service.Spec.Authorization.InlinePolicies[0]).(*corev1.InlinePolicy)
				deny.Spec.Rules[0].Effect = corev1.Policy_Spec_Rule_DENY
				coreC.namespace.Spec.Authorization = &corev1.Namespace_Spec_Authorization{InlinePolicies: []*corev1.InlinePolicy{deny}}
				assert.Nil(t, srv.s.cache.DeleteNamespace(coreC.namespace))
				coreC.errs["namespace"] = lookupErr
				assertAuthorizationLookupError(t, srv, coreC, nil, lookupErr)
				_, err := srv.s.cache.GetNamespace(coreC.namespace.Metadata.Name)
				assert.NotNil(t, err)
				delete(coreC.errs, "namespace")
				downstream := coreC.ResourceServiceClient.(*downstreamCoreC)
				di, err := srv.s.GetDownstreamInfo(t.Context(), downstream.session.Metadata.Uid)
				assert.Nil(t, err)
				req := srv.s.getReqCtx(di, nil, coreC.service)
				for range 2 {
					resp, err := srv.s.DoAuthorize(t.Context(), req, nil)
					if !assert.Nil(t, err) || !assert.NotNil(t, resp) {
						return
					}
					assert.False(t, resp.IsAuthorized)
					coreC.errs["namespace"] = lookupErr
				}
			})
		}
	}
}

func TestEvaluatePolicyLookupFailuresOverrideAllow(t *testing.T) {
	for _, parent := range []bool{false, true} {
		for _, lookupErr := range []error{status.Error(codes.Unavailable, "Policy lookup failed"), context.Canceled, errors.New("Policy lookup failed")} {
			t.Run(fmt.Sprintf("Parent%t/%s", parent, lookupErr.Error()), func(t *testing.T) {
				srv, coreC := newAuthorizationService(t)
				allow := coreC.service.Spec.Authorization.InlinePolicies[0]
				deny := pbutils.Clone(allow.Spec).(*corev1.Policy_Spec)
				deny.Rules[0].Effect = corev1.Policy_Spec_Rule_DENY
				coreC.policies["deny"] = &corev1.Policy{Metadata: &metav1.Metadata{Name: "deny", Uid: "deny"}, Spec: deny}
				name := "deny"
				if parent {
					name = "child.deny"
					coreC.policies[name] = &corev1.Policy{Metadata: &metav1.Metadata{Name: name, Uid: "child"}, Spec: &corev1.Policy_Spec{}}
				}
				req := &coctovigilv1.EvaluateRequest{
					Policies: []string{name}, InlinePolicies: []*coctovigilv1.EvaluateRequest_InlinePolicy{{Policy: allow}},
				}
				coreC.errs["policy:deny"] = lookupErr
				rules, err := srv.s.getEvaluatePolicyRules(t.Context(), req, nil)
				assert.Nil(t, rules)
				assert.ErrorIs(t, err, lookupErr)
				resp, err := srv.Evaluate(t.Context(), req)
				assert.Nil(t, resp)
				assert.Equal(t, codes.Internal, status.Code(err))
				delete(coreC.errs, "policy:deny")
				resp, err = srv.Evaluate(t.Context(), req)
				if assert.Nil(t, err) && assert.NotNil(t, resp) {
					assert.Equal(t, corev1.Policy_Spec_Rule_DENY, resp.Effect)
				}
			})
		}
	}
}

func TestMissingPolicyLookupCompatibility(t *testing.T) {
	for _, source := range []string{"service", "trigger", "evaluate"} {
		for _, tc := range []struct {
			name       string
			policyName string
			wrapped    bool
		}{
			{"MissingParent", "child.parent", false},
			{"MissingChild", "parent", false},
			{"MissingBoth", "", false},
			{"WrappedNotFound", "parent", true},
		} {
			t.Run(source+"/"+tc.name, func(t *testing.T) {
				srv, coreC := newAuthorizationService(t)
				allow := coreC.service.Spec.Authorization.InlinePolicies[0]
				if tc.policyName != "" {
					deny := pbutils.Clone(allow.Spec).(*corev1.Policy_Spec)
					deny.Rules[0].Effect = corev1.Policy_Spec_Rule_DENY
					coreC.policies[tc.policyName] = &corev1.Policy{
						Metadata: &metav1.Metadata{Name: tc.policyName, Uid: "deny-policy"}, Spec: deny,
					}
				}
				if tc.wrapped {
					coreC.errs["policy:child.parent"] = fmt.Errorf("Policy lookup failed: %w", status.Error(codes.NotFound, "Policy not found"))
				}
				names := []string{"child.parent"}
				wantAllow := tc.policyName == ""
				switch source {
				case "service":
					coreC.service.Spec.Authorization.Policies = names
				case "trigger":
					assert.Nil(t, srv.s.policyTriggerCtl.SetPolicyTrigger(&corev1.PolicyTrigger{
						Metadata: &metav1.Metadata{Uid: "trigger"},
						Status: &corev1.PolicyTrigger_Status{Policies: names,
							PreCondition: &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{MatchAny: true}},
						},
					}))
				case "evaluate":
					resp, err := srv.Evaluate(t.Context(), &coctovigilv1.EvaluateRequest{
						Policies: names, InlinePolicies: []*coctovigilv1.EvaluateRequest_InlinePolicy{{Policy: allow}},
					})
					if assert.Nil(t, err) && assert.NotNil(t, resp) {
						want := corev1.Policy_Spec_Rule_DENY
						if wantAllow {
							want = corev1.Policy_Spec_Rule_ALLOW
						}
						assert.Equal(t, want, resp.Effect)
					}
					return
				}
				resp, err := srv.AuthenticateAndAuthorize(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeRequest{
					ServiceUID: "service", Request: &coctovigilv1.DownstreamRequest{Source: &coctovigilv1.DownstreamRequest_Source{Address: "100.64.0.2"}},
				})
				if assert.Nil(t, err) && assert.NotNil(t, resp) {
					assert.Equal(t, wantAllow, resp.IsAuthorized)
				}
			})
		}
	}
}
