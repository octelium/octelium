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
match {
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
match {
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
