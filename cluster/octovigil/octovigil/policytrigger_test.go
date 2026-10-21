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
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDoEvalPreCondition(t *testing.T) {

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

	srv, err := New(ctx, tst.C.OcteliumC)
	assert.Nil(t, err)

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, nil)
		assert.Nil(t, err)
		assert.False(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{})
		assert.Nil(t, err)
		assert.False(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{
				MatchAny: true,
			},
		})
		assert.Nil(t, err)
		assert.True(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_NotAfter{
				NotAfter: pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
			},
		})
		assert.Nil(t, err)
		assert.True(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_NotAfter{
				NotAfter: pbutils.Timestamp(time.Now().Add(-1 * time.Hour)),
			},
		})
		assert.Nil(t, err)
		assert.False(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_NotBefore{
				NotBefore: pbutils.Timestamp(time.Now().Add(-1 * time.Hour)),
			},
		})
		assert.Nil(t, err)
		assert.True(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_NotBefore{
				NotBefore: pbutils.Timestamp(time.Now().Add(1 * time.Hour)),
			},
		})
		assert.Nil(t, err)
		assert.False(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_SessionRef{
				SessionRef: umetav1.GetObjectReference(usr.Session),
			},
		})
		assert.Nil(t, err)
		assert.True(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_SessionRef{
				SessionRef: umetav1.GetObjectReference(usr.Usr),
			},
		})
		assert.Nil(t, err)
		assert.False(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_UserRef{
				UserRef: umetav1.GetObjectReference(usr.Usr),
			},
		})
		assert.Nil(t, err)
		assert.True(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_UserRef{
				UserRef: umetav1.GetObjectReference(usr.Session),
			},
		})
		assert.Nil(t, err)
		assert.False(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_Condition{
				Condition: &corev1.Condition{
					Type: &corev1.Condition_Match{
						Match: fmt.Sprintf(`ctx.session.metadata.uid == "%s"`, usr.Session.Metadata.Uid),
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.True(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_Condition{
				Condition: &corev1.Condition{
					Type: &corev1.Condition_Match{
						Match: `2 < 1`,
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.False(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_All_{
				All: &corev1.PolicyTrigger_Status_PreCondition_All{
					Of: []*corev1.PolicyTrigger_Status_PreCondition{
						{
							Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{
								MatchAny: true,
							},
						},
						{
							Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{
								MatchAny: true,
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.True(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_All_{
				All: &corev1.PolicyTrigger_Status_PreCondition_All{
					Of: []*corev1.PolicyTrigger_Status_PreCondition{
						{
							Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{
								MatchAny: true,
							},
						},
						{
							Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{
								MatchAny: false,
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.False(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_Any_{
				Any: &corev1.PolicyTrigger_Status_PreCondition_Any{
					Of: []*corev1.PolicyTrigger_Status_PreCondition{
						{
							Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{
								MatchAny: true,
							},
						},
						{
							Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{
								MatchAny: false,
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.True(t, res)
	}

	{
		usr, err := tstuser.NewUserWithType(tst.C.OcteliumC, adminSrv, usrSrv, nil,
			corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
		assert.Nil(t, err)

		reqCtx := &corev1.RequestContext{
			User:    usr.Usr,
			Session: usr.Session,
		}

		inputMap := map[string]any{
			"ctx": pbutils.MustConvertToMap(reqCtx),
		}

		res, err := srv.doEvalPreCondition(ctx, reqCtx, inputMap, &corev1.PolicyTrigger_Status_PreCondition{
			Type: &corev1.PolicyTrigger_Status_PreCondition_Any_{
				Any: &corev1.PolicyTrigger_Status_PreCondition_Any{
					Of: []*corev1.PolicyTrigger_Status_PreCondition{

						{
							Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{
								MatchAny: false,
							},
						},
					},
				},
			},
		})
		assert.Nil(t, err)
		assert.False(t, res)
	}

}

func TestPolicyTriggerPreConditionEdges(t *testing.T) {
	srv, _ := newAuthorizationService(t)
	ref := func(uid string) *metav1.ObjectReference { return &metav1.ObjectReference{Uid: uid} }
	req := &corev1.RequestContext{
		User:      &corev1.User{Metadata: &metav1.Metadata{Uid: "user"}},
		Session:   &corev1.Session{Metadata: &metav1.Metadata{Uid: "session"}},
		Device:    &corev1.Device{Metadata: &metav1.Metadata{Uid: "device"}},
		Service:   &corev1.Service{Metadata: &metav1.Metadata{Uid: "service"}},
		Namespace: &corev1.Namespace{Metadata: &metav1.Metadata{Uid: "namespace"}},
		Groups:    []*corev1.Group{{Metadata: &metav1.Metadata{Uid: "group"}}},
	}
	for _, tc := range []struct {
		name string
		pc   *corev1.PolicyTrigger_Status_PreCondition
	}{
		{"Session", &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_SessionRef{SessionRef: ref("session")}}},
		{"User", &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_UserRef{UserRef: ref("user")}}},
		{"Device", &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_DeviceRef{DeviceRef: ref("device")}}},
		{"Service", &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_ServiceRef{ServiceRef: ref("service")}}},
		{"Namespace", &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_NamespaceRef{NamespaceRef: ref("namespace")}}},
		{"Group", &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_GroupRef{GroupRef: ref("group")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matched, err := srv.s.doEvalPreCondition(t.Context(), req, nil, tc.pc)
			assert.Nil(t, err)
			assert.True(t, matched)
			matched, err = srv.s.doEvalPreCondition(t.Context(), &corev1.RequestContext{}, nil, tc.pc)
			assert.Nil(t, err)
			assert.False(t, matched)
			other := &corev1.RequestContext{
				User:      &corev1.User{Metadata: &metav1.Metadata{Uid: "other"}},
				Session:   &corev1.Session{Metadata: &metav1.Metadata{Uid: "other"}},
				Device:    &corev1.Device{Metadata: &metav1.Metadata{Uid: "other"}},
				Service:   &corev1.Service{Metadata: &metav1.Metadata{Uid: "other"}},
				Namespace: &corev1.Namespace{Metadata: &metav1.Metadata{Uid: "other"}},
				Groups:    []*corev1.Group{{Metadata: &metav1.Metadata{Uid: "other"}}},
			}
			matched, err = srv.s.doEvalPreCondition(t.Context(), other, nil, tc.pc)
			assert.Nil(t, err)
			assert.False(t, matched)
		})
	}
	for _, pc := range []*corev1.PolicyTrigger_Status_PreCondition{
		{Type: &corev1.PolicyTrigger_Status_PreCondition_NotAfter{}},
		{Type: &corev1.PolicyTrigger_Status_PreCondition_NotBefore{}},
		{Type: &corev1.PolicyTrigger_Status_PreCondition_NotAfter{NotAfter: &timestamppb.Timestamp{Nanos: -1}}},
		{Type: &corev1.PolicyTrigger_Status_PreCondition_NotBefore{NotBefore: &timestamppb.Timestamp{Seconds: 1 << 62}}},
		{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{}},
		{Type: &corev1.PolicyTrigger_Status_PreCondition_Any_{}},
		{Type: &corev1.PolicyTrigger_Status_PreCondition_All_{}},
		{Type: &corev1.PolicyTrigger_Status_PreCondition_Any_{Any: &corev1.PolicyTrigger_Status_PreCondition_Any{}}},
		{Type: &corev1.PolicyTrigger_Status_PreCondition_All_{All: &corev1.PolicyTrigger_Status_PreCondition_All{}}},
	} {
		matched, err := srv.s.doEvalPreCondition(t.Context(), req, nil, pc)
		assert.Nil(t, err)
		assert.False(t, matched)
	}
	valid := &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{MatchAny: true}}
	invalid := &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_Condition{
		Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: "ctx =="}},
	}}
	for _, pc := range []*corev1.PolicyTrigger_Status_PreCondition{
		invalid,
		{Type: &corev1.PolicyTrigger_Status_PreCondition_Any_{Any: &corev1.PolicyTrigger_Status_PreCondition_Any{Of: []*corev1.PolicyTrigger_Status_PreCondition{invalid, valid}}}},
		{Type: &corev1.PolicyTrigger_Status_PreCondition_All_{All: &corev1.PolicyTrigger_Status_PreCondition_All{Of: []*corev1.PolicyTrigger_Status_PreCondition{valid, invalid}}}},
	} {
		matched, err := srv.s.doEvalPreCondition(t.Context(), req, nil, pc)
		assert.NotNil(t, err)
		assert.False(t, matched)
	}
	matched, err := srv.s.isPreConditionMatchedAny(t.Context(), req, nil,
		&corev1.PolicyTrigger_Status_PreCondition_Any{Of: []*corev1.PolicyTrigger_Status_PreCondition{nil, valid, invalid}})
	assert.Nil(t, err)
	assert.True(t, matched)
	matched, err = srv.s.isPreConditionMatchedAll(t.Context(), req, nil,
		&corev1.PolicyTrigger_Status_PreCondition_All{Of: []*corev1.PolicyTrigger_Status_PreCondition{nil, invalid}})
	assert.Nil(t, err)
	assert.False(t, matched)
}

func TestPolicyTriggerFiltering(t *testing.T) {
	srv, coreC := newAuthorizationService(t)
	spec := coreC.service.Spec.Authorization.InlinePolicies[0].Spec
	for _, tc := range []struct {
		name      string
		disabled  bool
		condition *corev1.PolicyTrigger_Status_PreCondition
	}{
		{"Disabled", true, &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{MatchAny: true}}},
		{"Unmatched", false, &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{MatchAny: false}}},
		{"Invalid", false, &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_Condition{Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: "ctx =="}}}}},
	} {
		assert.Nil(t, srv.s.policyTriggerCtl.SetPolicyTrigger(&corev1.PolicyTrigger{
			Metadata: &metav1.Metadata{Uid: tc.name},
			Status: &corev1.PolicyTrigger_Status{
				IsDisabled: tc.disabled, PreCondition: tc.condition,
				InlinePolicies: []*corev1.InlinePolicy{{Name: tc.name, Spec: spec}},
			},
		}))
	}
	var used []string
	rules, err := srv.s.getRulesFromPolicyTriggers(t.Context(), &corev1.RequestContext{}, nil, &used)
	assert.Nil(t, err)
	assert.Empty(t, rules)
	assert.Empty(t, used)
}
