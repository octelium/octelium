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
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func newPolicyTriggerTst(uid string,
	preCondition *corev1.PolicyTrigger_Status_PreCondition, policies ...string) *corev1.PolicyTrigger {
	return &corev1.PolicyTrigger{
		Metadata: &metav1.Metadata{Uid: uid, Name: uid},
		Status: &corev1.PolicyTrigger_Status{
			OwnerRef:     &metav1.ObjectReference{Uid: uid},
			PreCondition: preCondition,
			Policies:     policies,
			InlinePolicies: []*corev1.InlinePolicy{{Name: uid, Spec: &corev1.Policy_Spec{
				Rules: []*corev1.Policy_Spec_Rule{{Name: "inline"}},
			}}},
		},
	}
}

func getPolicyRuleNames(rules []*policyRule) []string {
	ret := make([]string, 0, len(rules))
	for _, rule := range rules {
		switch {
		case rule.policyRef != nil:
			ret = append(ret, rule.policyRef.Name+"/"+rule.rule.Name)
		case rule.inline != nil:
			ret = append(ret, rule.inline.resourceRef.Uid+"/"+rule.inline.name+"/"+rule.rule.Name)
		}
	}
	return ret
}

func TestPolicyTriggerCtlSnapshot(t *testing.T) {
	ctl := &policyTriggerCtl{ptMap: make(map[string]*corev1.PolicyTrigger)}
	assert.Empty(t, ctl.getPolicyTriggers())

	matchAny := &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{MatchAny: true}}
	first := newPolicyTriggerTst("first", matchAny)
	disabled := newPolicyTriggerTst("disabled", matchAny)
	disabled.Status.IsDisabled = true
	assert.Nil(t, ctl.SetPolicyTrigger(first))
	assert.Nil(t, ctl.SetPolicyTrigger(disabled))

	pts := ctl.getPolicyTriggers()
	assert.Len(t, pts, 2)
	assert.True(t, slices.Contains(pts, first))
	assert.True(t, slices.Contains(pts, disabled))

	second := newPolicyTriggerTst("first", matchAny)
	assert.Nil(t, ctl.SetPolicyTrigger(second))
	assert.Nil(t, ctl.DeletePolicyTrigger(disabled))
	assert.Len(t, pts, 2)
	assert.True(t, slices.Contains(pts, first))
	assert.True(t, slices.Contains(pts, disabled))

	cur := ctl.getPolicyTriggers()
	if assert.Len(t, cur, 1) {
		assert.Same(t, second, cur[0])
	}
	cur[0] = nil
	pts[0] = nil
	assert.Same(t, second, ctl.ptMap["first"])
	assert.Equal(t, []*corev1.PolicyTrigger{second}, ctl.getPolicyTriggers())

	assert.Nil(t, ctl.DeletePolicyTrigger(second))
	assert.Empty(t, ctl.getPolicyTriggers())
}

func TestPolicyTriggerRules(t *testing.T) {
	srv, coreC := newAuthorizationService(t)
	for _, name := range []string{"p1", "p2", "p3"} {
		coreC.policies[name] = &corev1.Policy{
			Metadata: &metav1.Metadata{Uid: name, Name: name},
			Spec:     &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{Name: "a"}, {Name: "b"}}},
		}
	}
	coreC.errs["policy:err"] = status.Error(codes.Unavailable, "policy lookup failed")

	ref := func(uid string) *metav1.ObjectReference { return &metav1.ObjectReference{Uid: uid} }
	match := func(exp string) *corev1.PolicyTrigger_Status_PreCondition {
		return &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_Condition{
			Condition: &corev1.Condition{Type: &corev1.Condition_Match{Match: exp}},
		}}
	}
	serviceRef := func(uid string) *corev1.PolicyTrigger_Status_PreCondition {
		return &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_ServiceRef{ServiceRef: ref(uid)}}
	}
	matchAny := &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{MatchAny: true}}

	disabled := newPolicyTriggerTst("disabled", matchAny, "p3")
	disabled.Status.IsDisabled = true
	for _, pt := range []*corev1.PolicyTrigger{
		newPolicyTriggerTst("any", matchAny, "p1"),
		newPolicyTriggerTst("cel", match(`ctx.user.metadata.uid == "user"`), "p1", "p2"),
		newPolicyTriggerTst("service", serviceRef("service"), "p2"),
		newPolicyTriggerTst("all", &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_All_{
			All: &corev1.PolicyTrigger_Status_PreCondition_All{Of: []*corev1.PolicyTrigger_Status_PreCondition{
				{Type: &corev1.PolicyTrigger_Status_PreCondition_UserRef{UserRef: ref("user")}},
				match(`ctx.service.metadata.uid == "service"`),
			}},
		}}),
		newPolicyTriggerTst("cel-false", match(`ctx.user.metadata.uid == "other"`), "p3"),
		newPolicyTriggerTst("cel-missing", match(`ctx.device.metadata.uid == "device"`), "p3"),
		newPolicyTriggerTst("cel-invalid", match("ctx =="), "p3"),
		newPolicyTriggerTst("service-other", serviceRef("other"), "p3"),
		newPolicyTriggerTst("nil", nil, "p3"),
		disabled,
	} {
		assert.Nil(t, srv.s.policyTriggerCtl.SetPolicyTrigger(pt))
	}

	req := &corev1.RequestContext{
		User:    &corev1.User{Metadata: &metav1.Metadata{Uid: "user"}},
		Service: &corev1.Service{Metadata: &metav1.Metadata{Uid: "service"}},
	}
	reqCtxMap, err := srv.s.getReqCtxMap(req)
	assert.Nil(t, err)
	bodyReq := &corev1.RequestContext{
		User:    req.User,
		Service: req.Service,
		Request: &corev1.RequestContext_Request{Type: &corev1.RequestContext_Request_Http{
			Http: &corev1.RequestContext_Request_HTTP{IsBodyOmitted: true},
		}},
	}
	bodyReqCtxMap, err := srv.s.getReqCtxMap(bodyReq)
	assert.Nil(t, err)

	expected := []string{
		"p1/a", "p1/b", "p2/a", "p2/b",
		"any/any/inline", "cel/cel/inline", "service/service/inline", "all/all/inline",
	}
	for range 64 {
		for _, tc := range []struct {
			i         *corev1.RequestContext
			reqCtxMap map[string]any
		}{
			{req, reqCtxMap},
			{bodyReq, bodyReqCtxMap},
		} {
			var used []string
			rules, err := srv.s.getRulesFromPolicyTriggers(t.Context(), tc.i, tc.reqCtxMap, &used)
			assert.Nil(t, err)
			names := getPolicyRuleNames(rules)
			assert.ElementsMatch(t, expected, names)
			assert.ElementsMatch(t, []string{"p1", "p2"}, used)
			for _, name := range []string{"p1", "p2"} {
				idx := slices.Index(names, name+"/a")
				if assert.True(t, idx >= 0 && idx+1 < len(names)) {
					assert.Equal(t, name+"/b", names[idx+1])
				}
			}
		}
	}

	{
		used := []string{"p1"}
		rules, err := srv.s.getRulesFromPolicyTriggers(t.Context(), req, reqCtxMap, &used)
		assert.Nil(t, err)
		assert.ElementsMatch(t, expected[2:], getPolicyRuleNames(rules))
		assert.Equal(t, []string{"p1", "p2"}, used)
	}

	body := newPolicyTriggerTst("body", match(`ctx.request.http.bodyMap.x == 1`), "p3")
	assert.Nil(t, srv.s.policyTriggerCtl.SetPolicyTrigger(body))
	for range 16 {
		var used []string
		rules, err := srv.s.getRulesFromPolicyTriggers(t.Context(), bodyReq, bodyReqCtxMap, &used)
		assert.NotNil(t, err)
		assert.Nil(t, rules)

		used = nil
		rules, err = srv.s.getRulesFromPolicyTriggers(t.Context(), req, reqCtxMap, &used)
		assert.Nil(t, err)
		assert.ElementsMatch(t, expected, getPolicyRuleNames(rules))
	}
	assert.Nil(t, srv.s.policyTriggerCtl.DeletePolicyTrigger(body))

	assert.Nil(t, srv.s.policyTriggerCtl.SetPolicyTrigger(newPolicyTriggerTst("err", matchAny, "err")))
	for range 16 {
		var used []string
		rules, err := srv.s.getRulesFromPolicyTriggers(t.Context(), req, reqCtxMap, &used)
		assert.Equal(t, codes.Unavailable, status.Code(err))
		assert.Nil(t, rules)
	}
}

func TestPolicyTriggerAllocs(t *testing.T) {
	srv, _ := newAuthorizationService(t)
	ctx := t.Context()
	req := &corev1.RequestContext{Service: &corev1.Service{Metadata: &metav1.Metadata{Uid: "service"}}}
	reqCtxMap := map[string]any{}

	var rules []*policyRule
	var used []string
	var err error
	allocs := func(n int) float64 {
		srv.s.policyTriggerCtl = &policyTriggerCtl{ptMap: make(map[string]*corev1.PolicyTrigger)}
		for i := range n {
			assert.Nil(t, srv.s.policyTriggerCtl.SetPolicyTrigger(newPolicyTriggerTst(fmt.Sprintf("trigger-%d", i),
				&corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_ServiceRef{
					ServiceRef: &metav1.ObjectReference{Uid: "other"},
				}}, "policy")))
		}
		return testing.AllocsPerRun(100, func() {
			rules, err = srv.s.getRulesFromPolicyTriggers(ctx, req, reqCtxMap, &used)
		})
	}

	assert.Zero(t, allocs(0))
	assert.Nil(t, err)
	assert.Nil(t, rules)

	one := allocs(1)
	assert.Nil(t, err)
	assert.Nil(t, rules)

	assert.Equal(t, one, allocs(64))
	assert.Nil(t, err)
	assert.Nil(t, rules)
	assert.Empty(t, used)
}

type blockingPolicyCoreC struct {
	*authorizationCoreC
	name    string
	started chan struct{}
	release chan struct{}
}

func (c *blockingPolicyCoreC) GetPolicy(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Policy, error) {
	if in.Name == c.name {
		select {
		case c.started <- struct{}{}:
		default:
		}
		<-c.release
	}
	return c.authorizationCoreC.GetPolicy(ctx, in, opts...)
}

func TestPolicyTriggerLockScope(t *testing.T) {
	srv, coreC := newAuthorizationService(t)
	coreC.policies["slow"] = &corev1.Policy{
		Metadata: &metav1.Metadata{Uid: "slow", Name: "slow"},
		Spec:     &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{{Name: "a"}}},
	}
	blockingC := &blockingPolicyCoreC{
		authorizationCoreC: coreC,
		name:               "slow",
		started:            make(chan struct{}, 1),
		release:            make(chan struct{}),
	}
	release := sync.OnceFunc(func() { close(blockingC.release) })
	t.Cleanup(release)
	srv.s.octeliumC = &authorizationOcteliumC{coreC: blockingC}

	ctl := srv.s.policyTriggerCtl
	matchAny := &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{MatchAny: true}}
	deleted := newPolicyTriggerTst("deleted", matchAny)
	assert.Nil(t, ctl.SetPolicyTrigger(newPolicyTriggerTst("slow", &corev1.PolicyTrigger_Status_PreCondition{
		Type: &corev1.PolicyTrigger_Status_PreCondition_UserRef{UserRef: &metav1.ObjectReference{Uid: "slow-user"}},
	}, "slow")))
	assert.Nil(t, ctl.SetPolicyTrigger(deleted))

	type result struct {
		names []string
		err   error
	}
	getRules := func(userUID string) <-chan result {
		ret := make(chan result, 1)
		go func() {
			var used []string
			rules, err := srv.s.getRulesFromPolicyTriggers(context.Background(), &corev1.RequestContext{
				User: &corev1.User{Metadata: &metav1.Metadata{Uid: userUID}},
			}, map[string]any{}, &used)
			ret <- result{names: getPolicyRuleNames(rules), err: err}
		}()
		return ret
	}
	wait := func(ch <-chan result) result {
		select {
		case res := <-ch:
			return res
		case <-time.After(10 * time.Second):
			t.Fatal("timed out while a PolicyTrigger Policy lookup is in flight")
			return result{}
		}
	}

	slow := getRules("slow-user")
	select {
	case <-blockingC.started:
	case <-time.After(10 * time.Second):
		t.Fatal("the PolicyTrigger Policy lookup did not start")
	}

	updated := make(chan result, 1)
	go func() {
		err := ctl.DeletePolicyTrigger(deleted)
		if err == nil {
			err = ctl.SetPolicyTrigger(newPolicyTriggerTst("added", matchAny))
		}
		updated <- result{err: err}
	}()
	assert.Nil(t, wait(updated).err)

	res := wait(getRules("other-user"))
	assert.Nil(t, res.err)
	assert.Equal(t, []string{"added/added/inline"}, res.names)

	release()
	res = wait(slow)
	assert.Nil(t, res.err)
	assert.ElementsMatch(t, []string{"slow/a", "slow/slow/inline", "deleted/deleted/inline"}, res.names)

	res = wait(getRules("slow-user"))
	assert.Nil(t, res.err)
	assert.ElementsMatch(t, []string{"slow/a", "slow/slow/inline", "added/added/inline"}, res.names)
}

func TestPolicyTriggerConcurrentUpdates(t *testing.T) {
	srv, _ := newAuthorizationService(t)
	ctl := srv.s.policyTriggerCtl
	matchAny := &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{MatchAny: true}}
	assert.Nil(t, ctl.SetPolicyTrigger(newPolicyTriggerTst("stable", matchAny)))

	ctx, cancel := context.WithCancel(t.Context())
	var writer sync.WaitGroup
	writer.Go(func() {
		for i := 0; ctx.Err() == nil; i++ {
			pt := newPolicyTriggerTst(fmt.Sprintf("trigger-%d", i%8), matchAny)
			if i%3 == 0 {
				assert.Nil(t, ctl.DeletePolicyTrigger(pt))
			} else {
				assert.Nil(t, ctl.SetPolicyTrigger(pt))
			}
		}
	})

	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			for range 200 {
				var used []string
				rules, err := srv.s.getRulesFromPolicyTriggers(t.Context(), &corev1.RequestContext{}, map[string]any{}, &used)
				if !assert.Nil(t, err) {
					return
				}
				names := getPolicyRuleNames(rules)
				assert.Contains(t, names, "stable/stable/inline")
				assert.LessOrEqual(t, len(names), 9)
				assert.Len(t, slices.Compact(slices.Sorted(slices.Values(names))), len(names))
				assert.Empty(t, used)
			}
		})
	}
	readers.Wait()
	cancel()
	writer.Wait()
}

func BenchmarkGetRulesFromPolicyTriggers(b *testing.B) {
	req := &corev1.RequestContext{
		User:    &corev1.User{Metadata: &metav1.Metadata{Uid: "user"}},
		Service: &corev1.Service{Metadata: &metav1.Metadata{Uid: "service"}},
	}
	reqCtxMap := map[string]any{}

	for _, tc := range []struct {
		name         string
		preCondition func(i int) *corev1.PolicyTrigger_Status_PreCondition
	}{
		{"ServiceRef", func(i int) *corev1.PolicyTrigger_Status_PreCondition {
			return &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_ServiceRef{
				ServiceRef: &metav1.ObjectReference{Uid: fmt.Sprintf("service-%d", i)},
			}}
		}},
		{"AllUserRef", func(i int) *corev1.PolicyTrigger_Status_PreCondition {
			return &corev1.PolicyTrigger_Status_PreCondition{Type: &corev1.PolicyTrigger_Status_PreCondition_All_{
				All: &corev1.PolicyTrigger_Status_PreCondition_All{Of: []*corev1.PolicyTrigger_Status_PreCondition{
					{Type: &corev1.PolicyTrigger_Status_PreCondition_UserRef{
						UserRef: &metav1.ObjectReference{Uid: fmt.Sprintf("user-%d", i)},
					}},
					{Type: &corev1.PolicyTrigger_Status_PreCondition_ServiceRef{
						ServiceRef: &metav1.ObjectReference{Uid: "service"},
					}},
				}},
			}}
		}},
	} {
		for _, n := range []int{1, 100, 1000} {
			srv := &Server{policyTriggerCtl: &policyTriggerCtl{ptMap: make(map[string]*corev1.PolicyTrigger)}}
			for i := range n {
				assert.Nil(b, srv.policyTriggerCtl.SetPolicyTrigger(
					newPolicyTriggerTst(fmt.Sprintf("trigger-%d", i), tc.preCondition(i), "policy")))
			}

			b.Run(fmt.Sprintf("%s/%d", tc.name, n), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var used []string
					if _, err := srv.getRulesFromPolicyTriggers(b.Context(), req, reqCtxMap, &used); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
