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
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
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
