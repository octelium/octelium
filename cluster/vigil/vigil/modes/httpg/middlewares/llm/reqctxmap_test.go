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

package llm

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReqCtxMapInputs(t *testing.T) {
	ctx := context.Background()

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	require.Nil(t, err)

	newReqCtx := func(state string) *middlewares.RequestContext {
		ret := &middlewares.RequestContext{
			DownstreamInfo: &corev1.RequestContext{
				Request: &corev1.RequestContext_Request{
					Type: &corev1.RequestContext_Request_Llm{
						Llm: &corev1.RequestContext_Request_LLM{
							Http: &corev1.RequestContext_Request_HTTP{Path: "/v1/chat/completions"},
						},
					},
				},
				User: &corev1.User{
					Metadata: &metav1.Metadata{Uid: "llm-user-uid", Name: "user", ResourceVersion: "llm-user-rv"},
					Spec:     &corev1.User_Spec{Type: corev1.User_Spec_HUMAN, Email: "user@example.com"},
				},
				Session: &corev1.Session{
					Metadata: &metav1.Metadata{Uid: "llm-session-uid", Name: "session", ResourceVersion: "llm-session-rv"},
				},
			},
		}

		switch state {
		case "Set":
			ret.SetReqCtxMap()
		case "Built":
			ret.SetReqCtxMap()
			ret.GetReqCtxMap()
		}

		return ret
	}

	email := "user@example.com"

	for _, state := range []string{"NotSet", "Set", "Built"} {
		t.Run(state, func(t *testing.T) {
			{
				ret, err := (&guardrail{celEngine: celEngine}).render(ctx, newReqCtx(state),
					&corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace{
						Type: &corev1.Service_Spec_Config_LLM_Plugin_Guardrail_Pattern_Replace_Eval{
							Eval: `ctx.user.spec.email`,
						},
					})
				assert.Nil(t, err)
				assert.Equal(t, email, ret)
			}

			{
				ret, err := (&prompt{celEngine: celEngine}).render(ctx, newReqCtx(state),
					&corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content{
						Type: &corev1.Service_Spec_Config_LLM_Plugin_Prompt_Content_Eval{
							Eval: `ctx.user.spec.email`,
						},
					})
				assert.Nil(t, err)
				assert.Equal(t, email, ret)
			}

			{
				ret, err := (&tools{celEngine: celEngine}).render(ctx, newReqCtx(state),
					&corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool{
						Type: &corev1.Service_Spec_Config_LLM_Plugin_Tools_Tool_Eval{
							Eval: `"{\"name\": \"" + ctx.user.spec.email + "\"}"`,
						},
					})
				assert.Nil(t, err)
				assert.Equal(t, `{"name": "user@example.com"}`, string(ret))
			}

			{
				reqCtx := newReqCtx(state)
				var input map[string]any
				_, err := (&reasoning{celEngine: celEngine}).render(ctx, reqCtx,
					func(inputMap map[string]any) (string, error) {
						input = inputMap
						return "", nil
					})
				assert.Nil(t, err)
				assert.Equal(t, map[string]any{
					"ctx": pbutils.MustConvertToMap(reqCtx.DownstreamInfo),
				}, input)
			}

			{
				ret, err := (&semanticCache{celEngine: celEngine}).getScope(ctx, newReqCtx(state),
					&corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope{
						Type: &corev1.Service_Spec_Config_LLM_Plugin_SemanticCache_Scope_Eval{
							Eval: `ctx.user.spec.email`,
						},
					})
				assert.Nil(t, err)
				assert.Equal(t, "eval:"+email, ret)
			}

			{
				ret, err := (&tokenRateLimit{celEngine: celEngine, svcUID: "svc"}).getKey(ctx, "limit",
					&corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key{
						Type: &corev1.Service_Spec_Config_HTTP_Plugin_RateLimit_Key_Eval{
							Eval: `ctx.user.spec.email`,
						},
					}, newReqCtx(state))
				assert.Nil(t, err)
				assert.Equal(t, vutils.Sha256Sum([]byte("svc:limit:"+email)), ret)
			}

			{
				ret, err := (&model{celEngine: celEngine}).getModel(ctx,
					&corev1.Service_Spec_Config_LLM_Model{
						Type: &corev1.Service_Spec_Config_LLM_Model_Eval{
							Eval: `ctx.user.spec.email`,
						},
					}, newReqCtx(state))
				if state == "NotSet" {
					assert.NotNil(t, err)
				} else {
					assert.Nil(t, err)
					assert.Equal(t, email, ret)
				}
			}
		})
	}
}
