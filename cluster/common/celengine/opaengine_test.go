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

package celengine

import (
	"context"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

func TestConditionOPA(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	srv, err := New(ctx, &Opts{})
	assert.Nil(t, err)

	{
		i := &corev1.RequestContext{
			User: &corev1.User{
				Spec: &corev1.User_Spec{
					Type: corev1.User_Spec_HUMAN,
				},
			},
		}

		reqCtxMap, err := pbutils.ConvertToMap(i)
		assert.Nil(t, err)

		res, err := srv.EvalCondition(ctx, &corev1.Condition{
			Type: &corev1.Condition_Opa{
				Opa: &corev1.Condition_OPA{
					Type: &corev1.Condition_OPA_Inline{
						Inline: `
package octelium.condition

match if {
	input.ctx.user.spec.type == "HUMAN"
	input.attrs.attr1 == "val1"
}
						`,
					},
				},
			},
		}, map[string]any{
			"ctx": reqCtxMap,
			"attrs": map[string]any{
				"attr1": "val1",
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, res)
	}

	{
		i := &corev1.RequestContext{
			User: &corev1.User{
				Spec: &corev1.User_Spec{
					Type: corev1.User_Spec_HUMAN,
				},
			},
		}

		reqCtxMap, err := pbutils.ConvertToMap(i)
		assert.Nil(t, err)

		res, err := srv.EvalCondition(ctx, &corev1.Condition{
			Type: &corev1.Condition_Opa{
				Opa: &corev1.Condition_OPA{
					Type: &corev1.Condition_OPA_Inline{
						Inline: `
package octelium.condition

match if {
	input.ctx.user.spec.type == "WORKLOAD"
	input.attrs.attr1 == "val1"
}

match222 if {
	2 > 1
}
						`,
					},
				},
			},
		}, map[string]any{
			"ctx": reqCtxMap,
			"attrs": map[string]any{
				"attr1": "val1",
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.False(t, res)
	}
}

func TestDoEvaluatePolicy(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	e, err := newOPAEngine(ctx, nil)
	assert.Nil(t, err)

	usr := tests.GenUser(nil)
	res, err := e.doEvalPolicy(ctx, `
package octelium.eval

result := {
	"upstream": {
		"url": sprintf("https://%s.example.com", [input.ctx.user.metadata.name])
	}
}`, map[string]any{
		"ctx": map[string]any{
			"user": pbutils.MustConvertToMap(usr),
		},
	}, "eval", "result")
	assert.Nil(t, err, "%+v", err)

	cfg := &corev1.Service_Spec_Config{}

	cfgMap, ok := res.(map[string]any)
	assert.True(t, ok)

	err = pbutils.UnmarshalFromMap(cfgMap, cfg)
	assert.Nil(t, err)

	assert.Equal(t, fmt.Sprintf("https://%s.example.com", usr.Metadata.Name), cfg.Upstream.GetUrl())
}
