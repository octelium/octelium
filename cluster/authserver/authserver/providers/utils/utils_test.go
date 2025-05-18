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

package utils

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
)

func TestGetAAL(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	celEngine, err := celengine.New(ctx, &celengine.Opts{})
	assert.Nil(t, err)

	{
		out := GetAAL(ctx, &GetAALReq{
			CelEngine: celEngine,
		})
		assert.Equal(t, corev1.Session_Status_Authentication_Info_AAL_UNSET, out)
	}

	{
		out := GetAAL(ctx, &GetAALReq{
			CelEngine: celEngine,
			Rules: []*corev1.IdentityProvider_Spec_AALRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{
							MatchAny: true,
						},
					},
					Aal: corev1.IdentityProvider_Spec_AALRule_AAL3,
				},
			},
		})
		assert.Equal(t, corev1.Session_Status_Authentication_Info_AAL3, out)
	}

	{
		out := GetAAL(ctx, &GetAALReq{
			CelEngine: celEngine,
			Rules: []*corev1.IdentityProvider_Spec_AALRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: `ctx.assertionMap.k1 == "v1"`,
						},
					},
					Aal: corev1.IdentityProvider_Spec_AALRule_AAL3,
				},
			},
			AssertionMap: map[string]any{
				"k1": "v1",
			},
		})
		assert.Equal(t, corev1.Session_Status_Authentication_Info_AAL3, out)
	}

	{
		out := GetAAL(ctx, &GetAALReq{
			CelEngine: celEngine,
			Rules: []*corev1.IdentityProvider_Spec_AALRule{
				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: "2 < 1",
						},
					},
					Aal: corev1.IdentityProvider_Spec_AALRule_AAL3,
				},

				{
					Condition: &corev1.Condition{
						Type: &corev1.Condition_Match{
							Match: "2 > 1",
						},
					},
					Aal: corev1.IdentityProvider_Spec_AALRule_AAL2,
				},
			},
		})
		assert.Equal(t, corev1.Session_Status_Authentication_Info_AAL2, out)
	}
}
