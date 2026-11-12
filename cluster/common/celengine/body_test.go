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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/stretchr/testify/assert"
)

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
		{match(`ctx.request.http.isBodyOmitted`), false},
		{&corev1.Condition{Type: &corev1.Condition_All_{All: &corev1.Condition_All{Of: []*corev1.Condition{matchAny, match(`ctx.request.http.path == "/"`)}}}}, false},
		{opa("package octelium.condition\n\nmatch if {\n\tinput.ctx.request.http.path == \"/\"\n}\n"), false},
		{matchAny, false},
		{nil, false},
	} {
		assert.Equal(t, tc.want, IsBodyCondition(tc.condition), "%v", tc.condition)
	}
}

func TestIsBodyExpression(t *testing.T) {
	assert.True(t, IsBodyExpression(`{"upstream": {"url": ctx.request.http.bodyMap.url}}`))
	assert.True(t, IsBodyExpression("package octelium.eval\ndefault result := {}\nresult := {\"parent\": input.ctx.request.http.bodyMap.tier}"))
	assert.False(t, IsBodyExpression(`{"upstream": {"url": ctx.request.http.headers["x-url"]}}`))
	assert.False(t, IsBodyExpression(`ctx.request.http.isBodyOmitted`))
	assert.False(t, IsBodyExpression(""))
}
