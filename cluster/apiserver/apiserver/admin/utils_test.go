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

package admin

import (
	"context"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCheckCELExpression(t *testing.T) {
	assert.NotNil(t, checkCELExpression(context.Background(), ""))
	assert.Nil(t, checkCELExpression(context.Background(), `ctx.user.metadata.name == "usr1"`))
}

func TestExpressionValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check func(context.Context, string) error
		valid string
		max   int
	}{
		{"CELCondition", checkCELExpression, "true", maxCELExpressionLen},
		{"CELString", checkCELExpressionString, `"value"`, maxCELExpressionLen},
		{"CELMap", checkCELExpressionMap, `{"value": true}`, maxCELExpressionLen},
		{"OPACondition", checkOPACondition, "package octelium.condition\nmatch := true", maxOPAScriptLen},
		{"OPAString", checkOPAString, "package octelium.eval\nresult := \"value\"", maxOPAScriptLen},
		{"OPAMap", checkOPAMapAny, "package octelium.eval\nresult := {\"value\": true}", maxOPAScriptLen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Nil(t, tc.check(t.Context(), tc.valid))
			for _, arg := range []string{"", " \t\n", "(", "unknownVariable", strings.Repeat(" ", tc.max+1)} {
				assert.Equal(t, codes.InvalidArgument, status.Code(tc.check(t.Context(), arg)), "%q", arg[:min(len(arg), 40)])
			}
			assert.Nil(t, tc.check(t.Context(), tc.valid+strings.Repeat(" ", min(tc.max, 20000)-len(tc.valid))))
		})
	}
	assert.NotNil(t, checkCELExpression(t.Context(), `"value"`))
	assert.NotNil(t, checkCELExpressionString(t.Context(), "true"))
}

func TestAdminStringHelpers(t *testing.T) {
	s := &Server{}
	for _, tc := range []struct {
		arg      string
		required bool
		valid    bool
	}{
		{"", false, true}, {"", true, false}, {"value", true, true},
		{strings.Repeat("a", maxGenStrLen), true, true},
		{strings.Repeat("a", maxGenStrLen+1), false, false}, {"日本語", false, false},
	} {
		assert.Equal(t, tc.valid, s.validateGenStr(tc.arg, tc.required, "field") == nil)
	}
	for _, tc := range []struct {
		name string
		ns   string
	}{
		{"service", "default"}, {"service.namespace", "namespace"},
	} {
		ns, err := getNamespace(tc.name)
		assert.Nil(t, err)
		assert.Equal(t, tc.ns, ns)
	}
	for _, name := range []string{"", ".service", "service.", "service..namespace", "service.namespace.extra"} {
		_, err := getNamespace(name)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	}
}

func TestSecretOwnerErrors(t *testing.T) {
	s := &Server{}
	assert.Equal(t, codes.InvalidArgument, status.Code(s.validateSecretOwner(t.Context(), nil)))
	assert.Equal(t, codes.InvalidArgument, status.Code(s.validateSecretOwner(t.Context(), &corev1.Service_Spec_Config_HTTP_Auth_Bearer{})))
	for _, code := range []codes.Code{codes.NotFound, codes.InvalidArgument, codes.Unavailable} {
		s = newTstServer(func(method string, req, resp any) error { return status.Error(code, "backend") })
		err := s.validateSecretOwner(t.Context(), &corev1.Service_Spec_Config_HTTP_Auth_Bearer{Type: &corev1.Service_Spec_Config_HTTP_Auth_Bearer_FromSecret{FromSecret: "secret"}})
		if code == codes.Unavailable {
			assert.Equal(t, codes.Internal, status.Code(err))
		} else {
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		}
	}
}
