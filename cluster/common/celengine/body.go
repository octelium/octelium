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
	"regexp"
	"slices"

	"github.com/octelium/octelium/apis/main/corev1"
)

var rgxBodyRef = regexp.MustCompile(`\bbody(Map)?\b`)

func IsBodyExpression(exp string) bool {
	return rgxBodyRef.MatchString(exp)
}

func IsBodyCondition(condition *corev1.Condition) bool {
	if condition == nil {
		return false
	}

	switch condition.Type.(type) {
	case *corev1.Condition_Match:
		return IsBodyExpression(condition.GetMatch())
	case *corev1.Condition_Not:
		return IsBodyExpression(condition.GetNot())
	case *corev1.Condition_All_:
		return slices.ContainsFunc(condition.GetAll().GetOf(), IsBodyCondition)
	case *corev1.Condition_Any_:
		return slices.ContainsFunc(condition.GetAny().GetOf(), IsBodyCondition)
	case *corev1.Condition_None_:
		return slices.ContainsFunc(condition.GetNone().GetOf(), IsBodyCondition)
	case *corev1.Condition_Opa:
		return IsBodyExpression(condition.GetOpa().GetInline())
	default:
		return false
	}
}
