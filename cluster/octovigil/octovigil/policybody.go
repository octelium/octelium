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
	"regexp"
	"slices"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
)

var rgxBodyRef = regexp.MustCompile(`\bbody(Map)?\b`)

func isBodyOmitted(i *corev1.RequestContext) bool {
	return ucorev1.GetRequestHTTP(i.GetRequest()).GetIsBodyOmitted()
}

func isBodyCondition(condition *corev1.Condition) bool {
	if condition == nil {
		return false
	}

	switch condition.Type.(type) {
	case *corev1.Condition_Match:
		return rgxBodyRef.MatchString(condition.GetMatch())
	case *corev1.Condition_Not:
		return rgxBodyRef.MatchString(condition.GetNot())
	case *corev1.Condition_All_:
		return slices.ContainsFunc(condition.GetAll().GetOf(), isBodyCondition)
	case *corev1.Condition_Any_:
		return slices.ContainsFunc(condition.GetAny().GetOf(), isBodyCondition)
	case *corev1.Condition_None_:
		return slices.ContainsFunc(condition.GetNone().GetOf(), isBodyCondition)
	case *corev1.Condition_Opa:
		return rgxBodyRef.MatchString(condition.GetOpa().GetInline())
	default:
		return false
	}
}

func isBodyPreCondition(preCondition *corev1.PolicyTrigger_Status_PreCondition) bool {
	if preCondition == nil {
		return false
	}

	switch preCondition.Type.(type) {
	case *corev1.PolicyTrigger_Status_PreCondition_Condition:
		return isBodyCondition(preCondition.GetCondition())
	case *corev1.PolicyTrigger_Status_PreCondition_All_:
		return slices.ContainsFunc(preCondition.GetAll().GetOf(), isBodyPreCondition)
	case *corev1.PolicyTrigger_Status_PreCondition_Any_:
		return slices.ContainsFunc(preCondition.GetAny().GetOf(), isBodyPreCondition)
	default:
		return false
	}
}
