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
	"slices"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/celengine"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
)

func isBodyOmitted(i *corev1.RequestContext) bool {
	return ucorev1.GetRequestHTTP(i.GetRequest()).GetIsBodyOmitted()
}

func isBodyPreCondition(preCondition *corev1.PolicyTrigger_Status_PreCondition) bool {
	if preCondition == nil {
		return false
	}

	switch preCondition.Type.(type) {
	case *corev1.PolicyTrigger_Status_PreCondition_Condition:
		return celengine.IsBodyCondition(preCondition.GetCondition())
	case *corev1.PolicyTrigger_Status_PreCondition_All_:
		return slices.ContainsFunc(preCondition.GetAll().GetOf(), isBodyPreCondition)
	case *corev1.PolicyTrigger_Status_PreCondition_Any_:
		return slices.ContainsFunc(preCondition.GetAny().GetOf(), isBodyPreCondition)
	default:
		return false
	}
}
