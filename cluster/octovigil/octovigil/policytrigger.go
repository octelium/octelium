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
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
)

func (s *Server) getRulesFromPolicyTriggers(ctx context.Context,
	i *corev1.RequestContext, reqCtxMap map[string]any, usedPolicies *[]string) ([]*policyRule, error) {
	var ret []*policyRule

	s.policyTriggerCtl.RLock()
	defer s.policyTriggerCtl.RUnlock()

	for _, pt := range s.policyTriggerCtl.ptMap {
		if pt.Status.IsDisabled {
			continue
		}

		rules, err := s.getRulesFromPolicyTrigger(ctx, i, reqCtxMap, pt, usedPolicies)
		if err != nil {
			continue
		}
		if len(rules) == 0 {
			continue
		}

		ret = append(ret, rules...)
	}

	return ret, nil
}

func (s *Server) getRulesFromPolicyTrigger(ctx context.Context,
	i *corev1.RequestContext, reqCtxMap map[string]any, pt *corev1.PolicyTrigger, usedPolicies *[]string) ([]*policyRule, error) {

	isMatched, err := s.doEvalPreCondition(ctx, i, map[string]any{
		"ctx": reqCtxMap,
	}, pt.Status.PreCondition)
	if err != nil {
		return nil, err
	}
	if !isMatched {
		return nil, nil
	}

	return s.getResourcePolicyRules(ctx,
		i, reqCtxMap, pt.Status.Policies, pt.Status.InlinePolicies, pt.Status.OwnerRef, usedPolicies)

}

func (s *Server) doEvalPreCondition(ctx context.Context, i *corev1.RequestContext,
	inputMap map[string]any, preCondition *corev1.PolicyTrigger_Status_PreCondition) (bool, error) {

	if preCondition == nil {
		return false, nil
	}

	var didMatch bool

	switch preCondition.Type.(type) {
	case *corev1.PolicyTrigger_Status_PreCondition_Condition:
		res, err := s.celEngine.EvalCondition(ctx, preCondition.GetCondition(), inputMap)
		if err != nil {
			return false, err
		}
		if !res {
			return false, nil
		}
		didMatch = true
	case *corev1.PolicyTrigger_Status_PreCondition_MatchAny:
		if !preCondition.GetMatchAny() {
			return false, nil
		}
		didMatch = true
	case *corev1.PolicyTrigger_Status_PreCondition_NotAfter:
		if preCondition.GetNotAfter().IsValid() {
			if time.Now().After(preCondition.GetNotAfter().AsTime()) {
				return false, nil
			}

			didMatch = true
		}
	case *corev1.PolicyTrigger_Status_PreCondition_NotBefore:
		if preCondition.GetNotBefore().IsValid() {
			if time.Now().Before(preCondition.GetNotBefore().AsTime()) {
				return false, nil
			}

			didMatch = true
		}
	case *corev1.PolicyTrigger_Status_PreCondition_SessionRef:
		if preCondition.GetSessionRef() != nil && i.Session != nil {
			if preCondition.GetSessionRef().Uid != i.Session.Metadata.Uid {
				return false, nil
			}

			didMatch = true
		}
	case *corev1.PolicyTrigger_Status_PreCondition_UserRef:
		if preCondition.GetUserRef() != nil && i.User != nil {
			if preCondition.GetUserRef().Uid != i.User.Metadata.Uid {
				return false, nil
			}

			didMatch = true
		}
	case *corev1.PolicyTrigger_Status_PreCondition_All_:
		res, err := s.isPreConditionMatchedAll(ctx, i, inputMap, preCondition.GetAll())
		if err != nil {
			return false, err
		}
		if !res {
			return false, nil
		}
		didMatch = true
	case *corev1.PolicyTrigger_Status_PreCondition_Any_:
		res, err := s.isPreConditionMatchedAny(ctx, i, inputMap, preCondition.GetAny())
		if err != nil {
			return false, err
		}
		if !res {
			return false, nil
		}
		didMatch = true
	}

	return didMatch, nil
}

func (s *Server) isPreConditionMatchedAny(ctx context.Context, i *corev1.RequestContext,
	inputMap map[string]any, anyC *corev1.PolicyTrigger_Status_PreCondition_Any) (bool, error) {

	if anyC == nil || len(anyC.Of) == 0 {
		return false, nil
	}

	for _, condition := range anyC.Of {
		isMatched, err := s.doEvalPreCondition(ctx, i, inputMap, condition)
		if err != nil {
			return false, err
		}

		if isMatched {
			return true, nil
		}
	}

	return false, nil
}

func (s *Server) isPreConditionMatchedAll(ctx context.Context, i *corev1.RequestContext,
	inputMap map[string]any, allC *corev1.PolicyTrigger_Status_PreCondition_All) (bool, error) {

	if allC == nil || len(allC.Of) == 0 {
		return false, nil
	}

	for _, condition := range allC.Of {
		isMatched, err := s.doEvalPreCondition(ctx, i, inputMap, condition)
		if err != nil {
			return false, err
		}

		if !isMatched {
			return false, nil
		}
	}

	return true, nil
}
