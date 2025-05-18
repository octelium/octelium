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
	"slices"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"go.uber.org/zap"
)

type policyDecisionResult struct {
	decision matchDecision
	effect   corev1.Policy_Spec_Rule_Effect
	reason   *corev1.AccessLog_Entry_Common_Reason
}

type getDecisionReq struct {
	i *corev1.RequestContext
}

type getDecisionResp struct {
	decision matchDecision
	effect   corev1.Policy_Spec_Rule_Effect
	reason   *corev1.AccessLog_Entry_Common_Reason
}

type policyRule struct {
	rule      *corev1.Policy_Spec_Rule
	policyRef *metav1.ObjectReference
	inline    *policyRuleInline
	attrs     map[string]any
}

type policyRuleInline struct {
	name        string
	resourceRef *metav1.ObjectReference
}

func (s *Server) getDecision(ctx context.Context, req *getDecisionReq) (*getDecisionResp, error) {
	reqCtxMap, err := pbutils.ConvertToMap(req.i)
	if err != nil {
		return nil, err
	}

	allRules, err := s.getAllRules(ctx, req, reqCtxMap)
	if err != nil {
		return nil, err
	}

	return s.doGetDecision(ctx, reqCtxMap, allRules)
}

func (s *Server) doGetDecision(ctx context.Context, reqCtxMap map[string]any, allRules []*policyRule) (*getDecisionResp, error) {

	slices.SortFunc(allRules, func(a, b *policyRule) int {
		if diff := a.rule.Priority - b.rule.Priority; diff < 0 {
			return -1
		} else if diff > 0 {
			return 1
		}

		switch {
		case a.rule.Effect == corev1.Policy_Spec_Rule_DENY && b.rule.Effect == corev1.Policy_Spec_Rule_ALLOW:
			return -1
		case a.rule.Effect == corev1.Policy_Spec_Rule_ALLOW && b.rule.Effect == corev1.Policy_Spec_Rule_DENY:
			return 1
		}

		return 0
	})

	for _, rule := range allRules {
		res, err := s.getDecisionRule(ctx, &getDecisionRuleReq{
			rule:      rule,
			reqCtxMap: reqCtxMap,
		})
		if err != nil {
			zap.L().Debug("Could not getDecisionRule of denyRule", zap.Error(err))
			continue
		}
		if res.decision == matchDecisionMATCH_YES {
			ret := &getDecisionResp{
				decision: res.decision,
				effect:   res.effect,
				reason:   res.reason,
			}
			return ret, nil
		}
	}

	return &getDecisionResp{
		decision: matchDecisionMATCH_NO,
		effect:   corev1.Policy_Spec_Rule_DENY,
	}, nil
}

func (s *Server) getPolicyFromName(ctx context.Context, name string) (*corev1.Policy, error) {
	policy, err := s.cache.GetPolicy(name)
	if err == nil {
		return policy, nil
	}
	if !s.cache.IsErrNotFound(err) {
		return nil, err
	}

	policy, err = s.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{
		Name: name,
	})
	if err != nil {
		return nil, err
	}

	s.cache.SetPolicy(policy)

	return policy, nil
}

func (s *Server) getNamespaceFromName(ctx context.Context, name string) (*corev1.Namespace, error) {
	ns, err := s.cache.GetNamespace(name)
	if err == nil {
		return ns, nil
	}
	if !s.cache.IsErrNotFound(err) {
		return nil, err
	}

	ns, err = s.octeliumC.CoreC().GetNamespace(ctx, &rmetav1.GetOptions{
		Name: name,
	})
	if err != nil {
		return nil, err
	}

	s.cache.SetNamespace(ns)

	return ns, nil
}

func isInList(lst []string, itm string) bool {
	for _, x := range lst {
		if x == itm {
			return true
		}
	}
	return false
}

func (s *Server) getEvaluatePolicyRules(ctx context.Context, req *coctovigilv1.EvaluateRequest, reqCtxMap map[string]any) ([]*policyRule, error) {
	var ret []*policyRule

	var usedPolicies []string

	for _, name := range req.Policies {

		allPolices, err := apivalidation.GetNameAndParents(name)
		if err != nil {
			return nil, err
		}

		for _, p := range allPolices {
			policy, err := s.getPolicyFromName(ctx, p)
			if err != nil {
				continue
			}

			if policy.Spec.IsDisabled {
				continue
			}

			attrs, err := pbutils.ConvertToMap(policy.Spec.Attrs)
			if err != nil {
				zap.L().Debug("Could not unmarshal attrs", zap.Error(err))
				continue
			}

			if !s.shouldEnforcePolicy(ctx, &shouldEnforcePolicyReq{
				spec:      policy.Spec,
				reqCtxMap: reqCtxMap,
				attrs:     attrs,
			}) {
				continue
			}
			if isInList(usedPolicies, policy.Metadata.Name) {
				continue
			}
			usedPolicies = append(usedPolicies, policy.Metadata.Name)

			policyRef := umetav1.GetObjectReference(policy)
			for _, rule := range policy.Spec.Rules {
				ret = append(ret, &policyRule{
					rule:      rule,
					policyRef: policyRef,
					attrs:     attrs,
				})
			}
		}

	}

	for _, p := range req.InlinePolicies {
		if p.Policy.Spec.IsDisabled {
			continue
		}
		attrs, err := pbutils.ConvertToMap(p.Policy.Spec.Attrs)
		if err != nil {
			continue
		}
		if !s.shouldEnforcePolicy(ctx, &shouldEnforcePolicyReq{
			spec:      p.Policy.Spec,
			reqCtxMap: reqCtxMap,
			attrs:     attrs,
		}) {
			continue
		}

		for _, rule := range p.Policy.Spec.Rules {
			ret = append(ret, &policyRule{
				rule: rule,
				inline: &policyRuleInline{
					name:        p.Policy.Name,
					resourceRef: p.ResourceRef,
				},
				attrs: attrs,
			})
		}

	}

	return ret, nil
}

func (s *Server) getResourcePolicyRules(ctx context.Context,
	reqCtx *corev1.RequestContext, reqCtxMap map[string]any,
	policies []string, inlinePolicies []*corev1.InlinePolicy,
	resourceRef *metav1.ObjectReference,
	usedPolicies *[]string) ([]*policyRule, error) {
	var ret []*policyRule

	for _, name := range policies {

		allPolices, err := apivalidation.GetNameAndParents(name)
		if err != nil {
			return nil, err
		}

		for _, p := range allPolices {
			policy, err := s.getPolicyFromName(ctx, p)
			if err != nil {
				continue
			}

			if policy.Spec.IsDisabled {
				continue
			}

			attrs, err := pbutils.ConvertToMap(policy.Spec.Attrs)
			if err != nil {
				zap.L().Debug("Could not unmarshal attrs", zap.Error(err))
				continue
			}

			if !s.shouldEnforcePolicy(ctx, &shouldEnforcePolicyReq{
				spec:      policy.Spec,
				reqCtxMap: reqCtxMap,
				attrs:     attrs,
			}) {
				continue
			}
			if isInList(*usedPolicies, policy.Metadata.Name) {
				continue
			}
			*usedPolicies = append(*usedPolicies, policy.Metadata.Name)

			policyRef := umetav1.GetObjectReference(policy)
			for _, rule := range policy.Spec.Rules {
				ret = append(ret, &policyRule{
					rule:      rule,
					policyRef: policyRef,
					attrs:     attrs,
				})
			}
		}

	}

	for _, p := range inlinePolicies {
		if p.Spec.IsDisabled {
			continue
		}
		attrs, err := pbutils.ConvertToMap(p.Spec.Attrs)
		if err != nil {
			continue
		}
		if !s.shouldEnforcePolicy(ctx, &shouldEnforcePolicyReq{
			spec:      p.Spec,
			reqCtxMap: reqCtxMap,
			attrs:     attrs,
		}) {
			continue
		}

		for _, rule := range p.Spec.Rules {
			ret = append(ret, &policyRule{
				rule: rule,
				inline: &policyRuleInline{
					name:        p.Name,
					resourceRef: resourceRef,
				},
				attrs: attrs,
			})
		}

	}

	return ret, nil
}

func (s *Server) getAllRules(ctx context.Context, req *getDecisionReq, reqCtxMap map[string]any) ([]*policyRule, error) {
	var ret []*policyRule

	i := req.i

	var usedPolicies []string

	if i.User.Spec.Authorization != nil {
		rules, err := s.getResourcePolicyRules(ctx,
			req.i, reqCtxMap,
			i.User.Spec.Authorization.Policies,
			i.User.Spec.Authorization.InlinePolicies,
			umetav1.GetObjectReference(i.User), &usedPolicies)
		if err != nil {
			return nil, err
		}
		ret = append(ret, rules...)
	}

	for _, grp := range i.Groups {
		if grp.Spec.Authorization != nil {
			rules, err := s.getResourcePolicyRules(ctx,
				req.i, reqCtxMap,
				grp.Spec.Authorization.Policies,
				grp.Spec.Authorization.InlinePolicies,
				umetav1.GetObjectReference(grp), &usedPolicies)
			if err != nil {
				return nil, err
			}
			ret = append(ret, rules...)
		}
	}

	if i.Service.Spec.Authorization != nil {
		rules, err := s.getResourcePolicyRules(ctx,
			req.i, reqCtxMap,
			i.Service.Spec.Authorization.Policies,
			i.Service.Spec.Authorization.InlinePolicies,
			umetav1.GetObjectReference(i.Service), &usedPolicies)
		if err != nil {
			return nil, err
		}
		ret = append(ret, rules...)
	}

	if ns, err := s.getNamespaceFromName(ctx, i.Service.Status.NamespaceRef.Name); err == nil {
		if ns.Spec.Authorization != nil {

			rules, err := s.getResourcePolicyRules(ctx,
				req.i, reqCtxMap,
				ns.Spec.Authorization.Policies,
				ns.Spec.Authorization.InlinePolicies,
				umetav1.GetObjectReference(ns), &usedPolicies)
			if err != nil {
				return nil, err
			}
			ret = append(ret, rules...)
		}
	}

	if i.Session.Spec.Authorization != nil {
		rules, err := s.getResourcePolicyRules(ctx,
			req.i, reqCtxMap,
			i.Session.Spec.Authorization.Policies,
			i.Session.Spec.Authorization.InlinePolicies,
			umetav1.GetObjectReference(i.Session), &usedPolicies)
		if err != nil {
			return nil, err
		}
		ret = append(ret, rules...)
	}

	if i.Device != nil && i.Device.Spec.Authorization != nil {
		rules, err := s.getResourcePolicyRules(ctx,
			req.i, reqCtxMap,
			i.Device.Spec.Authorization.Policies,
			i.Device.Spec.Authorization.InlinePolicies,
			umetav1.GetObjectReference(i.Device), &usedPolicies)
		if err != nil {
			return nil, err
		}
		ret = append(ret, rules...)
	}

	if rules, err := s.getRulesFromPolicyTriggers(ctx, req.i, reqCtxMap, &usedPolicies); err == nil {
		ret = append(ret, rules...)
	}

	return ret, nil
}

type getDecisionRuleReq struct {
	rule      *policyRule
	reqCtxMap map[string]any
}

func (s *Server) getDecisionRule(ctx context.Context, req *getDecisionRuleReq) (*policyDecisionResult, error) {
	rule := req.rule.rule
	reqCtxMap := req.reqCtxMap

	resp := &policyDecisionResult{
		decision: matchDecisionMATCH_NO,
	}

	var didMatch bool

	inputMap := map[string]any{
		"ctx":   reqCtxMap,
		"attrs": req.rule.attrs,
	}

	if rule.Condition != nil {
		isMatched, err := s.celEngine.EvalCondition(ctx, rule.Condition, inputMap)
		if err != nil {
			return nil, err
		}
		if !isMatched {
			return resp, nil
		}
		didMatch = true
	}

	if didMatch {
		resp.decision = matchDecisionMATCH_YES
		resp.effect = rule.Effect
		resp.reason = s.getMatchedDecisionReason(req.rule)
	}

	return resp, nil
}

func (s *Server) getMatchedDecisionReason(rule *policyRule) *corev1.AccessLog_Entry_Common_Reason {
	ret := &corev1.AccessLog_Entry_Common_Reason{
		Type: corev1.AccessLog_Entry_Common_Reason_POLICY_MATCH,
		Details: &corev1.AccessLog_Entry_Common_Reason_Details{
			Type: &corev1.AccessLog_Entry_Common_Reason_Details_PolicyMatch_{
				PolicyMatch: &corev1.AccessLog_Entry_Common_Reason_Details_PolicyMatch{
					RuleName: rule.rule.Name,
					Priority: rule.rule.Priority,
				},
			},
		},
	}

	switch {
	case rule.policyRef != nil:
		ret.Details.GetPolicyMatch().Type = &corev1.AccessLog_Entry_Common_Reason_Details_PolicyMatch_Policy_{
			Policy: &corev1.AccessLog_Entry_Common_Reason_Details_PolicyMatch_Policy{
				PolicyRef: rule.policyRef,
			},
		}
	case rule.inline != nil:
		ret.Details.GetPolicyMatch().Type = &corev1.AccessLog_Entry_Common_Reason_Details_PolicyMatch_InlinePolicy_{
			InlinePolicy: &corev1.AccessLog_Entry_Common_Reason_Details_PolicyMatch_InlinePolicy{
				ResourceRef: rule.inline.resourceRef,
				Name:        rule.inline.name,
			},
		}
	}

	return ret
}

type getDecisionEnforcementRuleReq struct {
	rule      *corev1.Policy_Spec_EnforcementRule
	reqCtxMap map[string]any
	// reqCtx    *corev1.RequestContext
	attrs map[string]any
}

type getDecisionEnforcementRuleRes struct {
	decision matchDecision
	effect   corev1.Policy_Spec_EnforcementRule_Effect
}

type shouldEnforcePolicyReq struct {
	spec      *corev1.Policy_Spec
	reqCtxMap map[string]any
	attrs     map[string]any
}

func (s *Server) shouldEnforcePolicy(ctx context.Context, req *shouldEnforcePolicyReq) bool {
	if len(req.spec.EnforcementRules) == 0 {
		return true
	}

	var enforceRules []*corev1.Policy_Spec_EnforcementRule
	var ignoreRules []*corev1.Policy_Spec_EnforcementRule

	for _, rule := range req.spec.EnforcementRules {
		switch rule.Effect {
		case corev1.Policy_Spec_EnforcementRule_ENFORCE:
			enforceRules = append(enforceRules, rule)
		case corev1.Policy_Spec_EnforcementRule_IGNORE:
			ignoreRules = append(ignoreRules, rule)
		}
	}

	for _, rule := range enforceRules {
		res, err := s.getDecisionEnforcementRule(ctx, &getDecisionEnforcementRuleReq{
			rule:      rule,
			reqCtxMap: req.reqCtxMap,
			attrs:     req.attrs,
		})
		if err != nil {
			continue
		}
		if res.decision == matchDecisionMATCH_YES {
			return true
		}
	}

	for _, rule := range ignoreRules {
		res, err := s.getDecisionEnforcementRule(ctx, &getDecisionEnforcementRuleReq{
			rule:      rule,
			reqCtxMap: req.reqCtxMap,
			attrs:     req.attrs,
		})
		if err != nil {
			continue
		}
		if res.decision == matchDecisionMATCH_YES {
			return false
		}
	}

	return true
}

func (s *Server) getDecisionEnforcementRule(ctx context.Context,
	req *getDecisionEnforcementRuleReq) (*getDecisionEnforcementRuleRes, error) {
	rule := req.rule
	reqCtxMap := req.reqCtxMap

	resp := &getDecisionEnforcementRuleRes{
		decision: matchDecisionMATCH_NO,
	}

	var didMatch bool

	inputMap := map[string]any{
		"ctx":   reqCtxMap,
		"attrs": req.attrs,
	}

	if rule.Condition != nil {
		isMatched, err := s.celEngine.EvalCondition(ctx, rule.Condition, inputMap)
		if err != nil {
			return nil, err
		}
		if !isMatched {
			return resp, nil
		}
		didMatch = true
	}

	if didMatch {
		resp.decision = matchDecisionMATCH_YES
		resp.effect = rule.Effect
	}

	return resp, nil
}
