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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/common"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/apivalidation"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
)

const priorityMaxVal = 4

func (s *Server) CreatePolicy(ctx context.Context, req *corev1.Policy) (*corev1.Policy, error) {

	if err := s.validatePolicy(ctx, req); err != nil {
		return nil, serr.InvalidArgWithErr(err)
	}

	_, err := s.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
	if err == nil {
		return nil, grpcutils.AlreadyExists("The Policy %s already exists", req.Metadata.Name)
	}
	if !grpcerr.IsNotFound(err) {
		return nil, grpcutils.InternalWithErr(err)
	}

	policyNames, err := apivalidation.GetNameAndParents(req.Metadata.Name)
	if err != nil {
		return nil, serr.InvalidArgWithErr(err)
	}

	item := &corev1.Policy{
		Metadata: common.MetadataFrom(req.Metadata),
		Spec:     req.Spec,
		Status:   &corev1.Policy_Status{},
	}

	if len(policyNames) > 1 {
		parentPolicy, err := s.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{Name: policyNames[1]})
		if err != nil {
			if !grpcerr.IsNotFound(err) {
				return nil, grpcutils.InternalWithErr(err)
			}
			return nil, grpcutils.InvalidArg("The Policy %s does not exist", policyNames[1])
		}

		item.Status.ParentPolicyRef = umetav1.GetObjectReference(parentPolicy)
	}

	if err := s.validatePolicySpec(ctx, item.Spec); err != nil {
		return nil, grpcutils.InvalidArg("%s", err)
	}

	item, err = s.octeliumC.CoreC().CreatePolicy(ctx, item)
	if err != nil {
		return nil, err
	}

	return item, nil
}

func (s *Server) UpdatePolicy(ctx context.Context, req *corev1.Policy) (*corev1.Policy, error) {
	if err := s.validatePolicy(ctx, req); err != nil {
		return nil, serr.InvalidArgWithErr(err)
	}

	item, err := s.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{Name: req.Metadata.Name})
	if err != nil {
		return nil, err
	}

	if err := apivalidation.CheckIsSystem(item); err != nil {
		return nil, err
	}

	common.MetadataUpdate(item.Metadata, req.Metadata)
	item.Spec = req.Spec

	if err := s.validatePolicySpec(ctx, item.Spec); err != nil {
		return nil, grpcutils.InvalidArg("%s", err)
	}

	item, err = s.octeliumC.CoreC().UpdatePolicy(ctx, item)
	if err != nil {
		return nil, err
	}

	return item, nil
}

func (s *Server) ListPolicy(ctx context.Context, req *corev1.ListPolicyOptions) (*corev1.PolicyList, error) {

	itemList, err := s.octeliumC.CoreC().ListPolicy(ctx, urscsrv.GetPublicListOptions(req))
	if err != nil {
		return nil, err
	}

	return itemList, nil
}

func (s *Server) DeletePolicy(ctx context.Context, req *metav1.DeleteOptions) (*metav1.OperationResult, error) {
	if err := apivalidation.CheckDeleteOptions(req, &apivalidation.CheckGetOptionsOpts{
		ParentsMax: vutils.MaxPolicyParents,
	}); err != nil {
		return nil, err
	}

	g, err := s.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{Name: req.Name, Uid: req.Uid})
	if err != nil {
		return nil, err
	}

	if err := apivalidation.CheckIsSystem(g); err != nil {
		return nil, err
	}

	childPolicyList, err := s.octeliumC.CoreC().ListPolicy(ctx, &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterFieldEQValStr("status.parentPolicyRef.uid", g.Metadata.Uid),
		},
	})
	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	if len(childPolicyList.Items) > 0 {
		return nil, serr.InvalidArg("The Policy: %s has one or more child Policies", req.Name)
	}

	_, err = s.octeliumC.CoreC().DeletePolicy(ctx, &rmetav1.DeleteOptions{Uid: g.Metadata.Uid})
	if err != nil {
		return nil, serr.K8sInternal(err)
	}

	return &metav1.OperationResult{}, nil
}

func (s *Server) GetPolicy(ctx context.Context, req *metav1.GetOptions) (*corev1.Policy, error) {
	if err := apivalidation.CheckGetOptions(req, &apivalidation.CheckGetOptionsOpts{
		ParentsMax: vutils.MaxPolicyParents,
	}); err != nil {
		return nil, err
	}

	ret, err := s.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	})
	if err != nil {
		return nil, serr.K8sNotFoundOrInternalWithErr(err)
	}

	return ret, nil
}

func (s *Server) validatePolicy(ctx context.Context, p *corev1.Policy) error {
	if err := apivalidation.ValidateCommon(p, &apivalidation.ValidateCommonOpts{
		ValidateMetadataOpts: apivalidation.ValidateMetadataOpts{
			RequireName: true,
			ParentsMax:  vutils.MaxPolicyParents,
		},
	}); err != nil {
		return err
	}

	if err := s.validatePolicySpec(ctx, p.Spec); err != nil {
		return grpcutils.InvalidArgWithErr(err)
	}

	return nil
}

func (s *Server) validatePolicySpec(ctx context.Context, p *corev1.Policy_Spec) error {
	if p == nil {
		return grpcutils.InvalidArg("Nil spec")
	}

	if err := apivalidation.ValidateAttrs(p.Attrs); err != nil {
		return err
	}

	{
		specBytes, err := pbutils.Marshal(p)
		if err != nil {
			return grpcutils.InvalidArg("Could not marshal Policy spec")
		}
		if len(specBytes) > 100000 {
			return grpcutils.InvalidArg("Policy is too large")
		}
	}

	if len(p.Rules) > 100 {
		return grpcutils.InvalidArg("Too many rules")
	}

	if len(p.EnforcementRules) > 100 {
		return grpcutils.InvalidArg("Too many enforcement rules")
	}

	for _, rule := range p.Rules {
		if rule.Name != "" {
			if err := apivalidation.ValidateName(rule.Name, 0, 0); err != nil {
				return err
			}
		}

		if rule.Effect == corev1.Policy_Spec_Rule_EFFECT_UNKNOWN {
			return grpcutils.InvalidArg("Rule's effect must be set")
		}

		if rule.Priority > priorityMaxVal {
			return grpcutils.InvalidArg("Rule's priority cannot be higher than %d", priorityMaxVal)
		}

		if rule.Priority < -1*priorityMaxVal {
			return grpcutils.InvalidArg("Rule's priority cannot be lower than -%d", priorityMaxVal)
		}

		if err := s.validateCondition(ctx, rule.Condition); err != nil {
			return err
		}
	}

	for _, rule := range p.EnforcementRules {

		if rule.Effect == corev1.Policy_Spec_EnforcementRule_EFFECT_UNKNOWN {
			return grpcutils.InvalidArg("Unknown effect. It must be either `ENFORCE` or `IGNORE`")
		}

		if err := s.validateCondition(ctx, rule.Condition); err != nil {
			return err
		}

	}

	return nil
}

func (s *Server) validateCondition(ctx context.Context, c *corev1.Condition) error {
	if c == nil {
		return grpcutils.InvalidArg("Condition is not set")
	}

	switch c.Type.(type) {
	case *corev1.Condition_All_:
		arg := c.GetAll()
		if len(arg.Of) == 0 {
			return grpcutils.InvalidArg("Empty allOf array")
		}
		if len(arg.Of) > 100 {
			return grpcutils.InvalidArg("allOf array is too long")
		}
		for _, cond := range arg.Of {
			if err := s.validateCondition(ctx, cond); err != nil {
				return err
			}
		}

	case *corev1.Condition_Any_:
		arg := c.GetAny()
		if len(arg.Of) == 0 {
			return grpcutils.InvalidArg("Empty anyOf array")
		}
		if len(arg.Of) > 100 {
			return grpcutils.InvalidArg("anyOf array is too long")
		}
		for _, cond := range arg.Of {
			if err := s.validateCondition(ctx, cond); err != nil {
				return err
			}
		}
	case *corev1.Condition_Match:
		if err := checkCELExpression(ctx, c.GetMatch()); err != nil {
			return err
		}
	case *corev1.Condition_MatchAny:
	case *corev1.Condition_None_:
		arg := c.GetNone()
		if len(arg.Of) == 0 {
			return grpcutils.InvalidArg("Empty noneOf array")
		}
		if len(arg.Of) > 100 {
			return grpcutils.InvalidArg("noneOf array is too long")
		}
		for _, cond := range arg.Of {
			if err := s.validateCondition(ctx, cond); err != nil {
				return err
			}
		}
	case *corev1.Condition_Not:
		if err := checkCELExpression(ctx, c.GetNot()); err != nil {
			return err
		}
	case *corev1.Condition_Opa:
	default:
		return grpcutils.InvalidArg("Invalid Condition type")
	}

	return nil
}

type policyOwner interface {
	GetPolicies() []string
	GetInlinePolicies() []*corev1.InlinePolicy
}

func (s *Server) validatePolicyOwner(ctx context.Context, owner policyOwner) error {
	if owner == nil {
		return nil
	}
	policies := owner.GetPolicies()
	inlinePolices := owner.GetInlinePolicies()
	if len(policies) > 100 {
		return grpcutils.InvalidArg("Too many Policies")
	}
	if len(inlinePolices) > 100 {
		return grpcutils.InvalidArg("Too many inlinePolicies")
	}

	for _, pol := range policies {
		if err := apivalidation.ValidateName(pol, 0, vutils.MaxPolicyParents); err != nil {
			return grpcutils.InvalidArgWithErr(err)
		}
		_, err := s.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{
			Name: pol,
		})
		if err != nil {
			if grpcerr.IsNotFound(err) {
				return grpcutils.InvalidArg("The Policy %s does not exist", pol)
			}
			return grpcutils.InternalWithErr(err)
		}
	}

	for _, pol := range inlinePolices {
		if pol.Name != "" {
			if err := apivalidation.ValidateName(pol.Name, 0, 0); err != nil {
				return grpcutils.InvalidArgWithErr(err)
			}
		}

		if err := s.validatePolicySpec(ctx, pol.Spec); err != nil {
			return err
		}
	}

	return nil
}
