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

package cluster_config

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
)

type Controller struct {
	octeliumC octeliumc.ClientInterface
	k8sC      kubernetes.Interface
}

func NewController(
	octeliumC octeliumc.ClientInterface,
	k8sC kubernetes.Interface,
) *Controller {
	return &Controller{
		octeliumC: octeliumC,
		k8sC:      k8sC,
	}
}

func (c *Controller) OnUpdate(ctx context.Context, new, old *corev1.ClusterConfig) error {

	if err := c.setPolicyTrigger(ctx, new, old); err != nil {
		return err
	}

	return nil
}

func (c *Controller) setPolicyTrigger(ctx context.Context, new, old *corev1.ClusterConfig) error {

	if pbutils.IsEqual(new.Spec.Authorization, old.Spec.Authorization) {
		return nil
	}
	name := "cc-global"
	pt, err := c.octeliumC.CoreC().GetPolicyTrigger(ctx, &rmetav1.GetOptions{
		Name: name,
	})
	if err == nil {
		if new.Spec.Authorization == nil {
			pt.Status.InlinePolicies = nil
			pt.Status.Policies = nil
		} else {
			pt.Status.InlinePolicies = new.Spec.Authorization.InlinePolicies
			pt.Status.Policies = new.Spec.Authorization.Policies
		}

		pt.Status.OwnerRef = umetav1.GetObjectReference(new)

		pt, err = c.octeliumC.CoreC().UpdatePolicyTrigger(ctx, pt)
		if err != nil {
			return err
		}
		zap.L().Debug("Successfully update cc-global PolicyTrigger", zap.Any("policyTrigger", pt))
		return nil
	} else if !grpcerr.IsNotFound(err) {
		return err
	}

	zap.L().Debug("Creating cc-global PolicyTrigger")
	_, err = c.octeliumC.CoreC().CreatePolicyTrigger(ctx, &corev1.PolicyTrigger{
		Metadata: &metav1.Metadata{
			Name: name,
		},
		Spec: &corev1.PolicyTrigger_Spec{},
		Status: &corev1.PolicyTrigger_Status{
			OwnerRef: umetav1.GetObjectReference(new),
			PreCondition: &corev1.PolicyTrigger_Status_PreCondition{
				Type: &corev1.PolicyTrigger_Status_PreCondition_MatchAny{
					MatchAny: true,
				},
			},
			Policies: func() []string {
				if new.Spec.Authorization == nil {
					return nil
				}
				return new.Spec.Authorization.Policies
			}(),
			InlinePolicies: func() []*corev1.InlinePolicy {
				if new.Spec.Authorization == nil {
					return nil
				}

				return new.Spec.Authorization.InlinePolicies
			}(),
		},
	})
	if err != nil {
		return err
	}

	return nil
}
