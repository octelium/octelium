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

package genesis

import (
	"context"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"go.uber.org/zap"
)

func (g *Genesis) getBuiltinPolicies(ctx context.Context) (*corev1.PolicyList, error) {

	ret := &corev1.PolicyList{}

	ret.Items = append(ret.Items, &corev1.Policy{
		Metadata: &metav1.Metadata{
			Name: "allow-all",
		},
		Spec: &corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_ALLOW,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{
							MatchAny: true,
						},
					},
				},
			},
		},
	})

	ret.Items = append(ret.Items, &corev1.Policy{
		Metadata: &metav1.Metadata{
			Name: "deny-all",
		},
		Spec: &corev1.Policy_Spec{
			Rules: []*corev1.Policy_Spec_Rule{
				{
					Effect: corev1.Policy_Spec_Rule_DENY,
					Condition: &corev1.Condition{
						Type: &corev1.Condition_MatchAny{
							MatchAny: true,
						},
					},
				},
			},
		},
	})

	return ret, nil
}

func (g *Genesis) installBuiltinPolicies(ctx context.Context) error {

	zap.L().Debug("Starting installing builtin Policies")

	polList, err := g.getBuiltinPolicies(ctx)
	if err != nil {
		return err
	}

	for _, itm := range polList.Items {
		pol, err := g.octeliumC.CoreC().GetPolicy(ctx, &rmetav1.GetOptions{
			Name: itm.Metadata.Name,
		})
		if err != nil {
			if !grpcerr.IsNotFound(err) {
				return err
			}

			_, err := g.octeliumC.CoreC().CreatePolicy(ctx, itm)
			if err != nil {
				return err
			}
		} else {

			if !pbutils.IsEqual(pol.Spec, itm.Spec) {
				pol.Spec = itm.Spec
				_, err := g.octeliumC.CoreC().UpdatePolicy(ctx, pol)
				if err != nil {
					return err
				}
			}

		}
	}

	zap.L().Debug("Successfully installed builtin Policies")

	return nil
}
