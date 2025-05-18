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

package tests

import (
	"fmt"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
)

func GenUser(groups []string) *corev1.User {
	ret := &corev1.User{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("usr-%s", utilrand.GetRandomStringLowercase(6)),
		},
		Spec: &corev1.User_Spec{
			Type:   corev1.User_Spec_WORKLOAD,
			Groups: groups,
		},
	}

	return ret
}

func GenUserHuman(groups []string) *corev1.User {
	ret := &corev1.User{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("usr-%s", utilrand.GetRandomStringLowercase(6)),
		},
		Spec: &corev1.User_Spec{
			Type:   corev1.User_Spec_HUMAN,
			Groups: groups,
		},
	}

	return ret
}

func GenGroup() *corev1.Group {
	ret := &corev1.Group{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("group-%s", utilrand.GetRandomStringLowercase(6)),
		},
		Spec: &corev1.Group_Spec{},
	}

	return ret
}

func GenNamespace() *corev1.Namespace {
	ret := &corev1.Namespace{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("net-%s", utilrand.GetRandomStringLowercase(6)),
		},
		Spec: &corev1.Namespace_Spec{},
	}

	return ret
}

func GenService(ns string) *corev1.Service {

	if ns == "" {
		ns = "default"
	}

	ret := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: fmt.Sprintf("svc-%s.%s", utilrand.GetRandomStringLowercase(6), ns),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_TCP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},
			},
		},
	}

	return ret
}
