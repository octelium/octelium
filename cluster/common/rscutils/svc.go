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

package rscutils

import (
	"slices"

	"github.com/octelium/octelium/apis/main/corev1"
	"google.golang.org/protobuf/proto"
)

func GetMergedServiceConfig(cfg *corev1.Service_Spec_Config, svc *corev1.Service) *corev1.Service_Spec_Config {
	if cfg.Parent == "" {
		return cfg
	}

	var parent *corev1.Service_Spec_Config

	if cfg.Parent == "default" {
		parent = svc.Spec.Config
		if parent == nil {
			parent = &corev1.Service_Spec_Config{}
		}
	} else {
		idx := slices.IndexFunc(svc.Spec.DynamicConfig.Configs, func(itm *corev1.Service_Spec_Config) bool {
			return itm.Name == cfg.Parent
		})
		if idx < 0 {
			return cfg
		}
		parent = svc.Spec.DynamicConfig.Configs[idx]
	}

	ret := proto.Clone(parent).(*corev1.Service_Spec_Config)
	proto.Merge(ret, cfg)

	return ret
}
