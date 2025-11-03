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

package vigilutils

import (
	"context"
	"net"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/rscutils"
)

type GetServiceConfigRequest struct {
	ReqCtx *corev1.RequestContext
}

func GetServiceConfig(ctx context.Context, req *coctovigilv1.AuthenticateAndAuthorizeResponse) *corev1.Service_Spec_Config {

	if req == nil || req.RequestContext == nil || req.RequestContext.Service == nil {
		return nil
	}

	if req.Config != nil {
		return req.Config
	}

	svc := req.RequestContext.Service
	cfgName := req.ServiceConfigName

	if cfgName == "" || cfgName == "default" {
		return svc.Spec.Config
	}

	if len(svc.Spec.DynamicConfig.Configs) < 1 {
		return svc.Spec.Config
	}

	for _, namedCfg := range svc.Spec.DynamicConfig.Configs {
		if namedCfg.Name == cfgName {
			return rscutils.GetMergedServiceConfig(namedCfg, svc)
		}
	}

	return svc.Spec.Config
}

func GetDownstreamRequestSource(c net.Conn) *coctovigilv1.DownstreamRequest_Source {
	if c == nil {
		return &coctovigilv1.DownstreamRequest_Source{}
	}

	return &coctovigilv1.DownstreamRequest_Source{
		Address: func() string {
			switch addr := c.RemoteAddr().(type) {
			case *net.UDPAddr:
				return addr.IP.String()
			case *net.TCPAddr:
				return addr.IP.String()
			default:
				return ""
			}
		}(),
		Port: func() int32 {
			switch addr := c.RemoteAddr().(type) {
			case *net.UDPAddr:
				return int32(addr.Port)
			case *net.TCPAddr:
				return int32(addr.Port)
			default:
				return 0
			}
		}(),
	}
}
