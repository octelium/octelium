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

package user

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
)

// var rgxName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)

func (s *Server) SetServiceConfigs(ctx context.Context, req *userv1.SetServiceConfigsRequest) (*userv1.SetServiceConfigsResponse, error) {
	i, err := userctx.GetUserCtx(ctx)
	if err != nil {
		return nil, err
	}

	if i.Session.Status.Connection == nil {
		return nil, serr.InvalidArg("You must be connected first to set a Service config")
	}

	svcU, err := s.GetService(ctx, &metav1.GetOptions{
		Name: vutils.GetServiceFullNameFromName(req.Name),
	})
	if err != nil {
		return nil, err
	}

	svc, err := s.octeliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
		Name: svcU.Metadata.Name,
	})
	if err != nil {
		return nil, err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}

	ret := &userv1.SetServiceConfigsResponse{}

	if ucorev1.ToService(svc).IsKubernetes() {
		kubeConfig := getKubeConfig(svc, i.Session, cc)
		kubeConfigYAML, err := kubeConfig.MarshalToYAML()
		if err != nil {
			return nil, err
		}

		cfg := &userv1.SetServiceConfigsResponse_Config{
			Type: &userv1.SetServiceConfigsResponse_Config_Kubeconfig_{
				Kubeconfig: &userv1.SetServiceConfigsResponse_Config_Kubeconfig{
					Content: kubeConfigYAML,
				},
			},
		}

		ret.Configs = append(ret.Configs, cfg)
	}

	return ret, nil
}

func getKubeConfig(svc *corev1.Service, sess *corev1.Session, cc *corev1.ClusterConfig) *k8sutils.KubeConfig {

	publishedService := func() *corev1.Session_Status_Connection_PublishedService {
		for _, publishedSvc := range sess.Status.Connection.PublishedServices {
			if publishedSvc.ServiceRef.Uid == svc.Metadata.Uid {
				return publishedSvc
			}
		}
		return nil
	}()

	url := url.URL{
		Scheme: func() string {
			if svc.Spec.IsTLS {
				return "https"
			}
			return "http"
		}(),
		Host: func() string {
			var host string
			if publishedService != nil {
				return net.JoinHostPort(func() string {
					if publishedService.Address != "" {
						return publishedService.Address
					}
					return "localhost"
				}(), strconv.Itoa(int(publishedService.Port)))
			}

			if !sess.Status.Connection.IgnoreDNS {
				return fmt.Sprintf("%s:%d",
					vutils.GetServicePrivateFQDN(svc, cc.Status.Domain), ucorev1.ToService(svc).RealPort())
			}

			if ucorev1.ToSession(sess).HasV6() {
				host = svc.Status.Addresses[0].DualStackIP.Ipv6
			} else if ucorev1.ToSession(sess).HasV4() {
				host = svc.Status.Addresses[0].DualStackIP.Ipv4
			}

			return net.JoinHostPort(host, fmt.Sprintf("%d", ucorev1.ToService(svc).RealPort()))
		}(),
	}
	ret := &k8sutils.KubeConfig{
		APIVersion:  "v1",
		Kind:        "Config",
		Preferences: struct{}{},
		Clusters: []k8sutils.KubeConfigCluster{
			{
				Name: "kubernetes",
				Cluster: k8sutils.KubeConfigClusterConfig{
					Server: url.String(),
				},
			},
		},
		Users: []k8sutils.KubeConfigUser{
			{
				Name: "kubernetes-admin",
				User: k8sutils.KubeConfigUserConfig{
					Token: "dummy-token",
				},
			},
		},
		Contexts: []k8sutils.KubeConfigContext{
			{
				Name: "kubernetes-admin@kubernetes",
				Context: k8sutils.KubeConfigContextConfig{
					Cluster: "kubernetes",
					User:    "kubernetes-admin",
				},
			},
		},
		CurrentContext: "kubernetes-admin@kubernetes",
	}

	return ret
}
