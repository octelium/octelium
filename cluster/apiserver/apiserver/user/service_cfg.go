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

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/sshutils"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh/knownhosts"
)

func (s *Server) SetServiceConfigs(ctx context.Context,
	req *userv1.SetServiceConfigsRequest) (*userv1.SetServiceConfigsResponse, error) {
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

	host, port := getServiceConfigHostPort(svc, i.Session, cc)

	ret := &userv1.SetServiceConfigsResponse{
		Host: host,
		Port: int32(port),
		L3Mode: func() userv1.SetServiceConfigsResponse_L3Mode {
			if i.Session.Status.Connection == nil {
				return userv1.SetServiceConfigsResponse_BOTH
			}
			switch i.Session.Status.Connection.L3Mode {
			case corev1.Session_Status_Connection_V4:
				return userv1.SetServiceConfigsResponse_V4
			case corev1.Session_Status_Connection_V6:
				return userv1.SetServiceConfigsResponse_V6
			case corev1.Session_Status_Connection_BOTH:
				return userv1.SetServiceConfigsResponse_BOTH
			default:
				return userv1.SetServiceConfigsResponse_BOTH
			}
		}(),
	}

	switch {
	case ucorev1.ToService(svc).IsKubernetes():
		kubeConfig := getKubeConfig(svc, host, port)
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

	case svc.Spec.Mode == corev1.Service_Spec_SSH:
		ca, err := sshutils.GetCAPublicKey(ctx, s.octeliumC)
		if err != nil {
			zap.L().Warn("Could not do GetCAPublicKey", zap.Error(err))
			return nil, serr.InternalWithErr(err)
		}

		ret.Configs = append(ret.Configs, &userv1.SetServiceConfigsResponse_Config{
			Type: &userv1.SetServiceConfigsResponse_Config_Ssh{
				Ssh: &userv1.SetServiceConfigsResponse_Config_SSH{
					KnownHosts: []string{
						fmt.Sprintf("@cert-authority %s", knownhosts.Line([]string{"*"}, ca)),
					},
					AuthorizedKeys: []string{
						getAuthorizedKeyCALine(ca),
					},
				},
			},
		})
	}

	return ret, nil
}

func getKubeConfig(svc *corev1.Service, host string, port int) *k8sutils.KubeConfig {
	url := url.URL{
		Scheme: func() string {
			if svc.Spec.IsTLS {
				return "https"
			}
			return "http"
		}(),
		Host: net.JoinHostPort(host, fmt.Sprintf("%d", port)),
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

func getServiceConfigHostPort(svc *corev1.Service, sess *corev1.Session, cc *corev1.ClusterConfig) (string, int) {
	publishedService := func() *corev1.Session_Status_Connection_PublishedService {
		for _, publishedSvc := range sess.Status.Connection.PublishedServices {
			if publishedSvc.ServiceRef.Uid == svc.Metadata.Uid {
				return publishedSvc
			}
		}
		return nil
	}()

	if publishedService != nil {
		return func() string {
			if publishedService.Address != "" {
				return publishedService.Address
			}
			return "localhost"
		}(), int(publishedService.Port)
	}

	if !sess.Status.Connection.IgnoreDNS {
		return vutils.GetServicePrivateFQDN(svc, cc.Status.Domain), ucorev1.ToService(svc).RealPort()
	}

	if ucorev1.ToSession(sess).HasV6() {
		return svc.Status.Addresses[0].DualStackIP.Ipv6, ucorev1.ToService(svc).RealPort()
	} else if ucorev1.ToSession(sess).HasV4() {
		return svc.Status.Addresses[0].DualStackIP.Ipv4, ucorev1.ToService(svc).RealPort()
	}

	return vutils.GetServicePrivateFQDN(svc, cc.Status.Domain), ucorev1.ToService(svc).RealPort()
}
