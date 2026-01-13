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

package resources

import (
	"context"
	"fmt"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	corsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	envoy_type_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func getRouteConfigMain(ctx context.Context, r *GetListenersReq) (*routev3.RouteConfiguration, error) {

	routeConfig := &routev3.RouteConfiguration{}

	{
		vh, err := getVirtualHostAPI(ctx, r)
		if err != nil {
			return nil, err
		}
		if vh != nil {
			routeConfig.VirtualHosts = append(routeConfig.VirtualHosts, vh)
		}
	}

	svcList := r.ServiceList

	for _, svc := range svcList {
		if isAPIServer(svc) {
			continue
		}
		vh, err := getVirtualHostService(svc, r)
		if err != nil {
			return nil, err
		}
		routeConfig.VirtualHosts = append(routeConfig.VirtualHosts, vh)
	}

	return routeConfig, nil
}

func getVirtualHostAPI(ctx context.Context, r *GetListenersReq) (*routev3.VirtualHost, error) {

	domain := r.Domain
	svcList := r.ServiceList
	routes, err := getRoutesMain(domain, svcList)
	if err != nil {
		return nil, err
	}

	if len(routes) < 1 {
		return nil, nil
	}

	vh := &routev3.VirtualHost{
		Name: "vh.octelium-api",
		Domains: []string{
			fmt.Sprintf("octelium-api.%s", domain),
			fmt.Sprintf("octelium-api.%s:443", domain),
		},
		Routes: routes,
		RequireTls: func() routev3.VirtualHost_TlsRequirementType {
			if r.HasFrontProxy {
				return routev3.VirtualHost_NONE
			}

			return routev3.VirtualHost_ALL
		}(),
	}

	{
		filter := &corsv3.CorsPolicy{
			AllowOriginStringMatch: []*envoy_type_matcher.StringMatcher{
				{
					MatchPattern: &envoy_type_matcher.StringMatcher_Suffix{
						Suffix: domain,
					},
				},
			},
			AllowMethods:     "GET, PUT, DELETE, POST, OPTIONS",
			AllowHeaders:     "cookie,keep-alive,user-agent,cache-control,content-type,content-transfer-encoding,x-grpc-web,grpc-timeout",
			MaxAge:           "1728000",
			ExposeHeaders:    "set-cookie,grpc-status,grpc-message",
			AllowCredentials: wrapperspb.Bool(true),
		}
		pbFilter, err := anypb.New(filter)
		if err != nil {
			return nil, err
		}

		if vh.TypedPerFilterConfig == nil {
			vh.TypedPerFilterConfig = make(map[string]*anypb.Any)
		}

		vh.TypedPerFilterConfig[wellknown.CORS] = pbFilter
	}

	return vh, nil
}

func getRoutesMain(domain string, svcList []*corev1.Service) ([]*routev3.Route, error) {
	routes := []*routev3.Route{}

	var apiServerSvcs []*corev1.Service
	for _, svc := range svcList {
		if isAPIServer(svc) {
			apiServerSvcs = append(apiServerSvcs, svc)
		}
	}
	if len(apiServerSvcs) > 0 {
		/*
			slices.SortFunc(apiServerSvcs, func(a, b *corev1.Service) int {
				return len(b.Metadata.SystemLabels["apiserver-path"]) - len(a.Metadata.SystemLabels["apiserver-path"])
			})
		*/

		for _, svc := range apiServerSvcs {

			paths := strings.Split(svc.Metadata.SystemLabels["apiserver-path"], ",")
			for _, path := range paths {
				/*
					zap.L().Debug("Adding API Server path",
						zap.Any("service", svc.Metadata.Name),
						zap.String("path", strings.TrimSpace(path)))
				*/
				routeAPIServer, err := getRouteMain(domain,
					strings.TrimSpace(path), true, getClusterNameFromService(svc))
				if err != nil {
					return nil, err
				}
				routes = append(routes, routeAPIServer)
			}
		}
	}

	return routes, nil
}

func isAPIServer(svc *corev1.Service) bool {
	return svc.Metadata.SystemLabels != nil &&
		svc.Metadata.SystemLabels["octelium-apiserver"] == "true" &&
		svc.Metadata.SystemLabels["apiserver-path"] != ""
}

func getRouteMain(domain string, prefix string, isGRPC bool, cluster string) (*routev3.Route, error) {

	route := &routev3.Route{
		RequestHeadersToAdd: []*corev3.HeaderValueOption{
			{
				Header: &corev3.HeaderValue{
					Key:   vutils.GetDownstreamIPHeaderCanonical(),
					Value: "%REQ(x-envoy-external-address)%",
				},
				KeepEmptyValue: true,
				AppendAction:   corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			},
		},
		Match: &routev3.RouteMatch{
			PathSpecifier: &routev3.RouteMatch_Prefix{
				Prefix: prefix,
			},
		},

		Action: &routev3.Route_Route{

			Route: &routev3.RouteAction{
				Timeout: &durationpb.Duration{
					Seconds: 0,
					Nanos:   0,
				},

				IdleTimeout: &durationpb.Duration{
					Seconds: idleTimeoutSeconds,
					Nanos:   0,
				},

				HostRewriteSpecifier: &routev3.RouteAction_AutoHostRewrite{
					AutoHostRewrite: &wrapperspb.BoolValue{
						Value: true,
					},
				},

				ClusterSpecifier: &routev3.RouteAction_Cluster{
					Cluster: cluster,
				},
			},
		},
	}

	return route, nil
}

func getVirtualHostService(svc *corev1.Service, r *GetListenersReq) (*routev3.VirtualHost, error) {

	domain := r.Domain

	routes, err := getRoutesService(svc, domain)
	if err != nil {
		return nil, err
	}

	vh := &routev3.VirtualHost{
		Name:    fmt.Sprintf("vh-%s", k8sutils.GetSvcHostname(svc)),
		Domains: getSvcFQDNs(svc, domain),
		Routes:  routes,
		RequireTls: func() routev3.VirtualHost_TlsRequirementType {
			if r.HasFrontProxy {
				return routev3.VirtualHost_NONE
			}

			return routev3.VirtualHost_ALL
		}(),
	}

	return vh, nil
}

func getRoutesService(svc *corev1.Service, domain string) ([]*routev3.Route, error) {

	route := &routev3.Route{
		RequestHeadersToAdd: []*corev3.HeaderValueOption{
			{
				Header: &corev3.HeaderValue{
					Key:   vutils.GetDownstreamIPHeaderCanonical(),
					Value: "%REQ(x-envoy-external-address)%",
				},
				KeepEmptyValue: true,
				AppendAction:   corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			},
		},
		Match: &routev3.RouteMatch{
			PathSpecifier: &routev3.RouteMatch_Prefix{
				Prefix: "/",
			},
		},

		Action: &routev3.Route_Route{
			Route: &routev3.RouteAction{
				AppendXForwardedHost: ucorev1.ToService(svc).IsManagedService() &&
					svc.Status.ManagedService != nil && svc.Status.ManagedService.ForwardHost,
				UpgradeConfigs: []*routev3.RouteAction_UpgradeConfig{
					{
						UpgradeType: "websocket",
						Enabled: &wrapperspb.BoolValue{
							Value: true,
						},
					},
				},

				Timeout: &durationpb.Duration{
					Seconds: 0,
					Nanos:   0,
				},
				IdleTimeout: &durationpb.Duration{
					Seconds: idleTimeoutSeconds,
					Nanos:   0,
				},

				HostRewriteSpecifier: &routev3.RouteAction_HostRewriteLiteral{
					HostRewriteLiteral: getSvcFQDNs(svc, domain)[0],
				},

				ClusterSpecifier: &routev3.RouteAction_Cluster{
					Cluster: getClusterNameFromService(svc),
				},
			},
		},
	}

	return []*routev3.Route{route}, nil
}
