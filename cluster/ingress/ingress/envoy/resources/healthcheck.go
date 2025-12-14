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
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoyhcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	wellknown "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

func getListenerHealthCheck() (*listenerv3.Listener, error) {

	ret := &listenerv3.Listener{
		Name: "healthcheck-listener",
	}

	ret.Address = &core.Address{Address: &core.Address_SocketAddress{
		SocketAddress: &core.SocketAddress{
			Address:  "0.0.0.0",
			Protocol: core.SocketAddress_TCP,
			PortSpecifier: &core.SocketAddress_PortValue{
				PortValue: 11012,
			},
		},
	}}

	{

		httpConnMan, err := getHttpConnManagerFilterHealthCheck()
		if err != nil {
			return nil, err
		}
		ret.FilterChains = []*listenerv3.FilterChain{
			{
				TransportSocketConnectTimeout: &durationpb.Duration{
					Seconds: 3,
				},
				Filters: []*listenerv3.Filter{
					httpConnMan,
				},
			},
		}
	}

	return ret, nil
}

func getHttpConnManagerFilterHealthCheck() (*listenerv3.Filter, error) {

	routeConfig, err := getRouteConfigHealthCheck()
	if err != nil {
		return nil, err
	}

	filter := &envoyhcm.HttpConnectionManager{
		CodecType:             envoyhcm.HttpConnectionManager_AUTO,
		StatPrefix:            "hcm-health-check",
		ServerName:            "octelium",
		StripMatchingHostPort: true,
		RouteSpecifier: &envoyhcm.HttpConnectionManager_RouteConfig{
			RouteConfig: routeConfig,
		},

		StreamIdleTimeout: &durationpb.Duration{
			Seconds: 30,
			Nanos:   0,
		},
		RequestTimeout: &durationpb.Duration{
			Seconds: 5,
			Nanos:   0,
		},

		RequestHeadersTimeout: &durationpb.Duration{
			Seconds: 3,
			Nanos:   0,
		},
	}

	{
		routerFilter := &routerv3.Router{
			SuppressEnvoyHeaders: true,
		}
		pbFilter, err := anypb.New(routerFilter)
		if err != nil {
			return nil, err
		}

		filter.HttpFilters = []*envoyhcm.HttpFilter{
			{
				Name: "envoy.filters.http.router",
				ConfigType: &envoyhcm.HttpFilter_TypedConfig{

					TypedConfig: pbFilter,
				},
			},
		}
	}

	pbFilter, err := anypb.New(filter)
	if err != nil {
		return nil, err
	}

	return &listenerv3.Filter{
		Name: wellknown.HTTPConnectionManager,
		ConfigType: &listenerv3.Filter_TypedConfig{
			TypedConfig: pbFilter,
		},
	}, nil
}

func getRouteConfigHealthCheck() (*routev3.RouteConfiguration, error) {

	routeConfig := &routev3.RouteConfiguration{}

	routeConfig.VirtualHosts = []*routev3.VirtualHost{
		{
			Name:    "octelium-health-check",
			Domains: []string{"*"},
			Routes: []*routev3.Route{
				{
					Match: &routev3.RouteMatch{
						PathSpecifier: &routev3.RouteMatch_Path{
							Path: "/ready",
						},
					},

					Action: &routev3.Route_Route{
						Route: &routev3.RouteAction{

							HostRewriteSpecifier: &routev3.RouteAction_HostRewriteLiteral{
								HostRewriteLiteral: "127.0.0.1",
							},

							ClusterSpecifier: &routev3.RouteAction_Cluster{
								Cluster: healthCheckCluster,
							},
						},
					},
				},
			},
		},
	}

	return routeConfig, nil
}
