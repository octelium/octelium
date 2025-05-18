// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build serveenvoy

package envoy

/*
import (
	"fmt"

	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tcpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	udpproxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/udp/udp_proxy/v3"
	types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	wellknown "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/octelium/octelium/apis/main/userv1"
	"google.golang.org/protobuf/types/known/anypb"
)

type listener struct {
	svc       *userv1.HostedService
	address   string
	id        string
	clusterID string
}

func (s *Server) getListeners() ([]types.Resource, error) {
	ret := []types.Resource{}
	for _, l := range s.services {

		if l.Upstream == nil {
			continue
		}

		if l.Address != nil {
			if l.Address.Ipv4 != "" && s.ipv4Supported {
				listener := listener{
					svc:       l,
					address:   l.Address.Ipv4,
					id:        fmt.Sprintf("%s-%s-ipv4", l.Namespace, l.Name),
					clusterID: fmt.Sprintf("%s-%s", l.Namespace, l.Name),
				}

				rscListener, err := listener.getListener()
				if err != nil {
					return nil, err
				}
				ret = append(ret, rscListener)
			}

			if l.Address.Ipv6 != "" && s.ipv6Supported {
				listener := listener{
					svc:       l,
					address:   l.Address.Ipv6,
					id:        fmt.Sprintf("%s-%s-ipv6", l.Namespace, l.Name),
					clusterID: fmt.Sprintf("%s-%s", l.Namespace, l.Name),
				}
				rscListener, err := listener.getListener()
				if err != nil {
					return nil, err
				}
				ret = append(ret, rscListener)
			}
		}

	}

	return ret, nil
}

func (l *listener) getListener() (*listenerv3.Listener, error) {

	ret := &listenerv3.Listener{
		Name: l.id,
	}

	if l.svc.L4Type == userv1.HostedService_UDP {
		ret.Address = getAddress(l.address, uint32(l.svc.Port), ProtocolUDP)
		ret.ReusePort = true

		filter := &udpproxyv3.UdpProxyConfig{
			StatPrefix: "stat_udp_proxy-" + ret.Name,

			RouteSpecifier: &udpproxyv3.UdpProxyConfig_Cluster{
				Cluster: l.clusterID,
			},
		}

		pbFilter, err := anypb.New(filter)
		if err != nil {
			return nil, err
		}
		ret.ListenerFilters = append(ret.ListenerFilters, &listenerv3.ListenerFilter{
			Name: "envoy.filters.udp_listener.udp_proxy",
			ConfigType: &listenerv3.ListenerFilter_TypedConfig{
				TypedConfig: pbFilter,
			},
		})
	} else {
		ret.Address = getAddress(l.address, uint32(l.svc.Port), ProtocolTCP)
		filterChain, err := l.getFilterChains()

		if err != nil {
			return nil, err
		}

		ret.FilterChains = append(ret.FilterChains, filterChain)

	}

	return ret, nil
}

func (l *listener) getFilterChains() (*listenerv3.FilterChain, error) {

	ret := &listenerv3.FilterChain{}

	if l.svc.L4Type == userv1.HostedService_UDP {
		udpProxyFilter, err := l.getUDPProxyFitler()
		if err != nil {
			return nil, err
		}

		ret.Filters = append(ret.Filters, udpProxyFilter)

	} else {

		tcpProxyFilter, err := l.getTCPProxyFitler()
		if err != nil {
			return nil, err
		}

		ret.Filters = append(ret.Filters, tcpProxyFilter)

	}

	return ret, nil

}

func (l *listener) getUDPProxyFitler() (*listenerv3.Filter, error) {
	filter := &udpproxyv3.UdpProxyConfig{
		StatPrefix: "stat_udp_proxy" + l.id,

		RouteSpecifier: &udpproxyv3.UdpProxyConfig_Cluster{
			Cluster: l.id + "-cluster",
		},
	}

	pbFilter, err := anypb.New(filter)
	if err != nil {
		return nil, err
	}

	return &listenerv3.Filter{
		Name: "envoy.filters.udp_listener.udp_proxy",
		ConfigType: &listenerv3.Filter_TypedConfig{
			TypedConfig: pbFilter,
		},
	}, nil
}

func (l *listener) getTCPProxyFitler() (*listenerv3.Filter, error) {
	filter := &tcpproxyv3.TcpProxy{
		StatPrefix: "stat_tcp_proxy" + l.id,
		ClusterSpecifier: &tcpproxyv3.TcpProxy_Cluster{
			Cluster: l.clusterID,
		},
	}

	pbFilter, err := anypb.New(filter)
	if err != nil {
		return nil, err
	}

	return &listenerv3.Filter{
		Name: wellknown.TCPProxy,
		ConfigType: &listenerv3.Filter_TypedConfig{
			TypedConfig: pbFilter,
		},
	}, nil
}
*/
