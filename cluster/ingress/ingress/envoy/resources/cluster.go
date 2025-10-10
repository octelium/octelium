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
	"fmt"
	"slices"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"go.uber.org/zap"

	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	upstream_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

const healthCheckCluster = "octelium-health-check"

func getSvcFQDNs(svc *corev1.Service, domain string) []string {
	name := ucorev1.ToService(svc).Name()
	ns := ucorev1.ToService(svc).Namespace()
	ret := []string{
		fmt.Sprintf("%s.%s.%s", name, ns, domain),
	}

	appendIfNotExists := func(arg string) {
		if !slices.Contains(ret, arg) {
			ret = append(ret, arg)
		}
	}
	if name == "default" {
		appendIfNotExists(fmt.Sprintf("%s.%s", ns, domain))
	}

	if ns == "default" {
		appendIfNotExists(fmt.Sprintf("%s.%s", name, domain))
		if name == "default" {
			appendIfNotExists(domain)
		}
	}

	if ucorev1.ToService(svc).IsManagedService() &&
		svc.Status.ManagedService != nil && svc.Status.ManagedService.HasSubdomain {
		domains := slices.Clone(ret)

		for _, dmn := range domains {
			appendIfNotExists(fmt.Sprintf("*.%s", dmn))
		}
	}

	return ret
}

func GetClusters(domain string, svcList []*corev1.Service) ([]types.Resource, error) {
	ret := []types.Resource{}

	for _, svc := range svcList {
		isTLS := svc.Spec.IsTLS
		port := ucorev1.ToService(svc).RealPort()

		isHTTP2 := ucorev1.ToService(svc).IsListenerHTTP2()
		clstr, err := getCluster(getClusterNameFromService(svc),
			isHTTP2, k8sutils.GetSvcFQDN(svc), int(port), isTLS, getSvcFQDNs(svc, domain)[0])
		if err != nil {
			return nil, err
		}
		zap.L().Debug("Adding Envoy cluster for Service", zap.String("name", svc.Metadata.Name))
		ret = append(ret, clstr)
	}

	{
		healthCheckCluster, err := getCluster(healthCheckCluster, false, "127.0.0.1", 11011, false, "")
		if err != nil {
			return nil, err
		}

		ret = append(ret, healthCheckCluster)
	}

	return ret, nil
}

func getCluster(name string, isHTTP2 bool, host string, port int, isTLS bool, sni string) (*clusterv3.Cluster, error) {
	loadAssignments, err := getClusterLoadAssignment(name, host, port)
	if err != nil {
		return nil, err
	}

	cluster := &clusterv3.Cluster{
		Name:           name,
		ConnectTimeout: &durationpb.Duration{Seconds: 15},
		LbPolicy:       clusterv3.Cluster_ROUND_ROBIN,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{
			Type: clusterv3.Cluster_STRICT_DNS,
		},
		DnsRefreshRate: func() *durationpb.Duration {
			if ldflags.IsDev() {
				return &durationpb.Duration{
					Seconds: 10,
				}
			}
			return nil
		}(),
		CleanupInterval: func() *durationpb.Duration {
			if ldflags.IsDev() {
				return &durationpb.Duration{
					Seconds: 10,
				}
			}
			return nil
		}(),

		LoadAssignment: loadAssignments,
	}

	if isHTTP2 {
		httpOpts := &upstream_http_v3.HttpProtocolOptions{
			UpstreamProtocolOptions: &upstream_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
				ExplicitHttpConfig: &upstream_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
					ProtocolConfig: &upstream_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{
						Http2ProtocolOptions: &core.Http2ProtocolOptions{},
					},
				},
			},
		}

		toPB, err := anypb.New(httpOpts)
		if err != nil {
			return nil, err
		}

		cluster.TypedExtensionProtocolOptions = map[string]*anypb.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": toPB,
		}

	}

	if isTLS {
		tlsSocket, err := getTransportSocket(sni)
		if err != nil {
			return nil, err
		}
		cluster.TransportSocket = tlsSocket
	}

	return cluster, nil
}

func getClusterLoadAssignment(cluster, host string, port int) (*endpoint.ClusterLoadAssignment, error) {
	endpoints, err := getEndpoints(host, port)
	if err != nil {
		return nil, err
	}
	ret := &endpoint.ClusterLoadAssignment{
		ClusterName: cluster,
		Endpoints:   []*endpoint.LocalityLbEndpoints{endpoints},
	}

	return ret, nil
}

func getEndpoints(host string, port int) (*endpoint.LocalityLbEndpoints, error) {
	return getEndpointsBackend(host, port)
}

func getEndpointsBackend(host string, port int) (*endpoint.LocalityLbEndpoints, error) {
	ret := &endpoint.LocalityLbEndpoints{
		LbEndpoints: []*endpoint.LbEndpoint{},
	}

	ret.LbEndpoints = append(ret.LbEndpoints, &endpoint.LbEndpoint{
		HostIdentifier: &endpoint.LbEndpoint_Endpoint{
			Endpoint: &endpoint.Endpoint{
				Address: &core.Address{Address: &core.Address_SocketAddress{
					SocketAddress: &core.SocketAddress{
						Address:  host,
						Protocol: core.SocketAddress_TCP,
						PortSpecifier: &core.SocketAddress_PortValue{
							PortValue: uint32(port),
						},
					},
				}},
			},
		},
	})

	return ret, nil
}

func getTransportSocket(hostname string) (*core.TransportSocket, error) {

	upstreamTLSCtx := &tlsv3.UpstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},
		Sni: hostname,
	}

	tUpstreamCtx, err := anypb.New(upstreamTLSCtx)
	if err != nil {
		return nil, err
	}
	transportSocket := &core.TransportSocket{
		Name: "envoy.transport_sockets.tls",
		ConfigType: &core.TransportSocket_TypedConfig{
			TypedConfig: tUpstreamCtx,
		}}

	return transportSocket, nil

}

func getClusterNameFromService(svc *corev1.Service) string {
	return fmt.Sprintf("svc-%s", k8sutils.GetSvcHostname(svc))
}
