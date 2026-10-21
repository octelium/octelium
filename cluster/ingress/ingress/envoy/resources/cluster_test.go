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
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	dnsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dns/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	upstream_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetClusters(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usr := tests.GenUser(nil)

	doCreateSvc := func() *corev1.Service {
		svc := tests.GenService("default")
		svc.Spec.IsPublic = true
		svc.Spec.Mode = corev1.Service_Spec_HTTP
		svc, err = adminSrv.CreateService(ctx, svc)
		assert.Nil(t, err, "%+v", err)
		ret, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		return ret
	}

	usr, err = adminSrv.CreateUser(ctx, usr)
	assert.Nil(t, err)

	var svcList []*corev1.Service

	apiSrvSvc, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
		Name: "api.octelium",
	})
	assert.Nil(t, err)

	svcList = append(svcList, apiSrvSvc)

	_, err = GetClusters("example.com", nil)
	assert.Nil(t, err)
	//os.Setenv("OCTELIUM_REHION_NAME", "default")
	_, err = GetClusters("example.com", svcList)
	assert.Nil(t, err)

	for i := 0; i < 100; i++ {
		svcList = append(svcList, doCreateSvc())
	}

	_, err = GetClusters("example.com", svcList)
	assert.Nil(t, err)
	_, err = GetClusters("example.com", svcList)
	assert.Nil(t, err)
}

func TestGetSvcFQDNs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		namespace string
		want      []string
	}{
		{"app", "team", []string{"app.team.example.com"}},
		{"default", "team", []string{"default.team.example.com", "team.example.com"}},
		{"app", "default", []string{"app.default.example.com", "app.example.com"}},
		{"default", "default", []string{"default.default.example.com", "default.example.com", "example.com"}},
	} {
		for _, managed := range []bool{false, true} {
			for _, subdomain := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s.%s/%t/%t", tc.name, tc.namespace, managed, subdomain), func(t *testing.T) {
					svc := newIngressService(tc.name, tc.namespace)
					if managed {
						svc.Status.ManagedService = &corev1.Service_Status_ManagedService{HasSubdomain: subdomain}
					}
					before := pbutils.Clone(svc)
					want := append([]string{}, tc.want...)
					if managed && subdomain {
						for _, host := range tc.want {
							want = append(want, "*."+host)
						}
					}
					assert.Equal(t, want, getSvcFQDNs(svc, "example.com"))
					assert.True(t, pbutils.IsEqual(before, svc))
				})
			}
		}
	}
}

func newIngressService(name, namespace string) *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{Name: fmt.Sprintf("%s.%s", name, namespace)},
		Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, Port: 8080, IsPublic: true},
		Status:   &corev1.Service_Status{Port: 8080, NamespaceRef: &metav1.ObjectReference{Name: namespace}},
	}
}

func TestGetClusterProtocols(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		for _, tls := range []bool{false, true} {
			t.Run(fmt.Sprintf("HTTP2/%t/TLS/%t", http2, tls), func(t *testing.T) {
				clstr, err := getCluster("service", http2, "service.octelium.svc", 8443, tls, "app.example.com")
				require.Nil(t, err)
				assert.Nil(t, clstr.ValidateAll())
				assert.Equal(t, int64(15), clstr.ConnectTimeout.Seconds)
				assert.Equal(t, clusterv3.Cluster_ROUND_ROBIN, clstr.LbPolicy)
				assert.Equal(t, "service", clstr.LoadAssignment.ClusterName)
				require.Len(t, clstr.LoadAssignment.Endpoints, 1)
				require.Len(t, clstr.LoadAssignment.Endpoints[0].LbEndpoints, 1)
				address := clstr.LoadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().Address.GetSocketAddress()
				assert.Equal(t, "service.octelium.svc", address.Address)
				assert.Equal(t, uint32(8443), address.GetPortValue())
				assert.Equal(t, core.SocketAddress_TCP, address.Protocol)
				if http2 {
					var opts upstream_http_v3.HttpProtocolOptions
					require.Nil(t, clstr.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].UnmarshalTo(&opts))
					assert.Nil(t, opts.ValidateAll())
					assert.NotNil(t, opts.GetExplicitHttpConfig().GetHttp2ProtocolOptions())
					assert.Nil(t, opts.GetExplicitHttpConfig().GetHttpProtocolOptions())
				} else {
					assert.Empty(t, clstr.TypedExtensionProtocolOptions)
				}
				if tls {
					require.NotNil(t, clstr.TransportSocket)
					assert.Equal(t, "envoy.transport_sockets.tls", clstr.TransportSocket.Name)
					var tlsCtx tlsv3.UpstreamTlsContext
					require.Nil(t, clstr.TransportSocket.GetTypedConfig().UnmarshalTo(&tlsCtx))
					assert.Nil(t, tlsCtx.ValidateAll())
					assert.Equal(t, "app.example.com", tlsCtx.Sni)
					assert.Equal(t, []string{"h2", "http/1.1"}, tlsCtx.CommonTlsContext.AlpnProtocols)
				} else {
					assert.Nil(t, clstr.TransportSocket)
				}
			})
		}
	}
}

func TestGetClusterDNS(t *testing.T) {
	for _, dev := range []bool{false, true} {
		t.Run(fmt.Sprint(dev), func(t *testing.T) {
			t.Setenv("OCTELIUM_DEV", fmt.Sprint(dev))
			t.Setenv("OCTELIUM_PRODUCTION", "true")
			clstr, err := getCluster("service", false, "service.octelium.svc", 8080, false, "")
			require.Nil(t, err)
			require.NotNil(t, clstr.GetClusterType())
			assert.Equal(t, "envoy.clusters.dns", clstr.GetClusterType().Name)
			var cfg dnsv3.DnsCluster
			require.Nil(t, clstr.GetClusterType().TypedConfig.UnmarshalTo(&cfg))
			assert.Nil(t, cfg.ValidateAll())
			assert.False(t, cfg.AllAddressesInSingleEndpoint)
			assert.Zero(t, cfg.DnsLookupFamily)
			assert.Nil(t, clstr.DnsRefreshRate)
			assert.Nil(t, clstr.CleanupInterval)
			if dev {
				assert.Equal(t, int64(10), cfg.DnsRefreshRate.Seconds)
			} else {
				assert.Nil(t, cfg.DnsRefreshRate)
			}
		})
	}
}

func TestGetClustersServiceProtocols(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  corev1.Service_Spec_Mode
		cfg   string
		http2 bool
	}{
		{"HTTP1", corev1.Service_Spec_HTTP, `{}`, false},
		{"HTTP2", corev1.Service_Spec_HTTP, `{"http":{"listenHTTP2":true}}`, true},
		{"GRPC", corev1.Service_Spec_GRPC, `{}`, true},
		{"MCP", corev1.Service_Spec_MCP, `{"mcp":{"listenHTTP2":true}}`, true},
		{"LLM", corev1.Service_Spec_LLM, `{"llm":{"listenHTTP2":true}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := newIngressService("app", "team")
			svc.Spec.Mode = tc.mode
			svc.Spec.IsTLS = true
			svc.Spec.Config = &corev1.Service_Spec_Config{}
			require.Nil(t, pbutils.UnmarshalJSON([]byte(tc.cfg), svc.Spec.Config))
			before := pbutils.Clone(svc)
			rscs, err := GetClusters("example.com", []*corev1.Service{svc})
			require.Nil(t, err)
			require.Len(t, rscs, 2)
			clstr := rscs[0].(*clusterv3.Cluster)
			assert.Equal(t, getClusterNameFromService(svc), clstr.Name)
			assert.Equal(t, tc.http2, len(clstr.TypedExtensionProtocolOptions) > 0)
			var tlsCtx tlsv3.UpstreamTlsContext
			require.Nil(t, clstr.TransportSocket.GetTypedConfig().UnmarshalTo(&tlsCtx))
			assert.Equal(t, "app.team.example.com", tlsCtx.Sni)
			assert.True(t, pbutils.IsEqual(before, svc))
			health := rscs[1].(*clusterv3.Cluster)
			assert.Equal(t, healthCheckCluster, health.Name)
			assert.Nil(t, health.TransportSocket)
			assert.Empty(t, health.TypedExtensionProtocolOptions)
			address := health.LoadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().Address.GetSocketAddress()
			assert.Equal(t, "127.0.0.1", address.Address)
			assert.Equal(t, uint32(11011), address.GetPortValue())
		})
	}
}

func TestGetClustersEmptyAndInvalidDomain(t *testing.T) {
	for _, list := range [][]*corev1.Service{nil, {}} {
		rscs, err := GetClusters("example.com", list)
		require.Nil(t, err)
		require.Len(t, rscs, 1)
		assert.Equal(t, healthCheckCluster, rscs[0].(*clusterv3.Cluster).Name)
	}
	svc := newIngressService("app", "default")
	svc.Spec.IsTLS = true
	rscs, err := GetClusters("\xff.example.com", []*corev1.Service{svc})
	assert.NotNil(t, err)
	assert.Nil(t, rscs)
}

func TestGetClustersCircuitBreakers(t *testing.T) {
	apiSvc := newAPIServerService("default.octelium-api", "/octelium.api.main.core, /octelium.api.main.user")
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "svc1.default",
		},
		Spec: &corev1.Service_Spec{
			Port:     8080,
			IsPublic: true,
			Mode:     corev1.Service_Spec_HTTP,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "default"},
		},
	}

	resources, err := GetClusters("example.com", []*corev1.Service{apiSvc, svc})
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 3, len(resources))

	clusters := make(map[string]*clusterv3.Cluster)
	for _, rsc := range resources {
		clstr := rsc.(*clusterv3.Cluster)
		assert.Nil(t, clstr.ValidateAll())
		clusters[clstr.Name] = clstr
	}

	assertThresholds := func(thresholds *clusterv3.CircuitBreakers_Thresholds,
		priority core.RoutingPriority, maxRequests uint32) {
		assert.Equal(t, priority, thresholds.Priority)
		assert.Equal(t, maxRequests, thresholds.MaxRequests.GetValue())
		assert.Equal(t, maxRequests, thresholds.MaxPendingRequests.GetValue())
		assert.Equal(t, maxRequests, thresholds.MaxConnections.GetValue())
		assert.Equal(t, uint32(3), thresholds.MaxRetries.GetValue())
	}

	{
		clstr := clusters[getClusterNameFromService(apiSvc)]
		assert.NotNil(t, clstr)
		assert.Equal(t, 2, len(clstr.CircuitBreakers.Thresholds))
		assertThresholds(clstr.CircuitBreakers.Thresholds[0], core.RoutingPriority_DEFAULT, maxRequestsDefault)
		assertThresholds(clstr.CircuitBreakers.Thresholds[1], core.RoutingPriority_HIGH, maxRequestsAPIServerConnect)
	}

	{
		clstr := clusters[getClusterNameFromService(svc)]
		assert.NotNil(t, clstr)
		assert.Equal(t, 1, len(clstr.CircuitBreakers.Thresholds))
		assertThresholds(clstr.CircuitBreakers.Thresholds[0], core.RoutingPriority_DEFAULT, maxRequestsDefault)
	}

	{
		clstr := clusters[healthCheckCluster]
		assert.NotNil(t, clstr)
		assert.Equal(t, 1, len(clstr.CircuitBreakers.Thresholds))
		assertThresholds(clstr.CircuitBreakers.Thresholds[0], core.RoutingPriority_DEFAULT, maxRequestsDefault)
	}
}
