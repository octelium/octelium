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
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	upstream_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testClientConnectKeepAliveInterval = 5 * time.Minute

func TestAPIServerConnectRouteOutlivesClientKeepAlives(t *testing.T) {
	apiSvc := newAPIServerService("default.octelium-api", "/octelium.api.main.core, /octelium.api.main.user")
	routes, err := getRoutesMain("example.com", []*corev1.Service{apiSvc})
	require.Nil(t, err, "%+v", err)
	var found bool
	for _, route := range routes {
		if route.GetMatch().GetPath() != userConnectPath {
			continue
		}
		found = true
		action := route.GetRoute()
		require.NotNil(t, action)
		assert.Equal(t, int64(0), action.GetTimeout().GetSeconds(), "the Connect stream must not have a total duration limit")
		assert.Equal(t, int32(0), action.GetTimeout().GetNanos())
		assert.Greater(t, action.GetIdleTimeout().AsDuration(), 2*testClientConnectKeepAliveInterval,
			"the Connect stream idle timeout must outlive the client keepalive interval")
		assert.Equal(t, core.RoutingPriority_HIGH, action.Priority)
		assert.Equal(t, getClusterNameFromService(apiSvc), action.GetCluster())
	}
	assert.True(t, found, "the Connect route was not found")
}

func getTestReliabilityAPIServerCluster(t *testing.T) *clusterv3.Cluster {
	t.Helper()
	apiSvc := newAPIServerService("default.octelium-api", "/octelium.api.main.core, /octelium.api.main.user")
	resources, err := GetClusters("example.com", []*corev1.Service{apiSvc})
	require.Nil(t, err, "%+v", err)
	for _, rsc := range resources {
		if clstr := rsc.(*clusterv3.Cluster); clstr.Name == getClusterNameFromService(apiSvc) {
			return clstr
		}
	}
	require.FailNow(t, "the API Server cluster was not found")
	return nil
}

func TestAPIServerClusterUsesHTTP2(t *testing.T) {
	clstr := getTestReliabilityAPIServerCluster(t)
	require.Nil(t, clstr.ValidateAll())
	var opts upstream_http_v3.HttpProtocolOptions
	require.Nil(t, clstr.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].UnmarshalTo(&opts))
	assert.NotNil(t, opts.GetExplicitHttpConfig().GetHttp2ProtocolOptions(),
		"the long-lived Connect gRPC streams need an HTTP/2 upstream")
}

func getTestHTTP2ProtocolOptions(t *testing.T, clstr *clusterv3.Cluster) *core.Http2ProtocolOptions {
	t.Helper()
	var opts upstream_http_v3.HttpProtocolOptions
	require.Nil(t, clstr.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].UnmarshalTo(&opts))
	require.Nil(t, opts.ValidateAll())
	require.NotNil(t, opts.GetExplicitHttpConfig().GetHttp2ProtocolOptions())
	return opts.GetExplicitHttpConfig().GetHttp2ProtocolOptions()
}

func TestAPIServerClusterHasHTTP2Keepalive(t *testing.T) {
	clstr := getTestReliabilityAPIServerCluster(t)
	require.Nil(t, clstr.ValidateAll())
	keepalive := getTestHTTP2ProtocolOptions(t, clstr).GetConnectionKeepalive()
	require.NotNil(t, keepalive,
		"a crashed or partitioned API Server pod leaves every Connect stream through this ingress hanging")
	assert.Equal(t, 30*time.Second, keepalive.GetInterval().AsDuration())
	assert.Equal(t, 20*time.Second, keepalive.GetTimeout().AsDuration())
	assert.Nil(t, keepalive.GetIntervalJitter())
	assert.Nil(t, keepalive.GetConnectionIdleInterval())
	assert.Less(t, keepalive.GetInterval().AsDuration()*115/100+keepalive.GetTimeout().AsDuration(), time.Minute,
		"a dead API Server upstream connection must be detected well before the client keepalive is sent")
}

func TestHTTP2KeepaliveOnlyForAPIServerClusters(t *testing.T) {
	apiSvc := newAPIServerService("default.octelium-api", "/octelium.api.main.core, /octelium.api.main.user")
	authSvc := newAPIServerService("auth.octelium-api", "/octelium.api.main.auth")
	httpAPISvc := newAPIServerService("http.octelium-api", "/octelium.api.main.http")
	httpAPISvc.Spec.Mode = corev1.Service_Spec_HTTP

	newSvc := func(name string, mode corev1.Service_Spec_Mode, cfg string) *corev1.Service {
		svc := newIngressService(name, "default")
		svc.Spec.Mode = mode
		svc.Spec.Config = &corev1.Service_Spec_Config{}
		require.Nil(t, pbutils.UnmarshalJSON([]byte(cfg), svc.Spec.Config))
		return svc
	}

	grpcSvc := newSvc("grpc", corev1.Service_Spec_GRPC, `{}`)
	http2Svc := newSvc("http2", corev1.Service_Spec_HTTP, `{"http":{"listenHTTP2":true}}`)
	mcpSvc := newSvc("mcp", corev1.Service_Spec_MCP, `{"mcp":{"listenHTTP2":true}}`)
	llmSvc := newSvc("llm", corev1.Service_Spec_LLM, `{"llm":{"listenHTTP2":true}}`)
	httpSvc := newSvc("http", corev1.Service_Spec_HTTP, `{}`)
	webSvc := newSvc("web", corev1.Service_Spec_WEB, `{}`)

	svcList := []*corev1.Service{grpcSvc, apiSvc, http2Svc, authSvc, mcpSvc, httpAPISvc, llmSvc, httpSvc, webSvc}
	before := make([]*corev1.Service, 0, len(svcList))
	for _, svc := range svcList {
		before = append(before, pbutils.Clone(svc).(*corev1.Service))
	}

	resources, err := GetClusters("example.com", svcList)
	require.Nil(t, err, "%+v", err)
	require.Len(t, resources, len(svcList)+1)

	for i, svc := range svcList {
		assert.True(t, pbutils.IsEqual(before[i], svc))
	}

	clusters := make(map[string]*clusterv3.Cluster)
	for _, rsc := range resources {
		clstr := rsc.(*clusterv3.Cluster)
		require.Nil(t, clstr.ValidateAll())
		clusters[clstr.Name] = clstr
	}

	for _, svc := range []*corev1.Service{apiSvc, authSvc} {
		t.Run(svc.Metadata.Name, func(t *testing.T) {
			clstr := clusters[getClusterNameFromService(svc)]
			require.NotNil(t, clstr)
			assert.True(t, pbutils.IsEqual(getAPIServerConnectionKeepalive(),
				getTestHTTP2ProtocolOptions(t, clstr).GetConnectionKeepalive()))
		})
	}

	for _, svc := range []*corev1.Service{grpcSvc, http2Svc, mcpSvc, llmSvc} {
		t.Run(svc.Metadata.Name, func(t *testing.T) {
			clstr := clusters[getClusterNameFromService(svc)]
			require.NotNil(t, clstr)
			assert.Nil(t, getTestHTTP2ProtocolOptions(t, clstr).GetConnectionKeepalive())
		})
	}

	for _, svc := range []*corev1.Service{httpAPISvc, httpSvc, webSvc} {
		t.Run(svc.Metadata.Name, func(t *testing.T) {
			clstr := clusters[getClusterNameFromService(svc)]
			require.NotNil(t, clstr)
			assert.Empty(t, clstr.TypedExtensionProtocolOptions)
		})
	}

	health := clusters[healthCheckCluster]
	require.NotNil(t, health)
	assert.Empty(t, health.TypedExtensionProtocolOptions)
}
