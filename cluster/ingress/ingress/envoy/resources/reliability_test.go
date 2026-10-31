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
	"os"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	upstream_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/octelium/octelium/apis/main/corev1"
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

func TestIngressReliabilityKnownIssues(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
		t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to run unresolved regressions listed in tmp/client-reliability-report.md")
	}
	t.Run("RL-09-api-server-upstream-has-no-http2-keepalive", func(t *testing.T) {
		clstr := getTestReliabilityAPIServerCluster(t)
		var opts upstream_http_v3.HttpProtocolOptions
		require.Nil(t, clstr.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"].UnmarshalTo(&opts))
		keepalive := opts.GetExplicitHttpConfig().GetHttp2ProtocolOptions().GetConnectionKeepalive()
		if assert.NotNil(t, keepalive,
			"a crashed or partitioned API Server pod leaves every Connect stream through this ingress hanging") {
			assert.Positive(t, keepalive.GetInterval().AsDuration())
			assert.Positive(t, keepalive.GetTimeout().AsDuration())
		}
	})
}
