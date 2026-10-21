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
	"regexp"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	corsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAPIAllowedOriginMatchers(t *testing.T) {
	newService := func(name, namespace string, isSystem, hasSubdomain bool) *corev1.Service {
		return &corev1.Service{
			Metadata: &metav1.Metadata{Name: name, IsSystem: isSystem},
			Spec:     &corev1.Service_Spec{IsPublic: true},
			Status: &corev1.Service_Status{
				NamespaceRef: &metav1.ObjectReference{Name: namespace},
				ManagedService: &corev1.Service_Status_ManagedService{
					HasSubdomain: hasSubdomain,
				},
			},
		}
	}

	matchers := getAPIAllowedOriginMatchers("example.com", []*corev1.Service{
		newService("default.default", "default", true, false),
		newService("portal.default", "default", true, false),
		newService("default.cordium", "cordium", true, true),
		newService("untrusted.default", "default", false, true),
	})

	var got []string
	for _, matcher := range matchers {
		if exact := matcher.GetExact(); exact != "" {
			got = append(got, "exact:"+exact)
		} else if regex := matcher.GetSafeRegex(); regex != nil {
			got = append(got, "regex:"+regex.Regex)
			_, err := regexp.Compile(regex.Regex)
			assert.NoError(t, err)
		}
	}

	assert.Equal(t, []string{
		"exact:https://cordium.example.com",
		`regex:^https://([a-zA-Z0-9-]+\.)+cordium\.example\.com$`,
		"exact:https://default.cordium.example.com",
		`regex:^https://([a-zA-Z0-9-]+\.)+default\.cordium\.example\.com$`,
		"exact:https://default.default.example.com",
		"exact:https://default.example.com",
		"exact:https://example.com",
		"exact:https://portal.default.example.com",
		"exact:https://portal.example.com",
	}, got)
}

func TestIsAPIServerLabels(t *testing.T) {
	for _, tc := range []struct {
		labels map[string]string
		want   bool
	}{
		{nil, false},
		{map[string]string{}, false},
		{map[string]string{"octelium-apiserver": "true"}, false},
		{map[string]string{"apiserver-path": "/api"}, false},
		{map[string]string{"octelium-apiserver": "false", "apiserver-path": "/api"}, false},
		{map[string]string{"octelium-apiserver": "TRUE", "apiserver-path": "/api"}, false},
		{map[string]string{"octelium-apiserver": "true", "apiserver-path": "/api"}, true},
	} {
		svc := newIngressService("api", "octelium")
		svc.Metadata.SystemLabels = tc.labels
		assert.Equal(t, tc.want, isAPIServer(svc))
	}
}

func TestGetRouteConfigMain(t *testing.T) {
	for _, frontProxy := range []bool{false, true} {
		for _, api := range []bool{false, true} {
			t.Run(fmt.Sprintf("FrontProxy/%t/API/%t", frontProxy, api), func(t *testing.T) {
				svc := newIngressService("app", "team")
				services := []*corev1.Service{svc}
				if api {
					services = append(services, newAPIServerService("default.octelium-api", "/octelium.api.main.user"))
				}
				cfg, err := getRouteConfigMain(t.Context(), &GetListenersReq{
					Domain: "example.com", HasFrontProxy: frontProxy, ServiceList: services,
				})
				require.Nil(t, err)
				assert.Nil(t, cfg.ValidateAll())
				if api {
					require.Len(t, cfg.VirtualHosts, 2)
					assert.Equal(t, "vh.octelium-api", cfg.VirtualHosts[0].Name)
					assert.Equal(t, []string{"octelium-api.example.com", "octelium-api.example.com:443"}, cfg.VirtualHosts[0].Domains)
				} else {
					require.Len(t, cfg.VirtualHosts, 1)
				}
				vh := cfg.VirtualHosts[len(cfg.VirtualHosts)-1]
				assert.Equal(t, getSvcFQDNs(svc, "example.com"), vh.Domains)
				for _, vh := range cfg.VirtualHosts {
					if frontProxy {
						assert.Equal(t, routev3.VirtualHost_NONE, vh.RequireTls)
					} else {
						assert.Equal(t, routev3.VirtualHost_ALL, vh.RequireTls)
					}
					require.Len(t, vh.ResponseHeadersToAdd, 2)
					for _, header := range vh.ResponseHeadersToAdd {
						assert.Equal(t, corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD, header.AppendAction)
					}
					assert.Equal(t, "Strict-Transport-Security", vh.ResponseHeadersToAdd[0].Header.Key)
					assert.Equal(t, "max-age=2592000", vh.ResponseHeadersToAdd[0].Header.Value)
					assert.Equal(t, "Server", vh.ResponseHeadersToAdd[1].Header.Key)
					assert.Equal(t, "octelium", vh.ResponseHeadersToAdd[1].Header.Value)
				}
			})
		}
	}
	cfg, err := getRouteConfigMain(t.Context(), &GetListenersReq{Domain: "example.com"})
	require.Nil(t, err)
	assert.Empty(t, cfg.VirtualHosts)
}

func TestGetVirtualHostAPICORS(t *testing.T) {
	services := []*corev1.Service{newAPIServerService("default.octelium-api", "/octelium.api.main.user")}
	portal := newIngressService("portal", "default")
	portal.Metadata.IsSystem = true
	portal.Status.ManagedService = &corev1.Service_Status_ManagedService{}
	services = append(services, portal)
	services = append(services, newIngressService("untrusted", "default"))
	vh, err := getVirtualHostAPI(t.Context(), &GetListenersReq{Domain: "example.com", ServiceList: services})
	require.Nil(t, err)
	require.NotNil(t, vh)
	var policy corsv3.CorsPolicy
	require.Nil(t, vh.TypedPerFilterConfig["envoy.filters.http.cors"].UnmarshalTo(&policy))
	assert.Nil(t, policy.ValidateAll())
	assert.True(t, policy.AllowCredentials.GetValue())
	assert.Equal(t, "GET, PUT, DELETE, POST, OPTIONS", policy.AllowMethods)
	assert.Equal(t, "86400", policy.MaxAge)
	assert.Contains(t, policy.AllowHeaders, "x-grpc-web")
	assert.Contains(t, policy.AllowHeaders, "grpc-timeout")
	assert.Contains(t, policy.ExposeHeaders, "grpc-status")
	assert.Contains(t, policy.ExposeHeaders, "grpc-message")
	var origins []string
	for _, matcher := range policy.AllowOriginStringMatch {
		origins = append(origins, matcher.GetExact())
	}
	assert.Contains(t, origins, "https://portal.example.com")
	assert.NotContains(t, origins, "https://untrusted.example.com")
	assert.NotContains(t, origins, "http://portal.example.com")
}

func TestGetAPIAllowedOriginMatcherBoundaries(t *testing.T) {
	svc := newIngressService("default", "portal")
	svc.Metadata.IsSystem = true
	svc.Status.ManagedService = &corev1.Service_Status_ManagedService{HasSubdomain: true}
	matchers := getAPIAllowedOriginMatchers("example.com", []*corev1.Service{svc, svc})
	for _, tc := range []struct {
		origin string
		want   bool
	}{
		{"https://portal.example.com", true},
		{"https://default.portal.example.com", true},
		{"https://child.portal.example.com", true},
		{"https://a.b.portal.example.com", true},
		{"http://portal.example.com", false},
		{"https://portal.example.com.evil.test", false},
		{"https://evil-portal.example.com", false},
		{"https://portalXexample.com", false},
		{"https://portal.example.com:8443", false},
		{"https://portal.example.com@evil.test", false},
		{"https://portal.example.com/path", false},
		{"https://.portal.example.com", false},
		{"https://a..portal.example.com", false},
		{"https://a_b.portal.example.com", false},
		{"https://portal.example.com\n", false},
		{"null", false},
		{"", false},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			matched := false
			for _, matcher := range matchers {
				if exact := matcher.GetExact(); exact != "" && exact == tc.origin {
					matched = true
				}
				if regex := matcher.GetSafeRegex(); regex != nil {
					matched = matched || regexp.MustCompile(regex.Regex).MatchString(tc.origin)
				}
			}
			assert.Equal(t, tc.want, matched)
		})
	}
}

func TestGetRoutesServiceConfiguration(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, forwardHost := range []bool{false, true} {
			t.Run(fmt.Sprintf("Managed/%t/ForwardHost/%t", managed, forwardHost), func(t *testing.T) {
				svc := newIngressService("app", "team")
				if managed {
					svc.Status.ManagedService = &corev1.Service_Status_ManagedService{ForwardHost: forwardHost}
				}
				before := pbutils.Clone(svc)
				routes, err := getRoutesService(svc, "example.com")
				require.Nil(t, err)
				require.Len(t, routes, 1)
				route := routes[0]
				assert.Nil(t, route.ValidateAll())
				assert.Equal(t, "/", route.Match.GetPrefix())
				require.Len(t, route.RequestHeadersToAdd, 1)
				header := route.RequestHeadersToAdd[0]
				assert.Equal(t, vutils.GetDownstreamIPHeaderCanonical(), header.Header.Key)
				assert.Equal(t, "%REQ(x-envoy-external-address)%", header.Header.Value)
				assert.True(t, header.KeepEmptyValue)
				assert.Equal(t, corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD, header.AppendAction)
				action := route.GetRoute()
				assert.Equal(t, managed && forwardHost, action.AppendXForwardedHost)
				assert.Equal(t, "app.team.example.com", action.GetHostRewriteLiteral())
				assert.Equal(t, getClusterNameFromService(svc), action.GetCluster())
				require.NotNil(t, action.Timeout)
				assert.Zero(t, action.Timeout.Seconds)
				assert.Equal(t, int64(3600), action.IdleTimeout.Seconds)
				assert.Equal(t, int64(86400), action.MaxStreamDuration.MaxStreamDuration.Seconds)
				assert.Equal(t, int64(86400), action.MaxStreamDuration.GrpcTimeoutHeaderMax.Seconds)
				require.Len(t, action.UpgradeConfigs, 1)
				assert.Equal(t, "websocket", action.UpgradeConfigs[0].UpgradeType)
				assert.True(t, action.UpgradeConfigs[0].Enabled.GetValue())
				assert.True(t, pbutils.IsEqual(before, svc))
			})
		}
	}
}

func TestGetRouteAPIServerConfiguration(t *testing.T) {
	for _, connect := range []bool{false, true} {
		var route *routev3.Route
		var err error
		if connect {
			route, err = getRouteAPIServerConnect("api-cluster")
		} else {
			route, err = getRouteAPIServer("/api", "api-cluster")
		}
		require.Nil(t, err)
		assert.Nil(t, route.ValidateAll())
		assert.Equal(t, "api-cluster", route.GetRoute().GetCluster())
		assert.True(t, route.GetRoute().GetAutoHostRewrite().GetValue())
		assert.Equal(t, int64(86400), route.GetRoute().IdleTimeout.Seconds)
		require.NotNil(t, route.GetRoute().Timeout)
		assert.Zero(t, route.GetRoute().Timeout.Seconds)
		require.Len(t, route.RequestHeadersToAdd, 1)
		assert.Equal(t, vutils.GetDownstreamIPHeaderCanonical(), route.RequestHeadersToAdd[0].Header.Key)
		assert.Equal(t, corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD, route.RequestHeadersToAdd[0].AppendAction)
		if connect {
			assert.Equal(t, userConnectPath, route.Match.GetPath())
			assert.Equal(t, corev3.RoutingPriority_HIGH, route.GetRoute().Priority)
		} else {
			assert.Equal(t, "/api", route.Match.GetPrefix())
			assert.Equal(t, corev3.RoutingPriority_DEFAULT, route.GetRoute().Priority)
		}
	}
}

func newAPIServerService(name, paths string) *corev1.Service {
	return &corev1.Service{
		Metadata: &metav1.Metadata{
			Name:     name,
			IsSystem: true,
			SystemLabels: map[string]string{
				"octelium-apiserver": "true",
				"apiserver-path":     paths,
			},
		},
		Spec: &corev1.Service_Spec{
			Port:     8080,
			IsPublic: true,
			Mode:     corev1.Service_Spec_GRPC,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "octelium-api"},
		},
	}
}

func TestGetRoutesMainConnect(t *testing.T) {
	apiSvc := newAPIServerService("default.octelium-api", "/octelium.api.main.core, /octelium.api.main.user")
	authSvc := newAPIServerService("auth.octelium-api", "/octelium.api.main.auth")

	routes, err := getRoutesMain("example.com", []*corev1.Service{authSvc, apiSvc})
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 4, len(routes))

	for _, route := range routes {
		assert.Nil(t, route.ValidateAll())
	}

	assert.Equal(t, userConnectPath, routes[0].Match.GetPath())
	assert.Equal(t, corev3.RoutingPriority_HIGH, routes[0].GetRoute().Priority)
	assert.Equal(t, getClusterNameFromService(apiSvc), routes[0].GetRoute().GetCluster())
	assert.Equal(t, int64(0), routes[0].GetRoute().Timeout.Seconds)
	assert.Equal(t, 1, len(routes[0].RequestHeadersToAdd))

	assert.Equal(t, "/octelium.api.main.auth", routes[1].Match.GetPrefix())
	assert.Equal(t, getClusterNameFromService(authSvc), routes[1].GetRoute().GetCluster())
	assert.Equal(t, "/octelium.api.main.core", routes[2].Match.GetPrefix())
	assert.Equal(t, "/octelium.api.main.user", routes[3].Match.GetPrefix())

	for _, route := range routes[1:] {
		assert.Equal(t, corev3.RoutingPriority_DEFAULT, route.GetRoute().Priority)
	}

	getMatchingRoute := func(path string) *routev3.Route {
		for _, route := range routes {
			if route.Match.GetPath() == path ||
				(route.Match.GetPrefix() != "" && strings.HasPrefix(path, route.Match.GetPrefix())) {
				return route
			}
		}
		return nil
	}

	assert.Equal(t, routes[0], getMatchingRoute(userConnectPath))
	assert.Equal(t, routes[3], getMatchingRoute("/octelium.api.main.user.v1.MainService/Disconnect"))
	assert.Equal(t, routes[3], getMatchingRoute("/octelium.api.main.user.v1.MainService/ConnectX"))
	assert.Equal(t, routes[2], getMatchingRoute("/octelium.api.main.core.v1.MainService/ListSession"))
	assert.Equal(t, routes[1], getMatchingRoute("/octelium.api.main.auth.v1.MainService/AuthenticateWithAuthenticationToken"))

	{
		routes, err := getRoutesMain("example.com", []*corev1.Service{authSvc})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, len(routes))
		assert.Equal(t, "/octelium.api.main.auth", routes[0].Match.GetPrefix())
	}
}
