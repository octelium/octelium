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
	"regexp"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
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
