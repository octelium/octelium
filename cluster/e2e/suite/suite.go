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

package suite

import (
	"slices"
	"testing"

	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/pkg/errors"
)

type Phase struct {
	Name string
	Run  func(t *testing.T, h *harness.H)
}

func Phases() []Phase {
	return []Phase{
		{"ClusterReady", testClusterReady},
		{"CLIVersions", testCLIVersions},
		{"IngressPublic", testIngressPublic},
		{"AdminAPI", testAdminAPI},
		{"OcteliumctlCommands", testOcteliumctlCommands},
		{"SDK", testSDK},
		{"Authorization", testAuthorization},
		{"AuthenticationAssertion", testAuthenticationAssertion},
		{"AuthenticationSession", testAuthenticationSession},
		{"GeoIP", testGeoIP},
		{"AnonymousAuthorization", testAnonymousAuthorization},
		{"ServiceHostHeader", testServiceHostHeader},
		{"VigilPlugins", testVigilPlugins},
		{"VigilDynamicConfig", testVigilDynamicConfig},
		{"VigilServiceState", testVigilServiceState},
		{"RscServerMetadata", testRscServerMetadata},
		{"RscServerLifecycle", testRscServerLifecycle},
		{"RscServerList", testRscServerList},
		{"Nocturne", testNocturne},
		{"Ingress", testIngress},
		{"IngressCertificateRotation", testIngressCertificateRotation},
		{"GatewayResource", testGatewayResource},
		{"GatewayConnection", testGatewayConnection},
		{"OcteliumCommands", testOcteliumCommands},
		{"Connect", testConnect},
		{"Apply", testApply},
		{"ConnectQUIC", testConnectQUIC},
		{"GatewayL3", testGatewayL3},
		{"CredentialAccessToken", testCredentialAccessToken},
		{"CredentialOAuth2", testCredentialOAuth2},
		{"CredentialAuthToken", testCredentialAuthToken},
		{"ComponentHealth", testComponentHealth},
		{"RscServerResilience", testRscServerResilience},
	}
}

func indexOf(phases []Phase, name string) int {
	return slices.IndexFunc(phases, func(p Phase) bool { return p.Name == name })
}

func InsertAfter(phases []Phase, name string, extra ...Phase) []Phase {
	idx := indexOf(phases, name)
	if idx < 0 {
		return append(slices.Clone(phases), extra...)
	}

	ret := slices.Clone(phases[:idx+1])
	ret = append(ret, extra...)
	return append(ret, phases[idx+1:]...)
}

func InsertBefore(phases []Phase, name string, extra ...Phase) []Phase {
	idx := indexOf(phases, name)
	if idx < 0 {
		return append(slices.Clone(phases), extra...)
	}

	ret := slices.Clone(phases[:idx])
	ret = append(ret, extra...)
	return append(ret, phases[idx:]...)
}

func Without(phases []Phase, names ...string) []Phase {
	return slices.DeleteFunc(slices.Clone(phases), func(p Phase) bool {
		return slices.Contains(names, p.Name)
	})
}

func Only(phases []Phase, names ...string) []Phase {
	ret := make([]Phase, 0, len(names))
	for _, name := range names {
		idx := indexOf(phases, name)
		if idx >= 0 {
			ret = append(ret, phases[idx])
		}
	}
	return ret
}

func Validate(phases []Phase) error {
	seen := map[string]bool{}
	for _, p := range phases {
		if p.Name == "" {
			return errors.Errorf("A phase has no name")
		}
		if p.Run == nil {
			return errors.Errorf("The phase %q has no Run function", p.Name)
		}
		if seen[p.Name] {
			return errors.Errorf("The phase %q is declared more than once", p.Name)
		}
		seen[p.Name] = true
	}
	return nil
}
