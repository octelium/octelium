//go:build e2e

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

package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/e2e/harness"
	"go.uber.org/zap"
)

var (
	h       *harness.H
	initErr error
)

func TestMain(m *testing.M) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}
	zap.ReplaceGlobals(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h, initErr = harness.New(ctx, nil)

	code := m.Run()

	if h != nil {
		h.Close()
	}
	os.Exit(code)
}

type step struct {
	name string
	fn   func(t *testing.T, h *harness.H)
}

func TestE2E(t *testing.T) {
	if initErr != nil {
		t.Fatalf("Could not initialize the e2e harness: %+v", initErr)
	}

	started := time.Now()

	steps := []step{
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

	for _, s := range steps {
		t.Run(s.name, func(t *testing.T) {
			h.Setup(t)
			s.fn(t, h)
		})
	}

	zap.L().Debug("Test done", zap.Duration("duration", time.Since(started)))
}
