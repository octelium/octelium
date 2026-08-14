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

package spiffec

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func peerChain(t *testing.T, id spiffeid.ID) [][]*x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	uri, err := url.Parse(id.String())
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: id.String()},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		URIs:         []*url.URL{uri},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	crt, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return [][]*x509.Certificate{{crt}}
}

func TestAuthorizerFor(t *testing.T) {
	mine := spiffeid.RequireFromString(
		"spiffe://example.org/ns/octelium/sa/octelium-rscserver")

	t.Run("no configured trust domain adopts the one SPIRE issued in",
		func(t *testing.T) {
			authz, err := authorizerFor("", mine)
			require.NoError(t, err)

			peer := spiffeid.RequireFromString("spiffe://example.org/ns/octelium/sa/octovigil")
			assert.NoError(t, authz(peer, peerChain(t, peer)))

			other := spiffeid.RequireFromString("spiffe://elsewhere.org/ns/octelium/sa/octovigil")
			assert.Error(t, authz(other, peerChain(t, other)),
				"a peer from another trust domain is still rejected")
		})

	t.Run("a matching trust domain authorizes the Cluster's own components",
		func(t *testing.T) {
			authz, err := authorizerFor("example.org", mine)
			require.NoError(t, err)

			peer := spiffeid.RequireFromString("spiffe://example.org/ns/octelium/sa/octovigil")
			assert.NoError(t, authz(peer, peerChain(t, peer)))
		})

	t.Run("a trust domain SPIRE does not issue in is reported, not deadlocked on",
		func(t *testing.T) {
			_, err := authorizerFor("octelium.local", mine)
			require.Error(t, err)

			assert.Contains(t, err.Error(), "octelium.local")
			assert.Contains(t, err.Error(), "example.org")
		})

	t.Run("a malformed trust domain is reported", func(t *testing.T) {
		_, err := authorizerFor("://not a trust domain", mine)
		assert.Error(t, err)
	})
}

func TestIsEnabled(t *testing.T) {
	t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "")
	assert.False(t, IsEnabled())

	t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "false")
	assert.False(t, IsEnabled())

	t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "true")
	assert.True(t, IsEnabled())
}

func TestGetSPIFFEEndpointSocket(t *testing.T) {
	t.Run("an explicit endpoint is taken as is", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/agent.sock")
		assert.Equal(t, "unix:///tmp/agent.sock", GetSPIFFEEndpointSocket())
	})

	t.Run("a bare path is given a scheme", func(t *testing.T) {
		t.Setenv("SPIFFE_ENDPOINT_SOCKET", "/tmp/agent.sock")
		assert.Equal(t, "unix:///tmp/agent.sock", GetSPIFFEEndpointSocket())
	})
}

func requireNoAgentSocket(t *testing.T) {
	t.Helper()

	if addr := GetSPIFFEEndpointSocket(); addr != "" {
		t.Skipf("this machine has a SPIFFE Workload API socket at %s", addr)
	}
}

func TestWaitForEndpointSocketWithoutSPIFFE(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "")

	requireNoAgentSocket(t)

	start := time.Now()
	_, err := waitForEndpointSocket(context.Background())

	assert.ErrorIs(t, err, ErrNotFound)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestWaitForEndpointSocketRespectsContext(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "true")

	requireNoAgentSocket(t)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := waitForEndpointSocket(ctx)

	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound,
		"a Cluster with SPIFFE must not be told the socket is simply absent, "+
			"since that would let it fall back to plaintext gRPC")
	assert.Less(t, time.Since(start), socketWaitTimeout)
}
