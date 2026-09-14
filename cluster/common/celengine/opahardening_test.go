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

package celengine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOPANetworkIsRestrictedToPublicAddresses(t *testing.T) {
	ctx := context.Background()

	e, err := newOPAEngine(ctx, nil)
	assert.Nil(t, err, "%+v", err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"exfiltrated": true}`))
	}))
	t.Cleanup(srv.Close)

	script := fmt.Sprintf(`
package octelium.condition

match if {
	http.send({"method": "GET", "url": "%s", "raise_error": true})
}`, srv.URL)

	_, err = e.EvalPolicy(ctx, script, map[string]any{})
	assert.ErrorContains(t, err, "blocked",
		"http.send must not reach a loopback upstream")
}

func TestOPANetworkBlocksUnixSockets(t *testing.T) {
	ctx := context.Background()

	e, err := newOPAEngine(ctx, nil)
	assert.Nil(t, err, "%+v", err)

	_, err = e.EvalPolicy(ctx, `
package octelium.condition

match if {
	http.send({
		"method": "GET",
		"url": "unix://localhost/v1?socket=/var/run/docker.sock",
		"raise_error": true,
	})
}`, map[string]any{})
	assert.NotNil(t, err, "http.send must not reach a UNIX socket")
}

func TestOPAEvalIsBounded(t *testing.T) {
	ctx := context.Background()

	e, err := newOPAEngine(ctx, &opaOpts{EvalTimeout: 250 * time.Millisecond})
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 250*time.Millisecond, e.evalTimeout)

	startedAt := time.Now()
	_, err = e.EvalPolicy(ctx, `
package octelium.condition

match if {
	some i in numbers.range(1, 40000)
	some j in numbers.range(1, 40000)
	i * j == -1
}`, map[string]any{})

	assert.NotNil(t, err, "a runaway Rego policy must be cut off")
	assert.Less(t, time.Since(startedAt), 8*time.Second)
}

func TestOPAEvalTimeoutDefaults(t *testing.T) {
	ctx := context.Background()

	for _, o := range []*opaOpts{nil, {}, {EvalTimeout: -1}} {
		e, err := newOPAEngine(ctx, o)
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, opaEvalTimeout, e.evalTimeout)
	}
}

func TestOPANetworkBuiltinsAreLimitedToHTTPSend(t *testing.T) {
	caps := getOPACapabilities()

	names := map[string]struct{}{}
	for _, b := range caps.Builtins {
		names[b.Name] = struct{}{}
	}

	_, ok := names["http.send"]
	assert.True(t, ok)

	for _, name := range []string{
		"net.lookup_ip_addr",
		"opa.runtime",
		"trace",
		"print",
		"rego.parse_module",
	} {
		_, ok := names[name]
		assert.False(t, ok, "%s must not be available to Rego policies", name)
	}
}
