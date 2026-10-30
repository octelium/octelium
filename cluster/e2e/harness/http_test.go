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

package harness

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPNoKeepAlive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		http2 bool
	}{
		{name: "HTTP1"},
		{name: "HTTP2", http2: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type routeKey struct{}
			var public atomic.Bool
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path == "/unavailable" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				if r.Context().Value(routeKey{}).(bool) {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
				return context.WithValue(ctx, routeKey{}, public.Load())
			}
			server.EnableHTTP2 = tc.http2
			server.StartTLS()
			defer server.Close()

			c := (&H{}).HTTPNoKeepAlive().SetTransport(server.Client().Transport)
			t.Cleanup(c.GetClient().CloseIdleConnections)
			res, err := c.R().Get(server.URL)
			require.Nil(t, err)
			assert.Equal(t, http.StatusNotFound, res.StatusCode())
			if tc.http2 {
				assert.Equal(t, 2, res.RawResponse.ProtoMajor)
			}

			public.Store(true)
			res, err = c.R().Get(server.URL)
			require.Nil(t, err)
			assert.Equal(t, http.StatusUnauthorized, res.StatusCode())

			public.Store(false)
			res, err = c.R().Get(server.URL)
			require.Nil(t, err)
			assert.Equal(t, http.StatusNotFound, res.StatusCode())

			res, err = c.R().Get(server.URL + "/unavailable")
			require.Nil(t, err)
			assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode())
			assert.Equal(t, int32(4), requests.Load())
		})
	}
}
