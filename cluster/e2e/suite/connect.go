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
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/html"
)

func testConnect(t *testing.T, h *harness.H) {
	t.Run("UnknownServiceFails", func(t *testing.T) {
		h.MustFailWithin(t, fmt.Sprintf("octelium connect -p %s:%d",
			utilrand.GetRandomStringCanonical(8), h.Port()), 2*time.Minute)
	})

	t.Run("PublishedService", func(t *testing.T) {
		port := h.Port()
		conn := h.Connect(t, harness.ConnectOpts{
			Publish: map[string]int{"demo-nginx": port},
		})

		h.WaitGetStatus(t, h.HTTP(), conn.URL("demo-nginx"), http.StatusOK)
	})
}

func testConnectQUIC(t *testing.T, h *harness.H) {
	h.Require(t, capQUICv0)

	port := h.Port()
	conn := h.Connect(t, harness.ConnectOpts{
		TunnelMode: "quicv0",
		Publish:    map[string]int{"nginx": port},
	})

	h.MustWaitServiceUpstream(t, "nginx")

	res := h.WaitGetStatus(t, h.HTTP(), conn.URL("nginx"), http.StatusOK)

	_, err := html.Parse(strings.NewReader(string(res.Body())))
	assert.Nil(t, err)
}
