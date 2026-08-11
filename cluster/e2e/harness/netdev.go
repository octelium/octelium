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
	"net/netip"
	"strings"
	"testing"

	"github.com/pkg/errors"
)

func deviceHoldingAddr(ipAddrOutput, addr string) string {
	want, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(ipAddrOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		got, err := netip.ParsePrefix(fields[3])
		if err != nil {
			continue
		}

		if got.Addr() == want {
			return strings.TrimSuffix(fields[1], ":")
		}
	}

	return ""
}

func (h *H) SessionAddrs(t *testing.T) []string {
	t.Helper()

	sess := h.GetSession(t, h.Status(t).Session.Metadata.Name)
	if sess.Status == nil || sess.Status.Connection == nil {
		t.Fatalf("The Session %s reports no Connection", sess.Metadata.Name)
	}

	var ret []string
	for _, addr := range sess.Status.Connection.Addresses {
		for _, val := range []string{addr.V4, addr.V6} {
			if val == "" {
				continue
			}
			if pfx, err := netip.ParsePrefix(val); err == nil {
				ret = append(ret, pfx.Addr().String())
				continue
			}
			if parsed, err := netip.ParseAddr(val); err == nil {
				ret = append(ret, parsed.String())
			}
		}
	}

	return ret
}

func (h *H) TunDevice(t *testing.T) (string, error) {
	t.Helper()

	addrs := h.SessionAddrs(t)
	if len(addrs) == 0 {
		return "", errors.Errorf("The Session has no connection addresses")
	}

	out, err := h.Output(t.Context(), "ip -o addr show")
	if err != nil {
		return "", errors.Errorf("Could not list the host addresses: %+v: %s", err, out)
	}

	for _, addr := range addrs {
		if dev := deviceHoldingAddr(string(out), addr); dev != "" {
			return dev, nil
		}
	}

	return "", errors.Errorf(
		"No host interface holds any of the Session addresses %v", addrs)
}
