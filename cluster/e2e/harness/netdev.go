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
	"fmt"
	"net/netip"
	"strconv"
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

func (h *H) LocalSessionAddrs(t *testing.T) []netip.Addr {
	t.Helper()

	addrs := h.SessionAddrs(t)
	if len(addrs) == 0 {
		return nil
	}

	out, err := h.Output(t.Context(), "ip -o addr show")
	if err != nil {
		t.Fatalf("Could not list the host addresses: %+v: %s", err, out)
	}

	var ret []netip.Addr
	for _, addr := range addrs {
		if deviceHoldingAddr(string(out), addr) == "" {
			continue
		}
		if parsed, err := netip.ParseAddr(addr); err == nil {
			ret = append(ret, parsed)
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

func (h *H) DeviceHoldingAddr(t *testing.T, addr string) string {
	t.Helper()

	out, err := h.Output(t.Context(), "ip -o addr show")
	if err != nil {
		t.Fatalf("Could not list the host addresses: %+v: %s", err, out)
	}

	return deviceHoldingAddr(string(out), addr)
}

func (h *H) HasDevice(t *testing.T, dev string) bool {
	t.Helper()

	_, err := h.Output(t.Context(), fmt.Sprintf("ip link show dev %s", dev))
	return err == nil
}

func (h *H) DeviceMTU(t *testing.T, dev string) int {
	t.Helper()

	out, err := h.Output(t.Context(), fmt.Sprintf("ip -o link show dev %s", dev))
	if err != nil {
		t.Fatalf("Could not show the device %s: %+v: %s", dev, err, out)
	}

	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f != "mtu" || i+1 >= len(fields) {
			continue
		}
		mtu, err := strconv.Atoi(fields[i+1])
		if err != nil {
			continue
		}
		return mtu
	}

	t.Fatalf("Could not find the MTU of the device %s: %s", dev, out)
	return 0
}

func (h *H) DeviceAddrs(t *testing.T, dev string) []netip.Addr {
	t.Helper()

	out, err := h.Output(t.Context(), fmt.Sprintf("ip -o addr show dev %s", dev))
	if err != nil {
		t.Fatalf("Could not list the addresses of %s: %+v: %s", dev, err, out)
	}

	var ret []netip.Addr
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pfx, err := netip.ParsePrefix(fields[3])
		if err != nil {
			continue
		}
		ret = append(ret, pfx.Addr())
	}

	return ret
}

func (h *H) DeviceRoutes(t *testing.T, dev string) []netip.Prefix {
	t.Helper()

	var ret []netip.Prefix

	for _, cmd := range []string{
		fmt.Sprintf("ip -o route show table all dev %s", dev),
		fmt.Sprintf("ip -o -6 route show table all dev %s", dev),
	} {
		out, err := h.Output(t.Context(), cmd)
		if err != nil {
			t.Fatalf("Could not list the routes of %s: %+v: %s", dev, err, out)
		}

		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if pfx, err := netip.ParsePrefix(fields[0]); err == nil {
				ret = append(ret, pfx)
				continue
			}
			if addr, err := netip.ParseAddr(fields[0]); err == nil {
				ret = append(ret, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}
	}

	return ret
}
