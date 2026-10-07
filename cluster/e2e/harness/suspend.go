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
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func (c *Conn) pids(ctx context.Context) []int {
	pid := c.cmd.Process.Pid
	ret := []int{pid}

	out, err := c.h.Output(ctx, fmt.Sprintf("pgrep -P %d", pid))
	if err != nil {
		return ret
	}

	for _, field := range strings.Fields(string(out)) {
		if child, err := strconv.Atoi(field); err == nil {
			ret = append(ret, child)
		}
	}

	return ret
}

func (c *Conn) signal(ctx context.Context, sig string) error {
	pid := c.cmd.Process.Pid
	return c.h.Run(ctx, fmt.Sprintf("kill -%s %d $(pgrep -P %d)", sig, pid, pid))
}

func (c *Conn) Suspend(ctx context.Context) error {
	return c.signal(ctx, "STOP")
}

func (c *Conn) Resume(ctx context.Context) error {
	return c.signal(ctx, "CONT")
}

func establishedLocalAddrs(ssOutput string, pids []int, remotePort uint16) []netip.AddrPort {
	var ret []netip.AddrPort

	for _, line := range strings.Split(ssOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		local, err := netip.ParseAddrPort(fields[2])
		if err != nil {
			continue
		}

		peer, err := netip.ParseAddrPort(fields[3])
		if err != nil || peer.Port() != remotePort {
			continue
		}

		process := strings.Join(fields[4:], " ")
		if !slices.ContainsFunc(pids, func(pid int) bool {
			return strings.Contains(process, fmt.Sprintf("pid=%d,", pid))
		}) {
			continue
		}

		ret = append(ret, netip.AddrPortFrom(local.Addr().Unmap(), local.Port()))
	}

	return ret
}

func (h *H) BlackholeConnections(t *testing.T, c *Conn, remotePort uint16) {
	t.Helper()

	out := h.MustOutput(t,
		fmt.Sprintf("sudo ss -Htnp state established '( dport = :%d )'", remotePort))

	addrs := establishedLocalAddrs(string(out), c.pids(t.Context()), remotePort)
	if len(addrs) == 0 {
		t.Fatalf("octelium connect has no established connection to the port %d:\n%s",
			remotePort, out)
	}

	for _, addr := range addrs {
		bin := "iptables"
		if !addr.Addr().Is4() {
			bin = "ip6tables"
		}

		rule := fmt.Sprintf("INPUT -p tcp -m conntrack --ctorigsrc %s --ctorigsrcport %d -j DROP",
			addr.Addr(), addr.Port())

		h.MustRun(t, fmt.Sprintf("sudo %s -I %s", bin, rule))
		zap.L().Debug("Blackholed the connection", zap.String("local", addr.String()))

		t.Cleanup(func() {
			if err := h.Run(context.Background(), fmt.Sprintf("sudo %s -D %s", bin, rule)); err != nil {
				zap.L().Warn("Could not remove the blackhole rule",
					zap.String("rule", rule), zap.Error(err))
			}
		})
	}
}
