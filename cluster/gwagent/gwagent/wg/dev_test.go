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

package wg

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	osuser "os/user"

	"github.com/coreos/go-iptables/iptables"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	gwtests "github.com/octelium/octelium/cluster/gwagent/internal/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTstFWCC() *corev1.ClusterConfig {
	return &corev1.ClusterConfig{
		Status: &corev1.ClusterConfig_Status{
			Network: &corev1.ClusterConfig_Status_Network{
				WgConnSubnet: &metav1.DualStackNetwork{
					V4: "100.65.0.0/16",
					V6: "fdee::1:0:0:0/80",
				},
			},
		},
	}
}

func newTstFWGW(v4, v6 string) *corev1.Gateway {
	return &corev1.Gateway{
		Status: &corev1.Gateway_Status{
			Cidr: &metav1.DualStackNetwork{
				V4: v4,
				V6: v6,
			},
		},
	}
}

func isTstRoot(t *testing.T) bool {
	t.Helper()

	usr, err := osuser.Current()
	require.Nil(t, err)
	if usr.Uid != "0" {
		zap.L().Warn("Skipping this test since the running user is not root")
		return false
	}

	return true
}

func listTstFW(t *testing.T, ipt *iptables.IPTables) [][]string {
	t.Helper()

	var ret [][]string
	for _, chain := range []string{fwChain, inputChain} {
		rules, err := ipt.List(tableFilter, chain)
		require.Nil(t, err)
		ret = append(ret, rules)
	}

	return ret
}

func wipeTstFW(t *testing.T, ipt *iptables.IPTables) {
	t.Helper()

	require.Nil(t, ipt.Delete(tableFilter, "FORWARD", "-j", fwChain))
	require.Nil(t, ipt.Delete(tableFilter, "INPUT", "-j", inputChain))
	require.Nil(t, ipt.ClearAndDeleteChain(tableFilter, fwChain))
	require.Nil(t, ipt.ClearAndDeleteChain(tableFilter, inputChain))
}

func TestEnsureFirewall(t *testing.T) {
	if !isTstRoot(t) {
		return
	}

	gwtests.LockGateway(t)

	gw := newTstFWGW("100.64.1.0/24", "fdee::100:0/112")
	cc := newTstFWCC()

	ipt, err := newIPTables()
	require.Nil(t, err)

	cleanup := func() {
		ipt.OnDelete(true, true)
	}
	cleanup()
	t.Cleanup(cleanup)

	sentinel := []string{"-j", "RETURN"}

	hasSentinel := func(family *iptables.IPTables) bool {
		exists, err := family.Exists(tableFilter, fwChain, sentinel...)
		require.Nil(t, err)
		return exists
	}

	t.Run("NoChange", func(t *testing.T) {
		require.Nil(t, ipt.OnAdd(gw, cc, true, true))
		t.Cleanup(cleanup)

		for _, family := range []*iptables.IPTables{ipt.iptv4, ipt.iptv6} {
			require.Nil(t, family.Append(tableFilter, fwChain, sentinel...))
		}

		require.Nil(t, ipt.Ensure(gw, cc))

		assert.True(t, hasSentinel(ipt.iptv4))
		assert.True(t, hasSentinel(ipt.iptv6))
	})

	for _, tc := range []struct {
		name string
		set  func(t *testing.T, family *iptables.IPTables)
	}{
		{
			name: "Wiped",
			set:  wipeTstFW,
		},
		{
			name: "NoForwardJump",
			set: func(t *testing.T, family *iptables.IPTables) {
				require.Nil(t, family.Delete(tableFilter, "FORWARD", "-j", fwChain))
			},
		},
		{
			name: "NoInputJump",
			set: func(t *testing.T, family *iptables.IPTables) {
				require.Nil(t, family.Delete(tableFilter, "INPUT", "-j", inputChain))
			},
		},
		{
			name: "PartialChain",
			set: func(t *testing.T, family *iptables.IPTables) {
				require.Nil(t, family.Delete(tableFilter, "FORWARD", "-j", fwChain))
				rules, err := family.List(tableFilter, fwChain)
				require.Nil(t, err)
				require.Nil(t, family.DeleteById(tableFilter, fwChain, len(rules)-1))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, isV6 := range []bool{false, true} {
				require.Nil(t, ipt.OnAdd(gw, cc, true, true))

				broken, healthy := ipt.iptv4, ipt.iptv6
				if isV6 {
					broken, healthy = ipt.iptv6, ipt.iptv4
				}

				want := listTstFW(t, broken)

				require.Nil(t, healthy.Append(tableFilter, fwChain, sentinel...))

				tc.set(t, broken)

				require.Nil(t, ipt.Ensure(gw, cc))

				assert.Equal(t, want, listTstFW(t, broken))
				assert.True(t, hasSentinel(healthy), "the healthy family must not be rebuilt")

				for _, jump := range [][]string{{"FORWARD", fwChain}, {"INPUT", inputChain}} {
					rules, err := broken.List(tableFilter, jump[0])
					require.Nil(t, err)
					assert.Contains(t, rules, "-A "+jump[0]+" -j "+jump[1])
				}

				cleanup()
			}
		})
	}

	t.Run("SingleStack", func(t *testing.T) {
		gw := newTstFWGW("100.64.1.0/24", "")

		require.Nil(t, ipt.OnAdd(gw, cc, true, false))
		t.Cleanup(cleanup)

		wipeTstFW(t, ipt.iptv4)

		require.Nil(t, ipt.Ensure(gw, cc))

		for _, chain := range []string{fwChain, inputChain} {
			exists, err := ipt.iptv4.ChainExists(tableFilter, chain)
			require.Nil(t, err)
			assert.True(t, exists)

			exists, err = ipt.iptv6.ChainExists(tableFilter, chain)
			require.Nil(t, err)
			assert.False(t, exists)
		}
	})
}

func TestRunFirewallLoop(t *testing.T) {
	if !isTstRoot(t) {
		return
	}

	gwtests.LockGateway(t)

	gw := newTstFWGW("100.64.1.0/24", "fdee::100:0/112")
	cc := newTstFWCC()

	ipt, err := newIPTables()
	require.Nil(t, err)

	cleanup := func() {
		ipt.OnDelete(true, true)
	}
	cleanup()
	t.Cleanup(cleanup)

	require.Nil(t, ipt.OnAdd(gw, cc, true, true))

	want := listTstFW(t, ipt.iptv4)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		(&Wg{gw: gw, cc: cc}).runFirewallLoop(ctx)
	}()

	wipeTstFW(t, ipt.iptv4)

	require.Eventually(t, func() bool {
		exists, err := ipt.iptv4.ChainExists(tableFilter, inputChain)
		if err != nil || !exists {
			return false
		}
		exists, err = ipt.iptv4.Exists(tableFilter, "INPUT", "-j", inputChain)
		return err == nil && exists
	}, 2*firewallCheckPeriod, 100*time.Millisecond)

	assert.Equal(t, want, listTstFW(t, ipt.iptv4))

	cancel()

	select {
	case <-doneCh:
	case <-time.After(firewallCheckPeriod):
		assert.Fail(t, "the firewall loop did not stop")
	}
}

func writeTstFakeIPTables(t *testing.T, dir, callsPath string) {
	t.Helper()

	script := `#!/bin/sh
echo "$@" >> "` + callsPath + `"
case "$*" in
*--version*) echo "iptables v1.8.13 (nf_tables)" ;;
*) exit 4 ;;
esac
`

	for _, name := range []string{"iptables", "ip6tables"} {
		require.Nil(t, os.WriteFile(filepath.Join(dir, name), []byte(script), 0700))
	}
}

func TestRunFirewallLoopRetriesIPTablesClient(t *testing.T) {
	dir := t.TempDir()
	callsPath := filepath.Join(dir, "calls")

	t.Setenv("PATH", dir)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		(&Wg{gw: newTstFWGW("100.64.1.0/24", ""), cc: newTstFWCC()}).runFirewallLoop(ctx)
	}()

	time.Sleep(firewallCheckPeriod + time.Second)

	select {
	case <-doneCh:
		require.Fail(t, "the firewall loop must survive a missing iptables binary")
	default:
	}

	writeTstFakeIPTables(t, dir, callsPath)

	require.Eventually(t, func() bool {
		calls, err := os.ReadFile(callsPath)
		return err == nil && strings.Contains(string(calls), " -S ")
	}, 2*firewallCheckPeriod, 100*time.Millisecond)

	cancel()
	<-doneCh
}

func TestEnsureFirewallCheckError(t *testing.T) {
	dir := t.TempDir()
	callsPath := filepath.Join(dir, "calls")

	writeTstFakeIPTables(t, dir, callsPath)

	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	ipt, err := newIPTables()
	require.Nil(t, err)

	require.NotNil(t, ipt.Ensure(newTstFWGW("100.64.1.0/24", "fdee::100:0/112"), newTstFWCC()))

	calls, err := os.ReadFile(callsPath)
	require.Nil(t, err)

	for _, call := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
		assert.False(t, strings.Contains(call, " -A ") || strings.Contains(call, " -I ") ||
			strings.Contains(call, " -D ") || strings.Contains(call, " -N ") ||
			strings.Contains(call, " -F ") || strings.Contains(call, " -X "),
			"a failed check must not change the rules: %s", call)
	}
}
