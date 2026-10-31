// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func newTestReliabilityGateway(t *testing.T, idx int) *userv1.Gateway {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	return &userv1.Gateway{
		Id:        utilrand.GetRandomStringLowercase(6),
		Addresses: []string{fmt.Sprintf("192.0.2.%d", idx)},
		CIDRs:     []string{fmt.Sprintf("100.64.%d.0/24", idx)},
		Wireguard: &userv1.Gateway_WireGuard{
			Port:      51820,
			PublicKey: k.PublicKey().String(),
		},
	}
}

func newTestReliabilityNetstackController(t *testing.T, localDNSAddr string, gws ...*userv1.Gateway) (*Controller, error) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("This test needs the Linux WireGuard netstack configuration")
	}
	connCfg := genConnectionConfig(t, "example.com")
	connCfg.Connection.Dns.Servers = nil
	connCfg.Connection.Gateways = gws
	connCfg.Preferences.IgnoreDNS = true
	connCfg.Preferences.UserHome = t.TempDir()
	if localDNSAddr != "" {
		connCfg.Preferences.LocalDNS = &cliconfigv1.Connection_Preferences_LocalDNS{
			IsEnabled:     true,
			ListenAddress: localDNSAddr,
		}
	}
	c, err := NewController(connCfg)
	require.NoError(t, err)
	t.Cleanup(func() { c.Close() })
	return c, c.Start(t.Context())
}

func getTestReliabilityPeerKeys(t *testing.T, c *Controller) []string {
	t.Helper()
	uapi, err := c.dev.IpcGet()
	require.NoError(t, err)
	var ret []string
	for _, peer := range fromUAPI(uapi).Peers {
		ret = append(ret, peer.PublicKey.String())
	}
	return ret
}

func getTestReliabilityUDPAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := lis.LocalAddr().String()
	require.NoError(t, lis.Close())
	return addr
}

func testReliabilityLocalDNSReady(addr string) bool {
	cl := &dns.Client{Net: "udp", Timeout: 200 * time.Millisecond}
	msg := new(dns.Msg)
	msg.SetQuestion("missing.local.example.com.", dns.TypeA)
	response, _, err := cl.Exchange(msg, addr)
	return err == nil && response.Rcode == dns.RcodeServerFailure
}

func TestControllerRestartCyclesReleaseLocalListeners(t *testing.T) {
	addr := getTestReliabilityUDPAddr(t)
	for cycle := range 3 {
		c, err := newTestReliabilityNetstackController(t, addr, newTestReliabilityGateway(t, 1))
		require.NoError(t, err, "cycle %d", cycle)
		require.Eventually(t, func() bool {
			return testReliabilityLocalDNSReady(addr)
		}, 5*time.Second, 20*time.Millisecond, "cycle %d", cycle)
		assert.True(t, c.c.Preferences.LocalDNS.IsEnabled)
		assert.Len(t, getTestReliabilityPeerKeys(t, c), 1)
		require.NoError(t, c.Close())
		assert.ErrorContains(t, c.Start(t.Context()), "already closed")
		lis, err := net.ListenPacket("udp", addr)
		require.NoError(t, err, "a closed controller must release its local DNS port in cycle %d", cycle)
		require.NoError(t, lis.Close())
	}
}

func TestControllerGatewayEventsAfterCloseAreRejected(t *testing.T) {
	gw := newTestReliabilityGateway(t, 1)
	c, err := newTestReliabilityNetstackController(t, "", gw)
	require.NoError(t, err)
	require.NoError(t, c.Close())
	assert.ErrorContains(t, c.AddGateway(t.Context(), newTestReliabilityGateway(t, 2)), "already closed")
	assert.ErrorContains(t, c.UpdateGateway(t.Context(), gw), "already closed")
	assert.ErrorContains(t, c.DeleteGateway(t.Context(), gw.Id), "already closed")
	assert.ErrorContains(t, c.UpdateDNS(&userv1.DNS{Servers: []string{"100.64.0.53"}}), "already closed")
	assert.ErrorContains(t, c.SetConnectionState(c.c.Connection), "already closed")
	assert.NoError(t, c.Close())
}

func TestControllerIncompleteGatewayEventsKeepNetstackDevice(t *testing.T) {
	c, err := newTestReliabilityNetstackController(t, "")
	require.NoError(t, err)
	gw := newTestReliabilityGateway(t, 1)
	incomplete := &userv1.Gateway{Id: gw.Id, CIDRs: gw.CIDRs, Wireguard: gw.Wireguard}
	require.NoError(t, c.AddGateway(t.Context(), incomplete), "a Gateway without public addresses yet must not break the Connection")
	assert.Empty(t, getTestReliabilityPeerKeys(t, c))
	require.NoError(t, c.UpdateGateway(t.Context(), gw))
	assert.Equal(t, []string{gw.Wireguard.PublicKey}, getTestReliabilityPeerKeys(t, c))
	require.NoError(t, c.DeleteGateway(t.Context(), "unknown-gateway"))
	assert.Equal(t, []string{gw.Wireguard.PublicKey}, getTestReliabilityPeerKeys(t, c))
	require.NoError(t, c.DeleteGateway(t.Context(), gw.Id))
	assert.Empty(t, getTestReliabilityPeerKeys(t, c))
}

func TestControllerConcurrentGatewayEventsAndClose(t *testing.T) {
	c, err := newTestReliabilityNetstackController(t, "")
	require.NoError(t, err)
	var gws []*userv1.Gateway
	for i := range 50 {
		gws = append(gws, newTestReliabilityGateway(t, i+1))
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, gw := range gws {
			if err := c.AddGateway(context.Background(), gw); err != nil {
				return
			}
			if err := c.DeleteGateway(context.Background(), gw.Id); err != nil {
				return
			}
		}
	}()
	time.Sleep(5 * time.Millisecond)
	assert.NoError(t, c.Close())
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Gateway events did not stop after the controller was closed")
	}
}

func setTestReliabilityLockDir(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "octelium-lock-")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("TMPDIR", dir)
	if dirs := getLockDirs(); len(dirs) > 1 {
		if err := os.MkdirAll(dirs[0], 0755); err == nil {
			if f, err := os.CreateTemp(dirs[0], "probe-"); err == nil {
				f.Close()
				os.Remove(f.Name())
				t.Skip("the shared lock directory is writable by this user and is not isolated")
			}
		}
	}
}

func newTestReliabilitySSHController(t *testing.T) (*Controller, string) {
	t.Helper()
	c := newTestPlatformController(t, userv1.ConnectionState_V4)
	sshDir := filepath.Join(c.c.Preferences.UserHome, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0700))
	return c, sshDir
}

func TestControllerSSHServiceConfigsAcrossReconnects(t *testing.T) {
	setTestReliabilityLockDir(t)
	cfg := &userv1.ConnectionState_ServiceConfig_SSH{
		KnownHosts:     []string{"@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
		AuthorizedKeys: []string{"cert-authority ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
	}
	c, sshDir := newTestReliabilitySSHController(t)
	knownHosts := filepath.Join(sshDir, "known_hosts")
	require.NoError(t, os.WriteFile(knownHosts, []byte("example.org ssh-ed25519 AAAA\n"), 0600))
	for range 3 {
		require.NoError(t, c.setServiceConfigSSH(cfg))
		require.NoError(t, c.setServiceConfigSSH(cfg))
		b, err := os.ReadFile(knownHosts)
		require.NoError(t, err)
		assert.Equal(t, 1, strings.Count(string(b), "@cert-authority"), "repeated connections must not duplicate the Cluster CA")
		require.NoError(t, c.unsetServiceConfigSSH())
		b, err = os.ReadFile(knownHosts)
		require.NoError(t, err)
		assert.Equal(t, "example.org ssh-ed25519 AAAA\n", string(b))
	}
}

func TestControllerReliabilityKnownIssues(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
		t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to run unresolved regressions listed in tmp/client-reliability-report.md")
	}
	t.Run("RL-02-ssh-config-cleanup-lock-contention", func(t *testing.T) {
		setTestReliabilityLockDir(t)
		c, _ := newTestReliabilitySSHController(t)
		lock, err := acquireFileLock(sshConfigLockName)
		require.NoError(t, err)
		require.NotNil(t, lock)
		defer releaseFileLock(lock)
		assert.NoError(t, c.unsetServiceConfigSSH(),
			"another connection holding the SSH config lock for a moment makes the controller cleanup fail")
	})
	t.Run("RL-02-ssh-config-setup-lock-contention", func(t *testing.T) {
		setTestReliabilityLockDir(t)
		c, sshDir := newTestReliabilitySSHController(t)
		lock, err := acquireFileLock(sshConfigLockName)
		require.NoError(t, err)
		require.NotNil(t, lock)
		go func() {
			time.Sleep(100 * time.Millisecond)
			releaseFileLock(lock)
		}()
		require.NoError(t, c.setServiceConfigSSH(&userv1.ConnectionState_ServiceConfig_SSH{
			KnownHosts: []string{"@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
		}))
		b, err := os.ReadFile(filepath.Join(sshDir, "known_hosts"))
		assert.NoError(t, err)
		assert.Contains(t, string(b), "@cert-authority",
			"the Cluster CA is silently skipped for the whole Connection when the lock is briefly held")
	})
	t.Run("RL-12-duplicate-add-gateway-survives-delete", func(t *testing.T) {
		gw := newTestReliabilityGateway(t, 1)
		c, err := newTestReliabilityNetstackController(t, "", gw)
		require.NoError(t, err)
		require.NoError(t, c.AddGateway(t.Context(), gw))
		require.NoError(t, c.DeleteGateway(t.Context(), gw.Id))
		assert.Empty(t, getTestReliabilityPeerKeys(t, c), "a deleted Gateway remains a WireGuard peer")
		for _, cur := range c.c.Connection.Gateways {
			assert.NotEqual(t, gw.Id, cur.Id, "a deleted Gateway remains in the Connection state")
		}
	})
	t.Run("RL-11-update-unknown-gateway", func(t *testing.T) {
		c, err := newTestReliabilityNetstackController(t, "")
		require.NoError(t, err)
		gw := newTestReliabilityGateway(t, 1)
		assert.NoError(t, c.UpdateGateway(t.Context(), gw),
			"an update for a Gateway whose add event was missed forces a full reconnection")
		assert.Equal(t, []string{gw.Wireguard.PublicKey}, getTestReliabilityPeerKeys(t, c))
	})
	t.Run("RL-11-malformed-gateway-fails-whole-device", func(t *testing.T) {
		good := newTestReliabilityGateway(t, 1)
		bad := newTestReliabilityGateway(t, 2)
		bad.Wireguard.PublicKey = "not-a-key"
		c, err := newTestReliabilityNetstackController(t, "", good, bad)
		require.NoError(t, err, "one malformed Gateway in the initial state prevents every Connection")
		assert.Equal(t, []string{good.Wireguard.PublicKey}, getTestReliabilityPeerKeys(t, c))
	})
	t.Run("RL-22-local-dns-bind-failure-is-never-retried", func(t *testing.T) {
		blocker, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := blocker.LocalAddr().String()
		c, err := newTestReliabilityNetstackController(t, addr)
		require.NoError(t, err)
		require.NoError(t, blocker.Close())
		assert.Eventually(t, func() bool {
			return testReliabilityLocalDNSReady(addr)
		}, 10*time.Second, 50*time.Millisecond, "the local DNS server stays disabled for the whole Connection")
		assert.NoError(t, c.Close())
	})
	t.Run("RL-14-published-port-gives-up-after-startup-window", func(t *testing.T) {
		if testing.Short() {
			t.Skip("waiting past the published listener startup window")
		}
		blocker, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := blocker.Addr().(*net.TCPAddr)
		c := newTestPlatformController(t, userv1.ConnectionState_V4)
		c.c.Preferences.PublishedServices = []*cliconfigv1.Connection_Preferences_PublishedService{{
			Fqdn: "web.default.local.example.com", Name: "web.default", Port: 8080,
			HostPort: int32(addr.Port), HostAddress: "127.0.0.1",
			L4Type: cliconfigv1.Connection_Preferences_PublishedService_TCP,
		}}
		p, err := newServiceProxy(c)
		require.NoError(t, err)
		require.NoError(t, p.Start(t.Context()))
		defer p.Close()
		time.Sleep(27 * time.Second)
		require.NoError(t, blocker.Close())
		assert.Eventually(t, func() bool {
			conn, err := net.DialTimeout("tcp", addr.String(), 200*time.Millisecond)
			if err != nil {
				return false
			}
			conn.Close()
			return true
		}, 5*time.Second, 50*time.Millisecond, "a published port held for 25 seconds is never published while connected")
	})
}
