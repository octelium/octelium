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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/proto"
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

func newTestReliabilityCleanupDB(t *testing.T, c *Controller) *db.DB {
	t.Helper()
	dbC, err := db.Open("memory")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, dbC.Close()) })
	c.dbC = dbC
	return dbC
}

func TestControllerReconcileCleanupAfterTransientCloseFailure(t *testing.T) {
	c, sshDir := newTestReliabilitySSHController(t)
	dbC := newTestReliabilityCleanupDB(t, c)
	c.prepareCleanup()
	require.NotNil(t, c.cleanup)
	knownHosts := filepath.Join(sshDir, "known_hosts")
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	require.NoError(t, os.WriteFile(knownHosts, []byte("example.org ssh-ed25519 AAAA\n"), 0600))
	require.NoError(t, c.setServiceConfigSSH(&userv1.ConnectionState_ServiceConfig_SSH{
		KnownHosts:     []string{"@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
		AuthorizedKeys: []string{"cert-authority ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
	}))
	b, err := os.ReadFile(knownHosts)
	require.NoError(t, err)
	require.Contains(t, string(b), "@cert-authority")
	moved := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.Rename(knownHosts, moved))
	require.NoError(t, os.Mkdir(knownHosts, 0700))
	require.Error(t, c.Close())
	b, err = os.ReadFile(authorizedKeys)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "cert-authority")
	require.NoError(t, os.Remove(knownHosts))
	require.NoError(t, os.Rename(moved, knownHosts))
	journal, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.Equal(t, cliconfigv1.ConnectionCleanup_CLEANING, journal.Phase)
	assert.Equal(t, []string{knownHosts, authorizedKeys}, journal.GetSsh().GetFilePaths())
	c.ReconcileCleanup()
	b, err = os.ReadFile(knownHosts)
	require.NoError(t, err)
	assert.Equal(t, "example.org ssh-ed25519 AAAA\n", string(b))
	b, err = os.ReadFile(authorizedKeys)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "cert-authority")
	_, err = dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
	c.ReconcileCleanup()
	_, err = dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
}

func TestControllerReconcileCleanupReleasesResolvConfLock(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("This test restores the Linux container resolv.conf")
	}
	c := newTestPlatformController(t, userv1.ConnectionState_V4)
	c.isNetstack = false
	c.isQUIC = false
	c.c.Preferences.IgnoreDNS = false
	c.c.Preferences.RuntimeMode = cliconfigv1.Connection_Preferences_CONTAINER
	c.c.Preferences.DeviceName = fmt.Sprintf("octelium-%s", utilrand.GetRandomStringLowercase(6))
	dbC := newTestReliabilityCleanupDB(t, c)
	c.prepareCleanup()
	require.NotNil(t, c.cleanup)
	lockPath := filepath.Join(t.TempDir(), resolvConfLockName)
	c.resolvConf.lock = flock.New(lockPath)
	locked, err := c.resolvConf.lock.TryLock()
	require.NoError(t, err)
	require.True(t, locked)
	original := []byte("nameserver 192.0.2.53\n")
	require.NoError(t, os.WriteFile(c.resolvConf.path, original, 0644))
	require.NoError(t, c.setResolvConf())
	installed, err := os.ReadFile(c.resolvConf.path)
	require.NoError(t, err)
	require.NotEqual(t, original, installed)
	require.NoError(t, os.Remove(c.resolvConf.path))
	require.NoError(t, os.Mkdir(c.resolvConf.path, 0755))
	require.Error(t, c.Close())
	other := flock.New(lockPath)
	locked, err = other.TryLock()
	require.NoError(t, err)
	require.False(t, locked, "the closed controller still holds the resolv.conf lock after a failed restore")
	c.ReconcileCleanup()
	locked, err = other.TryLock()
	require.NoError(t, err)
	assert.True(t, locked, "the next Connection of this process must be able to manage resolv.conf")
	require.NoError(t, other.Close())
	journal, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err, "a journal that could not be reconciled must be kept")
	assert.Equal(t, cliconfigv1.ConnectionCleanup_CLEANING, journal.Phase)
	assert.Equal(t, original, journal.GetDns().GetResolvConf().GetContent())
	require.NoError(t, os.Remove(c.resolvConf.path))
	require.NoError(t, os.WriteFile(c.resolvConf.path, installed, 0644))
	c.ReconcileCleanup()
	b, err := os.ReadFile(c.resolvConf.path)
	require.NoError(t, err)
	assert.Equal(t, original, b)
	_, err = dbC.GetConnectionCleanup("example.com")
	assert.True(t, dbC.ErrorIsNotFound(err))
}

func TestControllerReconcileCleanupOnlyAfterFailedClose(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_V4)
	dbC := newTestReliabilityCleanupDB(t, c)
	stale := &cliconfigv1.ConnectionCleanup{
		Id: "stale-cleanup", Phase: cliconfigv1.ConnectionCleanup_CLEANING,
		Metadata: map[string]string{"pid": strconv.Itoa(os.Getpid())},
	}
	require.NoError(t, dbC.SetConnectionCleanup("example.com", stale))
	c.ReconcileCleanup()
	saved, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.True(t, proto.Equal(stale, saved), "a running controller must not reconcile the cleanup state")
	require.NoError(t, c.Close())
	c.ReconcileCleanup()
	saved, err = dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.True(t, proto.Equal(stale, saved), "a cleanly closed controller must not reconcile the cleanup state")
}

func TestControllerReconcileCleanupKeepsJournalOfRunningProcess(t *testing.T) {
	c, sshDir := newTestReliabilitySSHController(t)
	dbC := newTestReliabilityCleanupDB(t, c)
	owned := &cliconfigv1.ConnectionCleanup{
		Id: "running-owner", Phase: cliconfigv1.ConnectionCleanup_ACTIVE,
		Metadata: map[string]string{"pid": strconv.Itoa(os.Getppid())},
		Ssh: &cliconfigv1.ConnectionCleanup_SSH{
			Marker:    "octelium-managed:example.com",
			FilePaths: []string{filepath.Join(sshDir, "authorized_keys")},
		},
	}
	require.NoError(t, dbC.SetConnectionCleanup("example.com", owned))
	c.prepareCleanup()
	require.Nil(t, c.cleanup)
	require.NoError(t, os.Mkdir(filepath.Join(sshDir, "known_hosts"), 0700))
	require.Error(t, c.Close())
	c.ReconcileCleanup()
	saved, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.True(t, proto.Equal(owned, saved), "the cleanup state of another running process must be left to that process")
}

func TestControllerReconcileCleanupWithoutJournalDB(t *testing.T) {
	c, sshDir := newTestReliabilitySSHController(t)
	require.NoError(t, os.Mkdir(filepath.Join(sshDir, "known_hosts"), 0700))
	c.prepareCleanup()
	require.Nil(t, c.cleanup)
	closeErr := c.Close()
	require.Error(t, closeErr)
	assert.NotPanics(t, c.ReconcileCleanup)
	assert.Equal(t, closeErr, c.Close())
}

func setTestReliabilityPrivateLockDir(t *testing.T, name string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	dirs := getLockDirs()
	if dirs[len(dirs)-1] != filepath.Join(dir, "octelium") {
		t.Skip("the temporary directory cannot be overridden")
	}
	for _, shared := range dirs[:len(dirs)-1] {
		if err := os.MkdirAll(shared, 0755); err != nil {
			continue
		}
		f, err := os.OpenFile(filepath.Join(shared, name), os.O_CREATE|os.O_RDONLY, 0644)
		if err != nil {
			continue
		}
		f.Close()
		t.Skip("the shared lock directory is usable by this user and cannot be isolated")
	}
}

func holdTestReliabilityLock(t *testing.T, name string, d time.Duration) {
	t.Helper()
	lock, err := acquireFileLock(name)
	require.NoError(t, err)
	require.NotNil(t, lock)
	timer := time.AfterFunc(d, func() { releaseFileLock(lock) })
	t.Cleanup(func() {
		if timer.Stop() {
			releaseFileLock(lock)
		}
	})
}

func newTestReliabilitySSHConfig(domain string) *userv1.ConnectionState_ServiceConfig_SSH {
	return &userv1.ConnectionState_ServiceConfig_SSH{
		KnownHosts:     []string{fmt.Sprintf("@cert-authority *.%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample", domain)},
		AuthorizedKeys: []string{fmt.Sprintf("cert-authority,principals=\"%s\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample", domain)},
	}
}

func TestControllerSSHServiceConfigsWaitForBriefLockHolder(t *testing.T) {
	setTestReliabilityPrivateLockDir(t, sshConfigLockName)
	c, sshDir := newTestReliabilitySSHController(t)
	dbC := newTestReliabilityCleanupDB(t, c)
	c.prepareCleanup()
	require.NotNil(t, c.cleanup)
	knownHosts := filepath.Join(sshDir, "known_hosts")
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	require.NoError(t, os.WriteFile(knownHosts, []byte("example.org ssh-ed25519 AAAA\n"), 0600))
	cfg := newTestReliabilitySSHConfig("example.com")
	readFile := func(path string) string {
		b, err := os.ReadFile(path)
		require.NoError(t, err)
		return string(b)
	}

	holdTestReliabilityLock(t, sshConfigLockName, 300*time.Millisecond)
	started := time.Now()
	require.NoError(t, c.setServiceConfigSSH(cfg))
	assert.GreaterOrEqual(t, time.Since(started), 250*time.Millisecond)
	assert.Contains(t, readFile(knownHosts), cfg.KnownHosts[0])
	assert.Contains(t, readFile(authorizedKeys), cfg.AuthorizedKeys[0])
	journal, err := dbC.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{knownHosts, authorizedKeys}, journal.GetSsh().GetFilePaths())

	holdTestReliabilityLock(t, sshConfigLockName, 300*time.Millisecond)
	started = time.Now()
	require.NoError(t, c.unsetServiceConfigSSH())
	assert.GreaterOrEqual(t, time.Since(started), 250*time.Millisecond)
	assert.Equal(t, "example.org ssh-ed25519 AAAA\n", readFile(knownHosts))
	assert.NotContains(t, readFile(authorizedKeys), "cert-authority")

	require.NoError(t, c.setServiceConfigSSH(cfg))
	holdTestReliabilityLock(t, sshConfigLockName, 300*time.Millisecond)
	require.NoError(t, reconcileSSHCleanup(journal.GetSsh()))
	assert.Equal(t, "example.org ssh-ed25519 AAAA\n", readFile(knownHosts))
	assert.NotContains(t, readFile(authorizedKeys), "cert-authority")
}

func TestControllerSSHServiceConfigsProceedPastStuckLockHolder(t *testing.T) {
	if testing.Short() {
		t.Skip("waiting for the SSH config lock to time out")
	}
	setTestReliabilityPrivateLockDir(t, sshConfigLockName)
	c, sshDir := newTestReliabilitySSHController(t)
	knownHosts := filepath.Join(sshDir, "known_hosts")
	require.NoError(t, os.WriteFile(knownHosts, []byte("example.org ssh-ed25519 AAAA\n"), 0600))
	cfg := newTestReliabilitySSHConfig("example.com")
	holdTestReliabilityLock(t, sshConfigLockName, time.Hour)

	started := time.Now()
	require.NoError(t, c.setServiceConfigSSH(cfg))
	elapsed := time.Since(started)
	assert.GreaterOrEqual(t, elapsed, fileLockWaitTimeout)
	assert.Less(t, elapsed, fileLockWaitTimeout+3*time.Second)
	b, err := os.ReadFile(knownHosts)
	require.NoError(t, err)
	assert.Contains(t, string(b), cfg.KnownHosts[0], "a stuck lock holder must not prevent installing the Cluster CA")

	started = time.Now()
	require.NoError(t, c.Close(), "a stuck lock holder must not make the controller cleanup fail")
	assert.GreaterOrEqual(t, time.Since(started), fileLockWaitTimeout)
	b, err = os.ReadFile(knownHosts)
	require.NoError(t, err)
	assert.Equal(t, "example.org ssh-ed25519 AAAA\n", string(b))
}

func TestControllerConcurrentSSHServiceConfigsKeepEveryDomain(t *testing.T) {
	setTestReliabilityPrivateLockDir(t, sshConfigLockName)
	userHome := t.TempDir()
	sshDir := filepath.Join(userHome, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0700))
	knownHosts := filepath.Join(sshDir, "known_hosts")
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	original := "example.org ssh-ed25519 AAAA\n"
	require.NoError(t, os.WriteFile(knownHosts, []byte(original), 0600))
	require.NoError(t, os.WriteFile(authorizedKeys, []byte(original), 0600))

	var ctls []*Controller
	var cfgs []*userv1.ConnectionState_ServiceConfig_SSH
	for i := range 6 {
		domain := fmt.Sprintf("cluster-%d.example.com", i)
		c := newTestPlatformController(t, userv1.ConnectionState_V4)
		c.c.Info.Cluster.Domain = domain
		c.c.Preferences.UserHome = userHome
		ctls = append(ctls, c)
		cfgs = append(cfgs, newTestReliabilitySSHConfig(domain))
	}

	isSet := make([]bool, len(ctls))
	for round := range 6 {
		var wg sync.WaitGroup
		for i, c := range ctls {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if isSet[i] {
					assert.NoError(t, c.unsetServiceConfigSSH())
				} else {
					assert.NoError(t, c.setServiceConfigSSH(cfgs[i]))
				}
			}()
		}
		wg.Wait()

		knownHostsContent, err := os.ReadFile(knownHosts)
		require.NoError(t, err)
		authorizedKeysContent, err := os.ReadFile(authorizedKeys)
		require.NoError(t, err)
		for i := range ctls {
			isSet[i] = !isSet[i]
			want := 0
			if isSet[i] {
				want = 1
			}
			assert.Equal(t, want, strings.Count(string(knownHostsContent), cfgs[i].KnownHosts[0]),
				"round %d: Cluster %d in known_hosts", round, i)
			assert.Equal(t, want, strings.Count(string(authorizedKeysContent), cfgs[i].AuthorizedKeys[0]),
				"round %d: Cluster %d in authorized_keys", round, i)
		}
		assert.True(t, strings.HasPrefix(string(knownHostsContent), original), "round %d", round)
		assert.True(t, strings.HasPrefix(string(authorizedKeysContent), original), "round %d", round)

		if round%2 == 0 {
			for i := 0; i < len(ctls); i += 2 {
				require.NoError(t, ctls[i].unsetServiceConfigSSH())
				isSet[i] = false
			}
		}
	}

	for i, c := range ctls {
		require.NoError(t, c.unsetServiceConfigSSH())
		isSet[i] = false
	}
	b, err := os.ReadFile(knownHosts)
	require.NoError(t, err)
	assert.Equal(t, original, string(b))
	b, err = os.ReadFile(authorizedKeys)
	require.NoError(t, err)
	assert.Equal(t, original, string(b))
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
