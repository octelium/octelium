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
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func newTestCleanupStoreDB(t *testing.T, dir string) *db.DB {
	t.Helper()
	dbC, err := db.Open(dir)
	require.NoError(t, err)
	require.NoError(t, dbC.Migrate())
	t.Cleanup(func() { assert.NoError(t, dbC.Close()) })
	return dbC
}

func TestSanitizeConnectionCleanup(t *testing.T) {
	sshDir := filepath.Join(t.TempDir(), ".ssh")
	knownHosts := filepath.Join(sshDir, "known_hosts")
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	rulePath, err := getNRPTRuleLocalPath("example.com")
	require.NoError(t, err)
	marker := "octelium-managed:example.com"
	resolvConf := func(cfg *cliconfigv1.ConnectionCleanup_DNS_ResolvConf) *cliconfigv1.ConnectionCleanup_DNS {
		return &cliconfigv1.ConnectionCleanup_DNS{
			Config: &cliconfigv1.ConnectionCleanup_DNS_ResolvConf_{ResolvConf: cfg},
		}
	}
	systemdResolved := func(device string) *cliconfigv1.ConnectionCleanup_DNS {
		return &cliconfigv1.ConnectionCleanup_DNS{
			Config: &cliconfigv1.ConnectionCleanup_DNS_SystemdResolved_{
				SystemdResolved: &cliconfigv1.ConnectionCleanup_DNS_SystemdResolved{DeviceName: device, IsResolvectl: true},
			},
		}
	}
	macos := func(key string) *cliconfigv1.ConnectionCleanup_DNS {
		return &cliconfigv1.ConnectionCleanup_DNS{
			Config: &cliconfigv1.ConnectionCleanup_DNS_Macos{
				Macos: &cliconfigv1.ConnectionCleanup_DNS_MacOS{
					ScutilKey: key,
					Services: []*cliconfigv1.ConnectionCleanup_DNS_MacOS_Service{
						{Name: "Wi-Fi", DnsServers: []string{"Empty"}, InstalledDNSServers: []string{"100.64.0.53"}},
					},
				},
			},
		}
	}
	windows := func(path, marker string) *cliconfigv1.ConnectionCleanup_DNS {
		return &cliconfigv1.ConnectionCleanup_DNS{
			Config: &cliconfigv1.ConnectionCleanup_DNS_Windows_{
				Windows: &cliconfigv1.ConnectionCleanup_DNS_Windows{NrptRulePath: path, NrptMarker: marker},
			},
		}
	}

	tests := []struct {
		name string
		in   *cliconfigv1.ConnectionCleanup
		want *cliconfigv1.ConnectionCleanup
	}{
		{
			name: "valid-linux",
			in: &cliconfigv1.ConnectionCleanup{
				Id: "id",
				Dns: resolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
					Path: resolvConfPath, Existed: true, Mode: 0o644,
					Content: []byte("nameserver 192.0.2.53\n"), InstalledHash: []byte("hash"),
				}),
				Device: &cliconfigv1.ConnectionCleanup_Device{
					Type: cliconfigv1.ConnectionCleanup_Device_LINUX_WIREGUARD, Name: "octelium-abc123",
				},
				Ssh: &cliconfigv1.ConnectionCleanup_SSH{Marker: marker, FilePaths: []string{knownHosts, authorizedKeys}},
			},
		},
		{
			name: "valid-resolvconf-symlink",
			in: &cliconfigv1.ConnectionCleanup{
				Dns: resolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
					Path: resolvConfPath, Existed: true, IsSymlink: true, LinkTarget: "../run/systemd/resolve/stub-resolv.conf",
				}),
			},
		},
		{
			name: "valid-systemd-resolved",
			in:   &cliconfigv1.ConnectionCleanup{Dns: systemdResolved("octelium-abc123")},
		},
		{
			name: "valid-macos",
			in:   &cliconfigv1.ConnectionCleanup{Dns: macos("State:/Network/Service/octelium-example-com/DNS")},
		},
		{
			name: "valid-windows",
			in: &cliconfigv1.ConnectionCleanup{
				Dns: windows(rulePath, marker),
				Device: &cliconfigv1.ConnectionCleanup_Device{
					Type: cliconfigv1.ConnectionCleanup_Device_WINDOWS_WIREGUARD, Name: "octelium-example-com",
					Guid: "{4f1b54b2-4d0c-4ff4-9a52-6c2bfb6b2f4a}",
				},
			},
		},
		{
			name: "resolvconf-mode",
			in: &cliconfigv1.ConnectionCleanup{
				Dns: resolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
					Path: resolvConfPath, Existed: true, Mode: uint32(os.ModeSetuid | os.ModeSticky | 0o777),
				}),
			},
			want: &cliconfigv1.ConnectionCleanup{
				Dns: resolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
					Path: resolvConfPath, Existed: true, Mode: 0o755,
				}),
			},
		},
		{
			name: "resolvconf-arbitrary-path",
			in: &cliconfigv1.ConnectionCleanup{
				Id: "id",
				Dns: resolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
					Path: "/etc/sudoers.d/octelium", Existed: true, Mode: 0o440, Content: []byte("ALL ALL=(ALL) NOPASSWD: ALL\n"),
				}),
			},
			want: &cliconfigv1.ConnectionCleanup{Id: "id"},
		},
		{
			name: "resolvconf-symlink-without-target",
			in: &cliconfigv1.ConnectionCleanup{
				Dns: resolvConf(&cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
					Path: resolvConfPath, Existed: true, IsSymlink: true,
				}),
			},
			want: &cliconfigv1.ConnectionCleanup{},
		},
		{
			name: "systemd-resolved-foreign-device",
			in:   &cliconfigv1.ConnectionCleanup{Dns: systemdResolved("eth0")},
			want: &cliconfigv1.ConnectionCleanup{},
		},
		{
			name: "foreign-devices",
			in: &cliconfigv1.ConnectionCleanup{
				Device: &cliconfigv1.ConnectionCleanup_Device{Type: cliconfigv1.ConnectionCleanup_Device_TUN, Name: "docker0"},
			},
			want: &cliconfigv1.ConnectionCleanup{},
		},
		{
			name: "windows-foreign-device",
			in: &cliconfigv1.ConnectionCleanup{
				Device: &cliconfigv1.ConnectionCleanup_Device{Type: cliconfigv1.ConnectionCleanup_Device_WINDOWS_WINTUN, Name: "Ethernet"},
			},
			want: &cliconfigv1.ConnectionCleanup{},
		},
		{
			name: "macos-scutil-injection",
			in: &cliconfigv1.ConnectionCleanup{
				Dns: macos("State:/Network/Service/octelium-example-com/DNS\nset State:/Network/Global/Proxies"),
			},
			want: &cliconfigv1.ConnectionCleanup{Dns: macos("")},
		},
		{
			name: "macos-foreign-key",
			in:   &cliconfigv1.ConnectionCleanup{Dns: macos("State:/Network/Global/IPv4")},
			want: &cliconfigv1.ConnectionCleanup{Dns: macos("")},
		},
		{
			name: "windows-foreign-rule",
			in:   &cliconfigv1.ConnectionCleanup{Dns: windows(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, marker)},
			want: &cliconfigv1.ConnectionCleanup{},
		},
		{
			name: "windows-rule-of-another-domain",
			in:   &cliconfigv1.ConnectionCleanup{Dns: windows(rulePath, "octelium-managed:example.org")},
			want: &cliconfigv1.ConnectionCleanup{},
		},
		{
			name: "ssh-foreign-marker",
			in: &cliconfigv1.ConnectionCleanup{
				Ssh: &cliconfigv1.ConnectionCleanup_SSH{Marker: "root", FilePaths: []string{knownHosts}},
			},
			want: &cliconfigv1.ConnectionCleanup{},
		},
		{
			name: "ssh-foreign-files",
			in: &cliconfigv1.ConnectionCleanup{
				Ssh: &cliconfigv1.ConnectionCleanup_SSH{Marker: marker, FilePaths: []string{
					filepath.Join(t.TempDir(), "sudoers"),
					knownHosts,
					filepath.Join(sshDir, "config"),
					filepath.Join(filepath.Dir(sshDir), "authorized_keys"),
					filepath.Join(".ssh", "known_hosts"),
					authorizedKeys,
				}},
			},
			want: &cliconfigv1.ConnectionCleanup{
				Ssh: &cliconfigv1.ConnectionCleanup_SSH{Marker: marker, FilePaths: []string{knownHosts, authorizedKeys}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want
			if want == nil {
				want = proto.Clone(tt.in).(*cliconfigv1.ConnectionCleanup)
			}
			sanitizeConnectionCleanup(tt.in, "example.com")
			assert.True(t, proto.Equal(want, tt.in), "got %v, want %v", tt.in, want)
		})
	}
}

func TestGetCleanupStoreKey(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "octelium", "octelium.db")
	key := getCleanupStoreKey(dbPath)
	assert.Len(t, key, 32)
	assert.Equal(t, key, getCleanupStoreKey(dbPath))
	assert.Equal(t, key, getCleanupStoreKey(filepath.Join(dir, "octelium", ".", "octelium.db")))
	assert.Equal(t, key, getCleanupStoreKey(filepath.Join(dir, "other", "..", "octelium", "octelium.db")))
	assert.NotEqual(t, key, getCleanupStoreKey(filepath.Join(dir, "octelium2", "octelium.db")))

	wd, err := os.Getwd()
	require.NoError(t, err)
	assert.Equal(t, getCleanupStoreKey(filepath.Join(wd, "octelium.db")), getCleanupStoreKey("octelium.db"))

	if runtime.GOOS == "windows" {
		assert.Equal(t, key, getCleanupStoreKey(strings.ToUpper(dbPath)))
	} else {
		assert.NotEqual(t, key, getCleanupStoreKey(strings.ToUpper(dbPath)))
	}
}

func TestNewCleanupStore(t *testing.T) {
	ownedDB := newTestCleanupStoreDB(t, filepath.Join(t.TempDir(), "octelium"))
	userDB := newTestCleanupStoreDB(t, newTestUnownedDir(t))
	memDB, err := db.Open("memory")
	require.NoError(t, err)

	t.Run("unprivileged", func(t *testing.T) {
		storeDir := filepath.Join(t.TempDir(), "cleanup")
		for _, dbC := range []*db.DB{ownedDB, userDB, memDB, nil} {
			s := newCleanupStore(dbC, &cleanupStoreOpts{dir: storeDir})
			assert.Equal(t, dbC, s.dbC)
			assert.Nil(t, s.userDB)
			assert.False(t, s.isPrivileged)
		}
		_, err := os.Stat(storeDir)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("privileged-own-db", func(t *testing.T) {
		storeDir := filepath.Join(t.TempDir(), "cleanup")
		for _, dbC := range []*db.DB{ownedDB, memDB, nil} {
			s := newCleanupStore(dbC, &cleanupStoreOpts{dir: storeDir, isPrivileged: true})
			assert.Equal(t, dbC, s.dbC)
			assert.Nil(t, s.userDB)
			assert.False(t, s.isPrivileged)
		}
		_, err := os.Stat(storeDir)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("privileged-user-db", func(t *testing.T) {
		storeDir := filepath.Join(t.TempDir(), "cleanup")
		s := newCleanupStore(userDB, &cleanupStoreOpts{dir: storeDir, isPrivileged: true})
		require.NotNil(t, s.dbC)
		assert.Equal(t, userDB, s.userDB)
		assert.True(t, s.isPrivileged)
		assert.Equal(t,
			filepath.Clean(filepath.Join(storeDir, getCleanupStoreKey(userDB.Path()), "octelium.db")),
			filepath.Clean(s.dbC.Path()))
		assert.True(t, isOwnedPath(storeDir, os.ModeDir))
		assert.True(t, isOwnedPath(filepath.Dir(s.dbC.Path()), os.ModeDir))

		again := newCleanupStore(userDB, &cleanupStoreOpts{dir: storeDir, isPrivileged: true})
		require.NotNil(t, again.dbC)
		assert.Equal(t, s.dbC.Path(), again.dbC.Path())

		other := newCleanupStore(newTestCleanupStoreDB(t, newTestUnownedDir(t)),
			&cleanupStoreOpts{dir: storeDir, isPrivileged: true})
		require.NotNil(t, other.dbC)
		assert.NotEqual(t, s.dbC.Path(), other.dbC.Path())
	})

	t.Run("privileged-user-db-container", func(t *testing.T) {
		storeDir := filepath.Join(t.TempDir(), "cleanup")
		s := newCleanupStore(userDB, &cleanupStoreOpts{dir: storeDir, isPrivileged: true, isContainer: true})
		assert.Equal(t, userDB, s.dbC)
		assert.Nil(t, s.userDB)
		assert.True(t, s.isPrivileged)
		_, err := os.Stat(storeDir)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("privileged-user-db-unavailable-store", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(file, nil, 0600))
		for _, storeDir := range []string{"", filepath.Join(file, "cleanup")} {
			s := newCleanupStore(userDB, &cleanupStoreOpts{dir: storeDir, isPrivileged: true})
			assert.Nil(t, s.dbC)
			assert.Equal(t, userDB, s.userDB)
			assert.True(t, s.isPrivileged)
		}
	})
}

func TestPrepareCleanupStoreDir(t *testing.T) {
	storeDir := filepath.Join(t.TempDir(), "octelium", "cleanup")
	dir := filepath.Join(storeDir, "key")
	require.NoError(t, prepareCleanupStoreDir(storeDir, dir))
	require.NoError(t, prepareCleanupStoreDir(storeDir, dir))
	assert.True(t, isOwnedPath(storeDir, os.ModeDir))
	assert.True(t, isOwnedPath(dir, os.ModeDir))

	file := filepath.Join(storeDir, "file")
	require.NoError(t, os.WriteFile(file, nil, 0600))
	assert.Error(t, prepareCleanupStoreDir(storeDir, file))
	assert.Error(t, prepareCleanupStoreDir(file, filepath.Join(file, "key")))

	unowned := newTestUnownedDir(t)
	assert.Error(t, prepareCleanupStoreDir(unowned, filepath.Join(unowned, "key")))
	assert.Error(t, prepareCleanupStoreDir(storeDir, newTestUnownedDir(t)))
}

func TestCleanupStoreReconcileUserDBJournal(t *testing.T) {
	domain := "example.com"
	marker := "octelium-managed:" + domain
	userDB := newTestCleanupStoreDB(t, newTestUnownedDir(t))
	s := newCleanupStore(userDB, &cleanupStoreOpts{dir: filepath.Join(t.TempDir(), "cleanup"), isPrivileged: true})
	require.NotNil(t, s.dbC)

	sshDir := filepath.Join(t.TempDir(), ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0700))
	knownHosts := filepath.Join(sshDir, "known_hosts")
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	original := "example.org ssh-ed25519 AAAA\n"
	for _, filePath := range []string{knownHosts, authorizedKeys} {
		require.NoError(t, os.WriteFile(filePath,
			[]byte(original+"@cert-authority * ssh-ed25519 AAAA "+marker+"\n"), 0600))
	}
	victim := filepath.Join(t.TempDir(), "victim")
	victimContent := "root:x:0:0 " + marker + "\nuser:x:1000:1000\n"
	require.NoError(t, os.WriteFile(victim, []byte(victimContent), 0600))
	planted := filepath.Join(t.TempDir(), "planted")

	require.NoError(t, userDB.SetConnectionCleanup(domain, &cliconfigv1.ConnectionCleanup{
		Id:    "legacy",
		Phase: cliconfigv1.ConnectionCleanup_ACTIVE,
		Dns: &cliconfigv1.ConnectionCleanup_DNS{
			Config: &cliconfigv1.ConnectionCleanup_DNS_ResolvConf_{
				ResolvConf: &cliconfigv1.ConnectionCleanup_DNS_ResolvConf{
					Path: planted, Existed: true, Mode: 0o755, Content: []byte("#!/bin/sh\nid\n"),
				},
			},
		},
		Ssh: &cliconfigv1.ConnectionCleanup_SSH{Marker: marker, FilePaths: []string{knownHosts, victim}},
	}))
	require.NoError(t, s.dbC.SetConnectionCleanup(domain, &cliconfigv1.ConnectionCleanup{
		Id:    "privileged",
		Phase: cliconfigv1.ConnectionCleanup_ACTIVE,
		Ssh:   &cliconfigv1.ConnectionCleanup_SSH{Marker: marker, FilePaths: []string{authorizedKeys}},
	}))
	require.NoError(t, s.dbC.SetConnectionCleanup("example.org", &cliconfigv1.ConnectionCleanup{
		Id: "other",
	}))
	userFI, err := os.Stat(userDB.Path())
	require.NoError(t, err)

	assert.Equal(t, []string{"example.com", "example.org"}, s.listDomains())
	s.reconcile(domain)

	_, err = os.Stat(planted)
	assert.True(t, os.IsNotExist(err), "a privileged process must not restore a file named by the journal of a user")
	b, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, victimContent, string(b), "a privileged process must not edit a file named by the journal of a user")
	for _, filePath := range []string{knownHosts, authorizedKeys} {
		b, err := os.ReadFile(filePath)
		require.NoError(t, err)
		assert.Equal(t, original, string(b), filePath)
	}

	_, err = userDB.GetConnectionCleanup(domain)
	assert.True(t, userDB.ErrorIsNotFound(err), "the journal of a previous version must be migrated")
	_, err = s.dbC.GetConnectionCleanup(domain)
	assert.True(t, s.dbC.ErrorIsNotFound(err))
	assert.Equal(t, []string{"example.org"}, s.listDomains())

	fi, err := os.Stat(userDB.Path())
	require.NoError(t, err)
	assert.Equal(t, userFI.Mode(), fi.Mode())
	assertTestCleanupSameOwner(t, userFI, fi)
}

func TestCleanupStoreReconcileKeepsUserDBJournalOfRunningProcess(t *testing.T) {
	domain := "example.com"
	userDB := newTestCleanupStoreDB(t, newTestUnownedDir(t))
	s := newCleanupStore(userDB, &cleanupStoreOpts{dir: filepath.Join(t.TempDir(), "cleanup"), isPrivileged: true})
	require.NotNil(t, s.dbC)
	running := &cliconfigv1.ConnectionCleanup{
		Id: "running", Phase: cliconfigv1.ConnectionCleanup_ACTIVE,
		Metadata: map[string]string{"pid": strconv.Itoa(os.Getppid())},
		Ssh:      &cliconfigv1.ConnectionCleanup_SSH{Marker: "root", FilePaths: []string{"/etc/passwd"}},
	}
	require.NoError(t, userDB.SetConnectionCleanup(domain, running))
	s.reconcile(domain)
	saved, err := userDB.GetConnectionCleanup(domain)
	require.NoError(t, err)
	assert.True(t, proto.Equal(running, saved), "the journal of a running process must be left to that process")
}

func TestControllerCleanupUsesPrivilegedStore(t *testing.T) {
	c, sshDir := newTestReliabilitySSHController(t)
	userDB := newTestCleanupStoreDB(t, newTestUnownedDir(t))
	c.dbC = userDB
	c.cleanupStore = newCleanupStore(userDB, &cleanupStoreOpts{
		dir: filepath.Join(t.TempDir(), "cleanup"), isPrivileged: true,
	})
	storeDB := c.cleanupStore.dbC
	require.NotNil(t, storeDB)

	c.prepareCleanup()
	require.NotNil(t, c.cleanup)
	knownHosts := filepath.Join(sshDir, "known_hosts")
	authorizedKeys := filepath.Join(sshDir, "authorized_keys")
	require.NoError(t, os.WriteFile(knownHosts, []byte("example.org ssh-ed25519 AAAA\n"), 0600))
	require.NoError(t, c.setServiceConfigSSH(&userv1.ConnectionState_ServiceConfig_SSH{
		KnownHosts:     []string{"@cert-authority * ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
		AuthorizedKeys: []string{"cert-authority ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"},
	}))
	journal, err := storeDB.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{knownHosts, authorizedKeys}, journal.GetSsh().GetFilePaths())
	_, err = userDB.GetConnectionCleanup("example.com")
	assert.True(t, userDB.ErrorIsNotFound(err), "a privileged process must not journal into the database of a user")
	assert.Equal(t, []string{"example.com"}, ListConnectionCleanupDomains(storeDB))

	moved := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.Rename(knownHosts, moved))
	require.NoError(t, os.Mkdir(knownHosts, 0700))
	require.Error(t, c.Close())
	require.NoError(t, os.Remove(knownHosts))
	require.NoError(t, os.Rename(moved, knownHosts))
	journal, err = storeDB.GetConnectionCleanup("example.com")
	require.NoError(t, err)
	assert.Equal(t, cliconfigv1.ConnectionCleanup_CLEANING, journal.Phase)

	c.ReconcileCleanup()
	b, err := os.ReadFile(knownHosts)
	require.NoError(t, err)
	assert.Equal(t, "example.org ssh-ed25519 AAAA\n", string(b))
	_, err = storeDB.GetConnectionCleanup("example.com")
	assert.True(t, storeDB.ErrorIsNotFound(err))
	_, err = userDB.GetConnectionCleanup("example.com")
	assert.True(t, userDB.ErrorIsNotFound(err))
}

func TestControllerCleanupWithoutPrivilegedStore(t *testing.T) {
	c, _ := newTestReliabilitySSHController(t)
	userDB := newTestCleanupStoreDB(t, newTestUnownedDir(t))
	c.dbC = userDB
	c.cleanupStore = newCleanupStore(userDB, &cleanupStoreOpts{isPrivileged: true})
	require.Nil(t, c.cleanupStore.dbC)

	c.prepareCleanup()
	assert.Nil(t, c.cleanup)
	c.setCleanupPhase(cliconfigv1.ConnectionCleanup_ACTIVE)
	require.NoError(t, c.Close())
	_, err := userDB.GetConnectionCleanup("example.com")
	assert.True(t, userDB.ErrorIsNotFound(err))
}
