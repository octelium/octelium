//go:build !windows
// +build !windows

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
	"net"
	"os"
	"path"
	"strings"
	"syscall"
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
)

func newTestResolvConfCtl(t *testing.T, servers []string) (*Controller, string) {
	filePath := path.Join(t.TempDir(), "resolv.conf")

	c := &Controller{
		ipv4Supported: true,
		ipv6Supported: true,
		c: &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Dns: &userv1.DNS{
					Servers: servers,
				},
			},
			Info: &cliconfigv1.Connection_Info{
				Cluster: &cliconfigv1.Connection_Info_Cluster{
					Domain: "example.com",
				},
			},
			Preferences: &cliconfigv1.Connection_Preferences{},
		},
	}
	c.resolvConf.path = filePath

	return c, filePath
}

func getFileInode(t *testing.T, filePath string) uint64 {
	fi, err := os.Stat(filePath)
	assert.Nil(t, err)

	st, ok := fi.Sys().(*syscall.Stat_t)
	assert.True(t, ok)

	return st.Ino
}

func TestSetResolvConfOnlyUsesClusterDNS(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	original := "nameserver 192.168.1.1\nnameserver 9.9.9.9\nsearch corp.lan\noptions ndots:5 timeout:2\n"
	assert.Nil(t, os.WriteFile(filePath, []byte(original), 0644))

	assert.Nil(t, c.setResolvConf())

	b, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	out := string(b)

	assert.Equal(t, 1, strings.Count(out, "nameserver "))
	assert.True(t, strings.Contains(out, "nameserver 100.64.0.53"))
	assert.False(t, strings.Contains(out, "192.168.1.1"))
	assert.False(t, strings.Contains(out, "9.9.9.9"))
	assert.False(t, strings.Contains(out, "8.8.8.8"))
	assert.False(t, strings.Contains(out, "1.1.1.1"))

	assert.True(t, strings.Contains(out, "search local.example.com corp.lan"))
	assert.True(t, strings.Contains(out, "options ndots:5 timeout:2"))
}

func TestSetResolvConfWritesInPlace(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	assert.Nil(t, os.WriteFile(filePath, []byte("nameserver 192.168.1.1\n"), 0644))
	inode := getFileInode(t, filePath)

	assert.Nil(t, c.setResolvConf())
	assert.Equal(t, inode, getFileInode(t, filePath))

	assert.Nil(t, c.unsetResolvConf())
	assert.Equal(t, inode, getFileInode(t, filePath))
}

func TestUnsetResolvConfRestoresOriginal(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	original := "nameserver 192.168.1.1\nsearch corp.lan\noptions ndots:5\n"
	assert.Nil(t, os.WriteFile(filePath, []byte(original), 0600))

	assert.Nil(t, c.setResolvConf())
	assert.Nil(t, c.unsetResolvConf())

	b, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.Equal(t, original, string(b))

	fi, err := os.Stat(filePath)
	assert.Nil(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
}

func TestResolvConfSymlinkIsReplacedAndRestored(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	target := path.Join(path.Dir(filePath), "stub-resolv.conf")
	targetContent := "nameserver 127.0.0.53\noptions edns0\n"
	assert.Nil(t, os.WriteFile(target, []byte(targetContent), 0644))
	assert.Nil(t, os.Symlink(target, filePath))

	assert.Nil(t, c.setResolvConf())

	fi, err := os.Lstat(filePath)
	assert.Nil(t, err)
	assert.Equal(t, os.FileMode(0), fi.Mode()&os.ModeSymlink)

	b, err := os.ReadFile(target)
	assert.Nil(t, err)
	assert.Equal(t, targetContent, string(b))

	b, err = os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.True(t, strings.Contains(string(b), "nameserver 100.64.0.53"))
	assert.True(t, strings.Contains(string(b), "options edns0"))

	assert.Nil(t, c.unsetResolvConf())

	fi, err = os.Lstat(filePath)
	assert.Nil(t, err)
	assert.NotEqual(t, os.FileMode(0), fi.Mode()&os.ModeSymlink)

	linkTarget, err := os.Readlink(filePath)
	assert.Nil(t, err)
	assert.Equal(t, target, linkTarget)
}

func TestResolvConfCreatedWhenMissing(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	assert.Nil(t, c.setResolvConf())

	b, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.True(t, strings.Contains(string(b), "nameserver 100.64.0.53"))

	assert.Nil(t, c.unsetResolvConf())

	_, err = os.Stat(filePath)
	assert.True(t, os.IsNotExist(err))
}

func TestSetResolvConfIsIdempotentAcrossUpdateDNS(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	original := "nameserver 192.168.1.1\n"
	assert.Nil(t, os.WriteFile(filePath, []byte(original), 0644))

	assert.Nil(t, c.setResolvConf())

	c.c.Connection.Dns.Servers = []string{"100.64.0.54"}
	assert.Nil(t, c.setResolvConf())

	b, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.True(t, strings.Contains(string(b), "nameserver 100.64.0.54"))
	assert.False(t, strings.Contains(string(b), "100.64.0.53"))

	assert.Nil(t, c.unsetResolvConf())

	b, err = os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.Equal(t, original, string(b))
}

func TestUnsetResolvConfWithoutSet(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	original := "nameserver 192.168.1.1\n"
	assert.Nil(t, os.WriteFile(filePath, []byte(original), 0644))

	assert.Nil(t, c.unsetResolvConf())

	b, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.Equal(t, original, string(b))
}

func TestSetResolvConfWithoutValidServers(t *testing.T) {
	for _, servers := range [][]string{nil, {"not-an-ip"}} {
		c, filePath := newTestResolvConfCtl(t, servers)

		original := "nameserver 192.168.1.1\n"
		assert.Nil(t, os.WriteFile(filePath, []byte(original), 0644))

		assert.NotNil(t, c.setResolvConf())
		assert.False(t, c.resolvConf.written)

		b, err := os.ReadFile(filePath)
		assert.Nil(t, err)
		assert.Equal(t, original, string(b))

		assert.Nil(t, c.unsetResolvConf())

		b, err = os.ReadFile(filePath)
		assert.Nil(t, err)
		assert.Equal(t, original, string(b))
	}
}

func TestSetResolvConfReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the file mode")
	}

	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	original := "nameserver 192.168.1.1\n"
	assert.Nil(t, os.WriteFile(filePath, []byte(original), 0444))

	assert.NotNil(t, c.setResolvConf())
	assert.False(t, c.resolvConf.written)

	b, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.Equal(t, original, string(b))

	assert.Nil(t, c.unsetResolvConf())
}

func TestResolvConfCapsNameserversAndSearchDomains(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t,
		[]string{"100.64.0.51", "100.64.0.52", "100.64.0.53", "100.64.0.54"})

	assert.Nil(t, os.WriteFile(filePath,
		[]byte("search a.lan b.lan c.lan d.lan e.lan f.lan g.lan\n"), 0644))

	assert.Nil(t, c.saveResolvConf())

	opts, err := c.getResolvConfOpts()
	assert.Nil(t, err)
	assert.Equal(t, resolvConfMaxNameservers, len(opts.Nameservers))
	assert.Equal(t, resolvConfMaxSearchDomains, len(opts.SearchDomains))
	assert.Equal(t, "local.example.com", opts.SearchDomains[0])
}

func TestGetNRPTNamespaces(t *testing.T) {
	assert.Equal(t, []string{".local.example.com"},
		getNRPTNamespaces([]string{"local.example.com"}, "example.com"))

	assert.Equal(t, []string{".local.example.com"},
		getNRPTNamespaces([]string{"LOCAL.Example.COM."}, "Example.com"))

	assert.Equal(t, []string{".local.example.com"},
		getNRPTNamespaces([]string{"local.example.com", "local.example.com."}, "example.com"))

	assert.Equal(t, []string{".local.example.com", ".svc.example.com"},
		getNRPTNamespaces([]string{"local.example.com", "svc.example.com"}, "example.com"))
}

func TestGetNRPTNamespacesRefusesCapturingTheClusterDomain(t *testing.T) {
	assert.Nil(t, getNRPTNamespaces([]string{"example.com"}, "example.com"))
	assert.Nil(t, getNRPTNamespaces([]string{"com"}, "example.com"))
	assert.Nil(t, getNRPTNamespaces([]string{"example.com."}, "example.com"))
	assert.Nil(t, getNRPTNamespaces([]string{"corp.example.com"}, "eu.corp.example.com"))

	assert.Equal(t, []string{".local.example.com"},
		getNRPTNamespaces([]string{"example.com", "local.example.com"}, "example.com"))
}

func TestGetNRPTNamespacesWithInvalidDomains(t *testing.T) {
	assert.Nil(t, getNRPTNamespaces(nil, "example.com"))
	assert.Nil(t, getNRPTNamespaces([]string{""}, "example.com"))
	assert.Nil(t, getNRPTNamespaces([]string{"   "}, "example.com"))
	assert.Nil(t, getNRPTNamespaces([]string{"local example.com"}, "example.com"))
	assert.Nil(t, getNRPTNamespaces([]string{"local.example.com\nevil"}, "example.com"))
	assert.Nil(t, getNRPTNamespaces([]string{"100.64.0.53"}, "example.com"))
}

func TestGetNRPTRuleKey(t *testing.T) {
	key, err := getNRPTRuleKey("example.com")
	assert.Nil(t, err)
	assert.Regexp(t, `^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`, key)

	sameKey, err := getNRPTRuleKey("Example.COM ")
	assert.Nil(t, err)
	assert.Equal(t, key, sameKey)

	otherKey, err := getNRPTRuleKey("other.example.com")
	assert.Nil(t, err)
	assert.NotEqual(t, key, otherKey)

	for _, domain := range []string{"", "  ", "not a domain", "exa\nmple.com", `exa\mple.com`} {
		_, err := getNRPTRuleKey(domain)
		assert.NotNil(t, err)
	}
}

func TestSetDNSContainerModeWritesResolvConf(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})
	c.c.Preferences.RuntimeMode = cliconfigv1.Connection_Preferences_CONTAINER

	original := "nameserver 127.0.0.11\noptions ndots:5\n"
	assert.Nil(t, os.WriteFile(filePath, []byte(original), 0644))

	assert.Nil(t, c.SetDNS())

	b, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.True(t, strings.Contains(string(b), "nameserver 100.64.0.53"))
	assert.False(t, strings.Contains(string(b), "127.0.0.11"))
	assert.True(t, strings.Contains(string(b), "options ndots:5"))

	assert.Nil(t, c.UnsetDNS())

	b, err = os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.Equal(t, original, string(b))
}

func TestSetDNSContainerModeRespectsIgnoreDNS(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})
	c.c.Preferences.RuntimeMode = cliconfigv1.Connection_Preferences_CONTAINER
	c.c.Preferences.IgnoreDNS = true

	original := "nameserver 127.0.0.11\n"
	assert.Nil(t, os.WriteFile(filePath, []byte(original), 0644))

	assert.Nil(t, c.SetDNS())

	b, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.Equal(t, original, string(b))
}

func TestSetDNSContainerModeSkippedInNetstackMode(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})
	c.c.Preferences.RuntimeMode = cliconfigv1.Connection_Preferences_CONTAINER
	c.isNetstack = true

	original := "nameserver 127.0.0.11\n"
	assert.Nil(t, os.WriteFile(filePath, []byte(original), 0644))

	assert.Nil(t, c.SetDNS())

	b, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.Equal(t, original, string(b))
}

func TestGetLocalDNSServerAddrIsLoopback(t *testing.T) {
	c, _ := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	host, port, err := net.SplitHostPort(c.getLocalDNSServerAddr())
	assert.Nil(t, err)
	assert.Equal(t, "53", port)

	ip := net.ParseIP(host)
	assert.NotNil(t, ip)
	assert.True(t, ip.IsLoopback())
}

func TestSaveResolvConfRefusesUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the file mode")
	}

	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	original := "nameserver 192.168.1.1\n"
	assert.Nil(t, os.WriteFile(filePath, []byte(original), 0000))

	assert.NotNil(t, c.saveResolvConf())
	assert.False(t, c.resolvConf.saved)
	assert.False(t, c.resolvConf.existed)

	assert.NotNil(t, c.setResolvConf())
	assert.False(t, c.resolvConf.written)

	assert.Nil(t, os.Chmod(filePath, 0644))
	b, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.Equal(t, original, string(b))
}

func TestUnsetResolvConfIsRetryableAfterFailure(t *testing.T) {
	c, filePath := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	target := path.Join(path.Dir(filePath), "stub-resolv.conf")
	assert.Nil(t, os.WriteFile(target, []byte("nameserver 127.0.0.53\n"), 0644))
	assert.Nil(t, os.Symlink(target, filePath))

	assert.Nil(t, c.setResolvConf())
	assert.True(t, c.resolvConf.written)

	c.resolvConf.linkTarget = ""
	assert.NotNil(t, c.unsetResolvConf())
	assert.True(t, c.resolvConf.written)

	c.resolvConf.linkTarget = target
	assert.Nil(t, c.unsetResolvConf())
	assert.False(t, c.resolvConf.written)

	linkTarget, err := os.Readlink(filePath)
	assert.Nil(t, err)
	assert.Equal(t, target, linkTarget)
}

func TestGetClusterDNSServersFiltersByFamily(t *testing.T) {
	c, _ := newTestResolvConfCtl(t, []string{"100.64.0.53", "fd00::53", "not-an-ip"})

	c.ipv4Supported, c.ipv6Supported = true, false
	assert.Equal(t, []string{"100.64.0.53"}, c.getClusterDNSServers())

	c.ipv4Supported, c.ipv6Supported = false, true
	assert.Equal(t, []string{"fd00::53"}, c.getClusterDNSServers())

	c.ipv4Supported, c.ipv6Supported = true, true
	assert.Equal(t, []string{"100.64.0.53", "fd00::53"}, c.getClusterDNSServers())

	c.ipv4Supported, c.ipv6Supported = false, false
	assert.Nil(t, c.getClusterDNSServers())
}
