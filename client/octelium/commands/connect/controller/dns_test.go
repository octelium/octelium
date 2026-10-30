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
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
)

func TestControllerDNSCacheByIPMode(t *testing.T) {
	for _, tt := range testControllerIPModes {
		for _, local := range []bool{false, true} {
			name := tt.name
			if local {
				name += "-local"
			}
			t.Run(name, func(t *testing.T) {
				c := newTestPlatformController(t, tt.mode)
				c.c.Connection.Dns.Servers = []string{"invalid", "100.64.0.53", "fd00::53", "dns.example.com"}
				c.c.Preferences.LocalDNS = &cliconfigv1.Connection_Preferences_LocalDNS{
					IsEnabled: local, ListenAddress: "[::1]:1053",
				}
				original := []byte("nameserver 192.0.2.53\n")
				assert.Nil(t, os.WriteFile(c.resolvConf.path, original, 0600))
				assert.Nil(t, c.SetDNS())
				var want []string
				if tt.v4 {
					want = append(want, "100.64.0.53")
				}
				if tt.v6 {
					want = append(want, "fd00::53")
				}
				assert.Equal(t, want, c.GetClusterDNSServers())
				if local {
					assert.Equal(t, []string{"::1"}, c.getDNSServers())
					assert.True(t, net.ParseIP("::1").Equal(c.getCurrentDNS()))
				} else {
					assert.Equal(t, want, c.getDNSServers())
					assert.True(t, net.ParseIP(want[0]).Equal(c.getCurrentDNS()))
				}
				assert.Nil(t, c.UnsetDNS())
				content, err := os.ReadFile(c.resolvConf.path)
				assert.Nil(t, err)
				assert.Equal(t, original, content)
				assert.False(t, c.resolvConf.written)
			})
		}
	}
}

func TestControllerUpdateEmptyDNSPreservesState(t *testing.T) {
	for _, dns := range []*userv1.DNS{nil, {}, {Servers: []string{}}} {
		c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
		assert.Nil(t, c.SetDNS())
		old := c.c.Connection.Dns
		servers := c.GetClusterDNSServers()
		current := c.getCurrentDNS()
		assert.Nil(t, c.UpdateDNS(dns))
		assert.Same(t, old, c.c.Connection.Dns)
		assert.Equal(t, servers, c.GetClusterDNSServers())
		assert.Equal(t, current, c.getCurrentDNS())
	}
}

func TestControllerDNSUpdateClearsUnusableCachedServers(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_V6)
	assert.Nil(t, c.SetDNS())
	assert.Equal(t, []string{"fd00::53"}, c.GetClusterDNSServers())
	dns := &userv1.DNS{Servers: []string{"100.64.0.53", "invalid"}}
	assert.Nil(t, c.UpdateDNS(dns))
	assert.Same(t, dns, c.c.Connection.Dns)
	assert.Empty(t, c.GetClusterDNSServers())
	assert.Nil(t, c.getCurrentDNS())
	c.c.Connection.Dns = nil
	assert.Nil(t, c.SetDNS())
	assert.Empty(t, c.GetClusterDNSServers())
	assert.Nil(t, c.getCurrentDNS())
}

func TestControllerDNSIgnoreDoesNotWriteHostConfig(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.isNetstack = false
	assert.Nil(t, c.SetDNS())
	assert.Equal(t, []string{"100.64.0.53", "fd00::53"}, c.GetClusterDNSServers())
	assert.Nil(t, c.UnsetDNS())
	_, err := os.Stat(c.resolvConf.path)
	assert.True(t, os.IsNotExist(err))
}

func TestControllerLocalDNSHostExtraction(t *testing.T) {
	for _, tt := range []struct {
		addr string
		host string
	}{
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1:1053", "127.0.0.1"},
		{"::1", "::1"},
		{"[::1]:1053", "::1"},
		{"invalid", ""},
	} {
		t.Run(tt.addr, func(t *testing.T) {
			c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
			c.c.Preferences.LocalDNS = &cliconfigv1.Connection_Preferences_LocalDNS{ListenAddress: tt.addr}
			assert.Equal(t, tt.host, c.getLocalDNSServerHost())
		})
	}
}

func TestResolvConfParserAndGenerator(t *testing.T) {
	input := "# comment\n; comment\n\n nameserver 100.64.0.53\nnameserver fd00::53\nnameserver invalid\nnameserver\nsearch local.example.com corp.example\noptions ndots:2 timeout:1\noptions attempts:3\nunknown value\n"
	cfg, err := parseResolvConf([]byte(input))
	assert.Nil(t, err)
	assert.Equal(t, &resolvConfOpts{
		Nameservers:   []string{"100.64.0.53", "fd00::53"},
		SearchDomains: []string{"local.example.com", "corp.example"},
		Options:       []string{"ndots:2", "timeout:1", "attempts:3"},
	}, cfg)
	out, err := generateResolvConf(cfg)
	assert.Nil(t, err)
	assert.Equal(t, "nameserver 100.64.0.53\nnameserver fd00::53\nsearch local.example.com corp.example\noptions ndots:2 timeout:1 attempts:3\n", out)
	parsed, err := parseResolvConf([]byte(out))
	assert.Nil(t, err)
	assert.Equal(t, cfg, parsed)
	_, err = generateResolvConf(nil)
	assert.NotNil(t, err)
	out, err = generateResolvConf(&resolvConfOpts{})
	assert.Nil(t, err)
	assert.Empty(t, out)
}

func TestControllerLocalDNSServerInitializationFailure(t *testing.T) {
	for _, container := range []bool{false, true} {
		c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
		c.c.Preferences.IgnoreDNS = false
		if container {
			c.c.Preferences.RuntimeMode = cliconfigv1.Connection_Preferences_CONTAINER
		}
		c.c.Preferences.LocalDNS = &cliconfigv1.Connection_Preferences_LocalDNS{
			IsEnabled: true, ListenAddress: "invalid",
		}
		c.startLocalDNSServer()
		assert.Nil(t, c.localDNSSrv)
		assert.False(t, c.c.Preferences.LocalDNS.IsEnabled)
		assert.Equal(t, container, c.c.Preferences.IgnoreDNS)
		assert.Equal(t, c.getClusterDNSServers(), c.getDNSServers())
	}
}

func TestControllerCloseStopsLocalDNSServer(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	reserved, err := net.ListenPacket("udp", "127.0.0.1:0")
	if !assert.Nil(t, err) {
		return
	}
	addr := reserved.LocalAddr().String()
	assert.Nil(t, reserved.Close())
	c.c.Preferences.LocalDNS = &cliconfigv1.Connection_Preferences_LocalDNS{
		IsEnabled: true, ListenAddress: addr,
	}
	t.Cleanup(func() { assert.Nil(t, c.Close()) })
	c.startLocalDNSServer()
	if !assert.NotNil(t, c.localDNSSrv) {
		return
	}
	assert.True(t, c.c.Preferences.LocalDNS.IsEnabled)
	assert.Nil(t, c.SetDNS())
	assert.Equal(t, []string{"127.0.0.1"}, c.getDNSServers())
	assert.Nil(t, c.Close())
	lis, err := net.ListenPacket("udp", addr)
	if assert.Nil(t, err) {
		assert.Nil(t, lis.Close())
	}
}

func TestControllerContainerDNSSetUpdateUnsetByIPMode(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestPlatformController(t, tt.mode)
			c.isNetstack = false
			c.c.Preferences.IgnoreDNS = false
			c.c.Preferences.RuntimeMode = cliconfigv1.Connection_Preferences_CONTAINER
			original := []byte("nameserver 192.0.2.53\nsearch corp.example\noptions ndots:2 timeout:1\n")
			assert.Nil(t, os.WriteFile(c.resolvConf.path, original, 0600))
			assert.Nil(t, c.SetDNS())
			content, err := os.ReadFile(c.resolvConf.path)
			assert.Nil(t, err)
			cfg, err := parseResolvConf(content)
			assert.Nil(t, err)
			assert.Equal(t, c.getClusterDNSServers(), cfg.Nameservers)
			assert.Equal(t, []string{"local.example.com", "corp.example"}, cfg.SearchDomains)
			assert.Equal(t, []string{"ndots:2", "timeout:1"}, cfg.Options)
			assert.True(t, c.resolvConf.written)

			assert.Nil(t, c.UpdateDNS(&userv1.DNS{Servers: []string{"100.64.0.54", "fd00::54"}}))
			content, err = os.ReadFile(c.resolvConf.path)
			assert.Nil(t, err)
			cfg, err = parseResolvConf(content)
			assert.Nil(t, err)
			assert.Equal(t, c.getClusterDNSServers(), cfg.Nameservers)
			assert.Equal(t, original, c.resolvConf.content)
			assert.Nil(t, c.UnsetDNS())
			assert.False(t, c.resolvConf.written)
			content, err = os.ReadFile(c.resolvConf.path)
			assert.Nil(t, err)
			assert.Equal(t, original, content)
			assert.Nil(t, c.UnsetDNS())
		})
	}
}
