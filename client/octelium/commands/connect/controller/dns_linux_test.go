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
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/stretchr/testify/assert"
)

func TestGetResolvctlArgs(t *testing.T) {
	dnsServers := []string{"100.64.0.53", "fd00::53"}
	searchDomains := []string{"local.example.com"}

	dnsArgs, domainArgs := getResolvctlArgs(true, "octelium0", dnsServers, searchDomains)
	assert.Equal(t, []string{"dns", "octelium0", "100.64.0.53", "fd00::53"}, dnsArgs)
	assert.Equal(t, []string{"domain", "octelium0", "local.example.com"}, domainArgs)

	dnsArgs, domainArgs = getResolvctlArgs(false, "octelium0", dnsServers, searchDomains)
	assert.Equal(t, []string{
		"--interface", "octelium0",
		"--set-dns", "100.64.0.53",
		"--set-dns", "fd00::53",
	}, dnsArgs)
	assert.Equal(t, []string{
		"--interface", "octelium0",
		"--set-domain", "local.example.com",
	}, domainArgs)
}

func TestGetResolvctlArgsWithMultipleSearchDomains(t *testing.T) {
	searchDomains := []string{"local.example.com", "svc.example.com"}

	_, domainArgs := getResolvctlArgs(true, "octelium0", []string{"100.64.0.53"}, searchDomains)
	assert.Equal(t,
		[]string{"domain", "octelium0", "local.example.com", "svc.example.com"}, domainArgs)

	_, domainArgs = getResolvctlArgs(false, "octelium0", []string{"100.64.0.53"}, searchDomains)
	assert.Equal(t, []string{
		"--interface", "octelium0",
		"--set-domain", "local.example.com",
		"--set-domain", "svc.example.com",
	}, domainArgs)
}

func TestGetResolvctlDomains(t *testing.T) {
	c, _ := newTestResolvConfCtl(t, []string{"100.64.0.53"})

	assert.Equal(t, []string{"local.example.com"}, c.getResolvctlDomains())

	c.c.Preferences.FullDNS = true
	assert.Equal(t, []string{"local.example.com", "~."}, c.getResolvctlDomains())
}

func TestGetResolvctlArgsInFullDNSMode(t *testing.T) {
	c, _ := newTestResolvConfCtl(t, []string{"100.64.0.53"})
	c.c.Preferences.FullDNS = true

	dnsArgs, domainArgs := getResolvctlArgs(true, "octelium0",
		[]string{"127.0.0.100"}, c.getResolvctlDomains())
	assert.Equal(t, []string{"dns", "octelium0", "127.0.0.100"}, dnsArgs)
	assert.Equal(t, []string{"domain", "octelium0", "local.example.com", "~."}, domainArgs)

	dnsArgs, domainArgs = getResolvctlArgs(false, "octelium0",
		[]string{"127.0.0.100"}, c.getResolvctlDomains())
	assert.Equal(t, []string{
		"--interface", "octelium0",
		"--set-dns", "127.0.0.100",
	}, dnsArgs)
	assert.Equal(t, []string{
		"--interface", "octelium0",
		"--set-domain", "local.example.com",
		"--set-domain", "~.",
	}, domainArgs)
}

func TestGetResolvctlDefaultRouteArgs(t *testing.T) {
	assert.Equal(t, []string{"default-route", "octelium0", "no"},
		getResolvctlDefaultRouteArgs("octelium0", false))
	assert.Equal(t, []string{"default-route", "octelium0", "yes"},
		getResolvctlDefaultRouteArgs("octelium0", true))
}

func TestGetResolvctlRevertArgs(t *testing.T) {
	assert.Equal(t, []string{"revert", "octelium0"},
		getResolvctlRevertArgs(true, "octelium0"))
	assert.Equal(t, []string{"--interface", "octelium0", "--revert"},
		getResolvctlRevertArgs(false, "octelium0"))
}

func TestLinuxResolverCommandsByIPMode(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			commands := newTestOSCommands(t, map[string]string{"resolvectl": "exit 0"})
			c := newTestPlatformController(t, tt.mode)
			c.isNetstack = false
			c.c.Preferences.IgnoreDNS = false
			assert.Nil(t, c.doSetDNSResolvctl())
			wantDNS := append([]string{"resolvectl", "dns", "octelium-test"}, c.getClusterDNSServers()...)
			assert.Equal(t, [][]string{
				wantDNS,
				{"resolvectl", "domain", "octelium-test", "local.example.com"},
				{"resolvectl", "default-route", "octelium-test", "no"},
			}, commands.calls(t))
			assert.Equal(t, cliconfigv1.Connection_Preferences_Linux_RESOLVECTL_BIN, c.c.Preferences.LinuxPrefs.DnsMode)
			assert.Nil(t, c.doUnsetDNS())
			assert.Equal(t, []string{"resolvectl", "revert", "octelium-test"}, commands.calls(t)[3])
		})
	}
}

func TestLinuxLegacyResolverCommands(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{"systemd-resolve": "exit 0"})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.c.Preferences.FullDNS = true
	assert.Nil(t, c.doSetDNSResolvctl())
	assert.Nil(t, c.doUnsetDNSResolvctl())
	assert.Equal(t, [][]string{
		{"systemd-resolve", "--interface", "octelium-test", "--set-dns", "100.64.0.53", "--set-dns", "fd00::53"},
		{"systemd-resolve", "--interface", "octelium-test", "--set-domain", "local.example.com", "--set-domain", "~."},
		{"systemd-resolve", "--interface", "octelium-test", "--revert"},
	}, commands.calls(t))
}

func TestLinuxResolverPartialFailureRevertsConfig(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{
		"resolvectl": "if [ \"$1\" = domain ]; then printf 'domain failure'; exit 1; fi",
	})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	assert.NotNil(t, c.doSetDNSResolvctl())
	assert.Equal(t, cliconfigv1.Connection_Preferences_Linux_NO_DNS, c.c.Preferences.LinuxPrefs.DnsMode)
	assert.Equal(t, [][]string{
		{"resolvectl", "dns", "octelium-test", "100.64.0.53", "fd00::53"},
		{"resolvectl", "domain", "octelium-test", "local.example.com"},
		{"resolvectl", "revert", "octelium-test"},
	}, commands.calls(t))
}

func TestLinuxResolverDNSFailureStopsBeforeDomains(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{"resolvectl": "exit 1"})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	assert.NotNil(t, c.doSetDNSResolvctl())
	assert.Equal(t, [][]string{{"resolvectl", "dns", "octelium-test", "100.64.0.53", "fd00::53"}}, commands.calls(t))
	assert.Equal(t, cliconfigv1.Connection_Preferences_Linux_NO_DNS, c.c.Preferences.LinuxPrefs.DnsMode)
	err := c.doUnsetDNSResolvctl()
	if assert.NotNil(t, err) {
		assert.Contains(t, err.Error(), "Could not revert")
	}
}

func TestLinuxResolverFullDNSDefaultRouteFailureIsNonFatal(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{
		"resolvectl": "if [ \"$1\" = default-route ]; then exit 1; fi",
	})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.c.Preferences.FullDNS = true
	assert.Nil(t, c.doSetDNSResolvctl())
	assert.Equal(t, []string{"resolvectl", "domain", "octelium-test", "local.example.com", "~."}, commands.calls(t)[1])
	assert.Equal(t, []string{"resolvectl", "default-route", "octelium-test", "yes"}, commands.calls(t)[2])
	assert.Equal(t, cliconfigv1.Connection_Preferences_Linux_RESOLVECTL_BIN, c.c.Preferences.LinuxPrefs.DnsMode)
}

func TestLinuxResolverMissingToolsAndServers(t *testing.T) {
	commands := newTestOSCommands(t, nil)
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	assert.NotNil(t, c.doSetDNSResolvctl())
	assert.NotNil(t, c.doUnsetDNSResolvctl())
	assert.Nil(t, os.WriteFile(commands.dir+"/resolvectl", []byte("#!/bin/sh\nexit 0\n"), 0755))
	c.c.Connection.Dns = nil
	assert.EqualError(t, c.doSetDNSResolvctl(), "Could not find any DNS server to set")
	assert.Empty(t, commands.calls(t))
}

func TestLinuxDNSFallbackAndRestore(t *testing.T) {
	for _, active := range []bool{false, true} {
		name := "inactive"
		body := "exit 1"
		if active {
			name = "active-but-resolver-fails"
			body = "exit 0"
		}
		t.Run(name, func(t *testing.T) {
			commands := newTestOSCommands(t, map[string]string{"systemctl": body, "resolvectl": "exit 1"})
			c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
			original := []byte("nameserver 192.0.2.53\nsearch corp.example\n")
			assert.Nil(t, os.WriteFile(c.resolvConf.path, original, 0600))
			assert.Nil(t, c.doSetDNS())
			assert.Equal(t, cliconfigv1.Connection_Preferences_Linux_RESOLVCONF, c.c.Preferences.LinuxPrefs.DnsMode)
			content, err := os.ReadFile(c.resolvConf.path)
			assert.Nil(t, err)
			assert.Contains(t, string(content), "nameserver 100.64.0.53\nnameserver fd00::53\n")
			assert.Equal(t, []string{"systemctl", "is-active", "--quiet", "systemd-resolved"}, commands.calls(t)[0])
			assert.Nil(t, c.doUnsetDNS())
			content, err = os.ReadFile(c.resolvConf.path)
			assert.Nil(t, err)
			assert.Equal(t, original, content)
		})
	}
}
