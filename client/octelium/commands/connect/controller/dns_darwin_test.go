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
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/asaskevich/govalidator"
	pbconfig "github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestParseNetworkSetupValues(t *testing.T) {
	assert.Equal(t, []string{networkSetupEmpty}, parseNetworkSetupValues(
		[]byte("There aren't any DNS Servers set on Wi-Fi.\n"), "any dns servers", govalidator.IsIP))
	assert.Equal(t, []string{networkSetupEmpty}, parseNetworkSetupValues(
		[]byte("There aren't any Search Domains set on Wi-Fi.\n"), "any search domains",
		govalidator.IsDNSName))

	assert.Equal(t, []string{"8.8.8.8", "1.1.1.1"}, parseNetworkSetupValues(
		[]byte("8.8.8.8\n1.1.1.1\n"), "any dns servers", govalidator.IsIP))
	assert.Equal(t, []string{"fd00::1"}, parseNetworkSetupValues(
		[]byte("fd00::1"), "any dns servers", govalidator.IsIP))

	assert.Equal(t, []string{"corp.example.com", "example.com"}, parseNetworkSetupValues(
		[]byte("corp.example.com\nexample.com\n"), "any search domains", govalidator.IsDNSName))

	assert.Equal(t, []string{"8.8.8.8", "1.1.1.1"}, parseNetworkSetupValues(
		[]byte("  8.8.8.8  \n\n 1.1.1.1 \n"), "any dns servers", govalidator.IsIP))

	assert.Equal(t, []string{networkSetupEmpty}, parseNetworkSetupValues(
		[]byte("some unexpected output\n"), "any dns servers", govalidator.IsIP))
	assert.Equal(t, []string{networkSetupEmpty}, parseNetworkSetupValues(
		[]byte(""), "any dns servers", govalidator.IsIP))
}

func testNetworkSetupService(name string, servers ...string,
) *pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service {
	return &pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service{
		Name:       name,
		DnsServers: servers,
		DnsDomains: []string{networkSetupEmpty},
	}
}

func TestPrepareNetworkSetupConfigKeepsPristineOnUpdateDNS(t *testing.T) {
	prefs := &pbconfig.Connection_Preferences_MacOS{}
	netServices := []string{"Wi-Fi", "Ethernet"}

	pristine := map[string][]string{
		"Wi-Fi":    {"192.168.1.1"},
		"Ethernet": {"10.0.0.1", "10.0.0.2"},
	}

	var calls int
	getService := func(name string) (*pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service, error) {
		calls++
		return testNetworkSetupService(name, pristine[name]...), nil
	}

	cfg, err := prepareNetworkSetupConfig(prefs, netServices, getService)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(cfg.Services))
	assert.Equal(t, 2, calls)

	getService = func(name string) (*pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service, error) {
		calls++
		return testNetworkSetupService(name, "100.64.0.53"), nil
	}

	for i := 0; i < 3; i++ {
		cfg, err = prepareNetworkSetupConfig(prefs, netServices, getService)
		assert.Nil(t, err)
	}

	assert.Equal(t, 2, calls)
	assert.Equal(t, 2, len(cfg.Services))
	assert.Same(t, prefs.NetworkSetupConfig, cfg)

	for _, svc := range cfg.Services {
		assert.Equal(t, pristine[svc.Name], svc.DnsServers)
	}
}

func TestPrepareNetworkSetupConfigRecordsNewService(t *testing.T) {
	prefs := &pbconfig.Connection_Preferences_MacOS{}

	getService := func(name string) (*pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service, error) {
		return testNetworkSetupService(name, "192.168.1.1"), nil
	}

	cfg, err := prepareNetworkSetupConfig(prefs, []string{"Wi-Fi"}, getService)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(cfg.Services))

	cfg, err = prepareNetworkSetupConfig(prefs, []string{"Wi-Fi", "USB 10/100 LAN"}, getService)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(cfg.Services))
	assert.NotNil(t, getNetworkSetupService(cfg, "USB 10/100 LAN"))
	assert.NotNil(t, getNetworkSetupService(cfg, "Wi-Fi"))
}

func TestPrepareNetworkSetupConfigReadError(t *testing.T) {
	prefs := &pbconfig.Connection_Preferences_MacOS{}

	getService := func(name string) (*pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service, error) {
		return nil, errors.Errorf("networksetup failed")
	}

	_, err := prepareNetworkSetupConfig(prefs, []string{"Wi-Fi"}, getService)
	assert.NotNil(t, err)

	assert.Equal(t, 0, len(prefs.NetworkSetupConfig.Services))
}

func TestGetNetworkSetupService(t *testing.T) {
	assert.Nil(t, getNetworkSetupService(nil, "Wi-Fi"))

	cfg := &pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig{
		Services: []*pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service{
			testNetworkSetupService("Wi-Fi", "192.168.1.1"),
		},
	}

	assert.NotNil(t, getNetworkSetupService(cfg, "Wi-Fi"))
	assert.Nil(t, getNetworkSetupService(cfg, "Ethernet"))
}

func TestGetNetworkSetupSearchDomains(t *testing.T) {
	svcCfg := func(domains ...string) *pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service {
		return &pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service{
			Name:       "Wi-Fi",
			DnsServers: []string{networkSetupEmpty},
			DnsDomains: domains,
		}
	}

	assert.Equal(t, []string{"local.example.com", "corp.lan"},
		getNetworkSetupSearchDomains([]string{"local.example.com"}, svcCfg("corp.lan")))

	assert.Equal(t, []string{"local.example.com"},
		getNetworkSetupSearchDomains([]string{"local.example.com"}, svcCfg(networkSetupEmpty)))

	assert.Equal(t, []string{"local.example.com"},
		getNetworkSetupSearchDomains([]string{"local.example.com"}, nil))

	assert.Equal(t, []string{"local.example.com", "corp.lan"},
		getNetworkSetupSearchDomains([]string{"local.example.com"},
			svcCfg("corp.lan", "local.example.com", "  corp.lan  ", "")))

	assert.Nil(t, getNetworkSetupSearchDomains(nil, nil))
	assert.Nil(t, getNetworkSetupSearchDomains(nil, svcCfg(networkSetupEmpty)))
}

func TestDarwinScutilDNSByIPMode(t *testing.T) {
	for _, tt := range testControllerIPModes {
		t.Run(tt.name, func(t *testing.T) {
			commands := newTestOSCommands(t, map[string]string{
				"scutil": "/bin/cat > \"$OCTELIUM_TEST_COMMAND_LOG.stdin\"",
			})
			c := newTestPlatformController(t, tt.mode)
			assert.Nil(t, c.doSetDNSScutil())
			input, err := os.ReadFile(commands.log + ".stdin")
			assert.Nil(t, err)
			assert.Equal(t, fmt.Sprintf("\nopen\nd.init\nd.add ServerAddresses * %s\nd.add SearchDomains * local.example.com\nd.add SupplementalMatchDomains * local.example.com\nd.add InterfaceName octelium-test\nset State:/Network/Service/octelium-example-com/DNS\nquit\n", strings.Join(c.getClusterDNSServers(), " ")), string(input))
			assert.Equal(t, pbconfig.Connection_Preferences_MacOS_SCUTIL, c.c.Preferences.MacosPrefs.DnsMode)
			assert.Nil(t, c.doUnsetDNSScutil())
			input, err = os.ReadFile(commands.log + ".stdin")
			assert.Nil(t, err)
			assert.Equal(t, "\nopen\nremove State:/Network/Service/octelium-example-com/DNS\nquit\n", string(input))
			assert.Len(t, commands.calls(t), 2)
		})
	}
}

func TestDarwinScutilKeyAndCommandFailure(t *testing.T) {
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.c.Info.Cluster.Domain = "Example.COM/cluster"
	assert.Equal(t, "State:/Network/Service/octelium-Example-COM-cluster/DNS", c.getScutilServiceKey())
	c.c.Info = nil
	assert.Equal(t, "State:/Network/Service/octelium-default/DNS", c.getScutilServiceKey())
	c = newTestPlatformController(t, userv1.ConnectionState_BOTH)
	newTestOSCommands(t, map[string]string{"scutil": "printf 'scutil failure'; exit 1"})
	err := c.doSetDNSScutil()
	if assert.NotNil(t, err) {
		assert.Contains(t, err.Error(), "scutil failure")
	}
	assert.Equal(t, pbconfig.Connection_Preferences_MacOS_RESOLVCONF, c.c.Preferences.MacosPrefs.DnsMode)
	assert.NotNil(t, c.doUnsetDNSScutil())
}

const testDarwinNetworkSetup = `case "$1" in
-listallnetworkservices) printf 'An asterisk (*) denotes a disabled service.\nWi-Fi\n*Disabled\nEthernet\n' ;;
-getdnsservers) printf '192.0.2.53\n' ;;
-getsearchdomains) printf 'corp.example\n' ;;
esac`

func TestDarwinNetworkSetupSavesAndRestoresDNS(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{"networksetup": testDarwinNetworkSetup})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	assert.Nil(t, c.doSetDNSNetworkSetup())
	assert.True(t, c.dnsConfigSaved)
	assert.Equal(t, pbconfig.Connection_Preferences_MacOS_NETWORKSETUP, c.c.Preferences.MacosPrefs.DnsMode)
	c.c.Connection.Dns.Servers = []string{"fd00::54"}
	assert.Nil(t, c.doSetDNSNetworkSetup())
	assert.Nil(t, c.doUnsetDNS())
	assert.False(t, c.dnsConfigSaved)
	calls := commands.calls(t)
	assert.Equal(t, [][]string{
		{"networksetup", "-setdnsservers", "Wi-Fi", "192.0.2.53"},
		{"networksetup", "-setsearchdomains", "Wi-Fi", "corp.example"},
		{"networksetup", "-setdnsservers", "Ethernet", "192.0.2.53"},
		{"networksetup", "-setsearchdomains", "Ethernet", "corp.example"},
	}, calls[len(calls)-4:])
	var reads int
	for _, call := range calls {
		assert.NotContains(t, call, "*Disabled")
		if call[1] == "-getdnsservers" {
			reads++
		}
	}
	assert.Equal(t, 2, reads)
	before := len(calls)
	assert.Nil(t, c.doUnSetDNSNetworkSetup())
	assert.Len(t, commands.calls(t), before)
}

func TestDarwinNetworkSetupRestoreContinuesAndCanRetry(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{
		"networksetup": "if [ \"$2\" = Wi-Fi ]; then printf 'restore failure'; exit 1; fi",
	})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.dnsConfigSaved = true
	c.c.Preferences.MacosPrefs.NetworkSetupConfig = &pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig{
		Services: []*pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service{
			{Name: "Wi-Fi", DnsServers: []string{"Empty"}, DnsDomains: []string{"Empty"}},
			{Name: "Ethernet", DnsServers: []string{"192.0.2.53"}, DnsDomains: []string{"corp.example"}},
		},
	}
	assert.NotNil(t, c.doUnSetDNSNetworkSetup())
	assert.True(t, c.dnsConfigSaved)
	assert.Len(t, commands.calls(t), 3)
	assert.Equal(t, []string{"networksetup", "-setsearchdomains", "Ethernet", "corp.example"}, commands.calls(t)[2])
	assert.Nil(t, os.WriteFile(commands.dir+"/networksetup", []byte("#!/bin/sh\nexit 0\n"), 0755))
	assert.Nil(t, c.doUnSetDNSNetworkSetup())
	assert.False(t, c.dnsConfigSaved)
}

func TestDarwinDNSFallbackToResolvConf(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{
		"scutil": "exit 1", "networksetup": "exit 1",
	})
	c := newTestPlatformController(t, userv1.ConnectionState_V6)
	original := []byte("nameserver 192.0.2.53\n")
	assert.Nil(t, os.WriteFile(c.resolvConf.path, original, 0600))
	assert.Nil(t, c.doSetDNS())
	assert.Equal(t, pbconfig.Connection_Preferences_MacOS_RESOLVCONF, c.c.Preferences.MacosPrefs.DnsMode)
	content, err := os.ReadFile(c.resolvConf.path)
	assert.Nil(t, err)
	assert.Contains(t, string(content), "nameserver fd00::53\n")
	assert.NotContains(t, string(content), "nameserver 100.64.0.53")
	assert.Len(t, commands.calls(t), 2)
	assert.Nil(t, c.doUnsetDNS())
	content, err = os.ReadFile(c.resolvConf.path)
	assert.Nil(t, err)
	assert.Equal(t, original, content)
}

func TestDarwinFullDNSUsesNetworkSetup(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{
		"scutil": "exit 1", "networksetup": testDarwinNetworkSetup,
	})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	c.c.Preferences.FullDNS = true
	assert.Nil(t, c.doSetDNS())
	assert.Equal(t, pbconfig.Connection_Preferences_MacOS_NETWORKSETUP, c.c.Preferences.MacosPrefs.DnsMode)
	for _, call := range commands.calls(t) {
		assert.Equal(t, "networksetup", call[0])
	}
	assert.Nil(t, c.doUnsetDNS())
}

func TestDarwinSearchDomainFailureKeepsScutilResolverForCleanup(t *testing.T) {
	commands := newTestOSCommands(t, map[string]string{
		"scutil": "/bin/cat > /dev/null", "networksetup": "printf 'network services unavailable'; exit 1",
	})
	c := newTestPlatformController(t, userv1.ConnectionState_BOTH)
	assert.NoError(t, c.doSetDNS())
	assert.Equal(t, pbconfig.Connection_Preferences_MacOS_SCUTIL, c.c.Preferences.MacosPrefs.DnsMode)
	assert.NoError(t, c.doUnsetDNS())
	assert.Equal(t, [][]string{{"scutil"}, {"networksetup", "-listallnetworkservices"}, {"scutil"}}, commands.calls(t))
}

func TestDarwinNetworkSetupPartialReadCanBeRetried(t *testing.T) {
	prefs := &pbconfig.Connection_Preferences_MacOS{}
	var failed bool
	read := func(name string) (*pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service, error) {
		if name == "Ethernet" && !failed {
			failed = true
			return nil, errors.New("interface disappeared")
		}
		return testNetworkSetupService(name, "192.0.2.53"), nil
	}
	_, err := prepareNetworkSetupConfig(prefs, []string{"Wi-Fi", "Ethernet"}, read)
	assert.Error(t, err)
	assert.Len(t, prefs.NetworkSetupConfig.Services, 1)
	cfg, err := prepareNetworkSetupConfig(prefs, []string{"Wi-Fi", "Ethernet"}, read)
	assert.NoError(t, err)
	assert.Len(t, cfg.Services, 2)
	assert.Equal(t, []string{"192.0.2.53"}, getNetworkSetupService(cfg, "Wi-Fi").DnsServers)
}
