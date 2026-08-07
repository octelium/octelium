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
	"testing"

	"github.com/asaskevich/govalidator"
	pbconfig "github.com/octelium/octelium/apis/client/cliconfigv1"
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
