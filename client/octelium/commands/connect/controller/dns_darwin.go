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
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/asaskevich/govalidator"
	pbconfig "github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (c *Controller) doSetDNS() error {

	if err := c.saveResolvConf(); err != nil {
		zap.L().Debug("Could not save the current resolv.conf", zap.Error(err))
	}

	if c.isFullDNS() {
		zap.L().Debug("Full DNS mode. Setting DNS via networksetup")
		if err := c.doSetDNSNetworkSetup(); err != nil {
			zap.L().Warn("Could not doSetDNSNetworkSetup", zap.Error(err))
			return c.doSetDNSResolvConf()
		}

		return nil
	}

	if err := c.doSetDNSScutil(); err != nil {
		zap.L().Warn("Could not doSetDNSScutil", zap.Error(err))
		if err := c.doSetDNSNetworkSetup(); err != nil {
			zap.L().Warn("Could not doSetDNSNetworkSetup", zap.Error(err))
			return c.doSetDNSResolvConf()
		}

		return nil
	}

	if err := c.doSetDNSSearchDomains(); err != nil {
		zap.L().Warn("Could not set the DNS search domains via networksetup", zap.Error(err))
	}

	return nil
}

func (c *Controller) doSetDNSSearchDomains() error {
	zap.L().Debug("Setting the DNS search domains via networksetup")

	netServices, err := getNetworkSetupServices()
	if err != nil {
		return err
	}

	networkSetupConfig, err := prepareNetworkSetupConfig(c.c.Preferences.MacosPrefs,
		netServices, getNetworkSetupServiceConfig)
	if err != nil {
		return err
	}

	c.dnsConfigSaved = true

	var retErr error
	for _, svc := range netServices {
		svcCfg := getNetworkSetupService(networkSetupConfig, svc)
		if svcCfg == nil {
			zap.L().Debug("Could not find the saved config of the network service. Skipping",
				zap.String("svc", svc))
			continue
		}

		domains := getNetworkSetupSearchDomains(c.getDNSSearchDomains(), svcCfg)

		if err := setNetworkSetupSearchDomains(svc, domains); err != nil {
			zap.L().Warn("Could not set the search domains of a network service",
				zap.String("svc", svc), zap.Error(err))
			retErr = err
		}
	}

	return retErr
}

func getNetworkSetupSearchDomains(domains []string,
	svcCfg *pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service) []string {

	var ret []string

	appendDomain := func(domain string) {
		domain = strings.TrimSpace(domain)
		if domain == "" || domain == networkSetupEmpty || slices.Contains(ret, domain) {
			return
		}
		ret = append(ret, domain)
	}

	for _, domain := range domains {
		appendDomain(domain)
	}

	if svcCfg == nil {
		return ret
	}

	for _, domain := range svcCfg.DnsDomains {
		appendDomain(domain)
	}

	return ret
}

func (c *Controller) doSetDNSNetworkSetup() error {
	zap.L().Debug("Setting DNS via networksetup")
	netServices, err := getNetworkSetupServices()
	if err != nil {
		return err
	}

	zap.L().Debug("Found network services", zap.Strings("svcList", netServices))

	networkSetupConfig, err := prepareNetworkSetupConfig(c.c.Preferences.MacosPrefs,
		netServices, getNetworkSetupServiceConfig)
	if err != nil {
		return err
	}

	zap.L().Debug("Stored networksetup config", zap.Any("cfg", networkSetupConfig))

	c.dnsConfigSaved = true

	for _, svc := range netServices {
		if err := setNetworkSetupDNSServers(svc, c.getDNSServers(), c.getDNSSearchDomains()); err != nil {
			return err
		}
	}

	c.c.Preferences.MacosPrefs.DnsMode = pbconfig.Connection_Preferences_MacOS_NETWORKSETUP

	return nil
}

const networkSetupEmpty = "Empty"

func parseNetworkSetupValues(out []byte, emptyMsg string, isValid func(string) bool) []string {
	lower := strings.ToLower(string(out))
	if strings.Contains(lower, "there aren") || strings.Contains(lower, emptyMsg) {
		return []string{networkSetupEmpty}
	}

	var ret []string
	for _, line := range strings.Split(string(out), "\n") {
		if line := strings.TrimSpace(line); line != "" {
			ret = append(ret, line)
		}
	}

	if len(ret) == 0 || !isValid(ret[0]) {
		return []string{networkSetupEmpty}
	}

	return ret
}

func getNetworkSetupService(cfg *pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig,
	name string) *pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service {
	if cfg == nil {
		return nil
	}

	for _, svc := range cfg.Services {
		if svc.Name == name {
			return svc
		}
	}

	return nil
}

func prepareNetworkSetupConfig(prefs *pbconfig.Connection_Preferences_MacOS, netServices []string,
	getService func(string) (*pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service, error),
) (*pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig, error) {

	if prefs.NetworkSetupConfig == nil {
		prefs.NetworkSetupConfig = &pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig{}
	}
	cfg := prefs.NetworkSetupConfig

	for _, name := range netServices {
		if getNetworkSetupService(cfg, name) != nil {
			continue
		}

		svc, err := getService(name)
		if err != nil {
			return nil, err
		}
		if svc == nil {
			continue
		}

		cfg.Services = append(cfg.Services, svc)
	}

	return cfg, nil
}

func getNetworkSetupServiceConfig(svc string) (*pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service, error) {
	outServers, err := runOSCmdOutput("networksetup", "-getdnsservers", svc)
	if err != nil {
		return nil, errors.Errorf("Could not get the DNS servers of %s: %+v. %s",
			svc, err, string(outServers))
	}

	zap.L().Debug("Got DNS servers", zap.String("svc", svc), zap.String("servers", string(outServers)))

	outDomains, err := runOSCmdOutput("networksetup", "-getsearchdomains", svc)
	if err != nil {
		return nil, errors.Errorf("Could not get the search domains of %s: %+v. %s",
			svc, err, string(outDomains))
	}

	zap.L().Debug("Got search domains", zap.String("svc", svc), zap.String("domains", string(outDomains)))

	return &pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service{
		Name:       svc,
		DnsServers: parseNetworkSetupValues(outServers, "any dns servers", govalidator.IsIP),
		DnsDomains: parseNetworkSetupValues(outDomains, "any search domains", govalidator.IsDNSName),
	}, nil
}

func (c *Controller) doSetDNSResolvConf() error {

	if err := c.setResolvConf(); err != nil {
		return err
	}

	c.c.Preferences.MacosPrefs.DnsMode = pbconfig.Connection_Preferences_MacOS_RESOLVCONF

	return nil
}

func (c *Controller) doUnsetDNS() error {

	zap.L().Debug("Unsetting DNS")
	if c.c.Preferences.MacosPrefs == nil {
		return nil
	}

	var retErr error

	switch c.c.Preferences.MacosPrefs.DnsMode {
	case pbconfig.Connection_Preferences_MacOS_SCUTIL:
		if err := c.doUnsetDNSScutil(); err != nil {
			zap.L().Warn("Could not unset the DNS via scutil", zap.Error(err))
			retErr = err
		}
	case pbconfig.Connection_Preferences_MacOS_RESOLVCONF:
		if err := c.unsetResolvConf(); err != nil {
			zap.L().Warn("Could not restore resolv.conf", zap.Error(err))
			retErr = err
		}
	default:
	}

	if err := c.doUnSetDNSNetworkSetup(); err != nil {
		retErr = err
	}

	return retErr
}

func getNetworkSetupServices() ([]string, error) {
	out, err := runOSCmdOutput("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, errors.Errorf("Could not get list network services: %+v. %s", err, string(out))
	}

	services := []string{}

	for _, v := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
		if bytes.Contains(v, []byte("*")) {
			continue
		}

		svc := string(bytes.TrimSpace(v))
		services = append(services, svc)
	}

	if len(services) == 0 {
		return nil, errors.Errorf("Could not find any network services")
	}

	return services, nil
}

func setNetworkSetupDNSServers(svc string, dnsServers []string, networkDomains []string) error {

	cmd := []string{"-setdnsservers", svc}
	cmd = append(cmd, dnsServers...)
	if o, err := runOSCmdOutput("networksetup", cmd...); err != nil {
		return errors.Errorf("Could not set dns servers: %s. %+v", string(o), err)
	}

	return setNetworkSetupSearchDomains(svc, networkDomains)
}

func setNetworkSetupSearchDomains(svc string, networkDomains []string) error {
	if len(networkDomains) == 0 {
		return nil
	}

	cmd := []string{"-setsearchdomains", svc}
	cmd = append(cmd, networkDomains...)
	if o, err := runOSCmdOutput("networksetup", cmd...); err != nil {
		return errors.Errorf("Could not set dns search domains: %s. %+v", string(o), err)
	}

	return nil
}

func (c *Controller) doUnSetDNSNetworkSetup() error {
	cfg := c.c.Preferences.MacosPrefs.NetworkSetupConfig
	if cfg == nil || len(cfg.Services) == 0 {
		return nil
	}

	zap.L().Debug("Unsetting DNS using networksetup")

	var retErr error
	for _, svc := range cfg.Services {
		if err := setNetworkSetupDNSServers(svc.Name, svc.DnsServers, svc.DnsDomains); err != nil {
			zap.L().Warn("Could not restore the DNS config of a network service",
				zap.String("svc", svc.Name), zap.Error(err))
			retErr = err
		}
	}

	return retErr
}

func (c *Controller) getScutilServiceKey() string {
	domain := "default"
	if c.c.Info != nil && c.c.Info.Cluster != nil && c.c.Info.Cluster.Domain != "" {
		domain = strings.Map(func(r rune) rune {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
				return r
			default:
				return '-'
			}
		}, c.c.Info.Cluster.Domain)
	}

	return fmt.Sprintf("State:/Network/Service/octelium-%s/DNS", domain)
}

func (c *Controller) doSetDNSScutil() error {
	arg := fmt.Sprintf(`
open
d.init
d.add ServerAddresses * %s
d.add SearchDomains * %s
d.add SupplementalMatchDomains * %s
d.add InterfaceName %s
set %s
quit
`, strings.Join(c.getDNSServers(), " "),
		strings.Join(c.getDNSSearchDomains(), " "),
		strings.Join(c.getDNSSearchDomains(), " "),
		c.c.Preferences.DeviceName,
		c.getScutilServiceKey())

	if err := c.doRunScutil(arg); err != nil {
		return err
	}

	c.c.Preferences.MacosPrefs.DnsMode = pbconfig.Connection_Preferences_MacOS_SCUTIL
	return nil
}

func (c *Controller) doUnsetDNSScutil() error {
	arg := fmt.Sprintf(`
open
remove %s
quit
`, c.getScutilServiceKey())

	return c.doRunScutil(arg)
}

func (c *Controller) doRunScutil(arg string) error {
	out, err := runOSCmdInput(arg, "scutil")
	if err != nil {
		return errors.Errorf("Could not run scutil command: %s: %+v. %s", arg, err, string(out))
	}

	return nil
}
