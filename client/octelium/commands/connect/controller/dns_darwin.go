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
	"os"
	"os/exec"
	"strings"

	"github.com/asaskevich/govalidator"
	pbconfig "github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (c *Controller) doSetDNS() error {

	if err := c.doSetDNSScutil(); err != nil {
		zap.L().Warn("Could not doSetDNSScutil", zap.Error(err))
		if err := c.doSetDNSNetworkSetup(); err != nil {
			zap.L().Warn("Could not doSetDNSNetworkSetup", zap.Error(err))
			return c.doSetDNSResolvConf()
		}
	}

	return nil
}

func (c *Controller) doSetDNSNetworkSetup() error {
	zap.L().Debug("Setting DNS via networksetup")
	netServices, err := getNetworkSetupServices()
	if err != nil {
		return err
	}

	zap.L().Debug("Found network services", zap.Strings("svcList", netServices))

	c.c.Preferences.MacosPrefs.NetworkSetupConfig = &pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig{}
	networkSetupConfig := c.c.Preferences.MacosPrefs.NetworkSetupConfig

	if !c.dnsConfigSaved {
		for _, svc := range netServices {
			outServers, err := exec.Command("networksetup", "-getdnsservers", svc).CombinedOutput()
			if err != nil {
				return errors.Errorf("Could not get list network services: %+v. %s", err, string(outServers))
			}

			zap.L().Debug("Got search domains", zap.String("svc", svc), zap.String("domains", string(outServers)))

			outDomains, err := exec.Command("networksetup", "-getsearchdomains", svc).CombinedOutput()
			if err != nil {
				return errors.Errorf("Could not get list network services: %+v. %s", err, string(outServers))
			}

			zap.L().Debug("Got search domains", zap.String("svc", svc), zap.String("domains", string(outDomains)))

			var dnsServers []string
			var dnsDomains []string
			if strings.Contains(strings.ToLower(string(outServers)), `there aren`) ||
				strings.Contains(strings.ToLower(string(outServers)), `any dns servers`) {
				dnsServers = []string{"Empty"}
			} else {
				dnsServers = strings.Split(strings.TrimSpace(string(outServers)), "\n")
				if len(dnsServers) == 0 || !govalidator.IsIP(dnsServers[0]) {
					dnsServers = []string{"Empty"}
				}
			}

			if strings.Contains(strings.ToLower(string(outDomains)), `there aren`) ||
				strings.Contains(strings.ToLower(string(outDomains)), `any search domains`) {
				dnsDomains = []string{"Empty"}
			} else {
				dnsDomains = strings.Split(strings.TrimSpace(string(outDomains)), "\n")
				if len(dnsDomains) == 0 || !govalidator.IsDNSName(dnsDomains[0]) {
					dnsDomains = []string{"Empty"}
				}
			}

			networkSetupConfig.Services = append(networkSetupConfig.Services, &pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig_Service{
				Name:       svc,
				DnsServers: dnsServers,
				DnsDomains: dnsDomains,
			})
		}

		zap.L().Debug("Stored networksetup config", zap.Any("cfg", networkSetupConfig))

		c.dnsConfigSaved = true
	}

	for _, svc := range netServices {
		if err := setNetworkSetupDNSServers(svc, c.getDNSServers(), c.getDNSSearchDomains()); err != nil {
			return err
		}
	}

	c.c.Preferences.MacosPrefs.DnsMode = pbconfig.Connection_Preferences_MacOS_NETWORKSETUP

	return nil
}

func (c *Controller) doSetDNSResolvConf() error {

	if !c.dnsConfigSaved {
		oldResolvConf, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
		c.c.Preferences.MacosPrefs.ResolvConf = oldResolvConf
		c.dnsConfigSaved = true
	}

	resolvConfOpts, err := parseResolvConf(c.c.Preferences.MacosPrefs.ResolvConf)
	if err != nil {
		zap.L().Warn("Could not parse resolv.conf", zap.Error(err))
	}

	if err := c._doSetDNSResolvConf(resolvConfOpts); err != nil {
		return err
	}

	return nil
}

func (c *Controller) doUnsetDNS() error {

	zap.L().Debug("Unsetting DNS")
	if c.c.Preferences.MacosPrefs == nil {
		return nil
	}

	switch c.c.Preferences.MacosPrefs.DnsMode {
	case pbconfig.Connection_Preferences_MacOS_SCUTIL:
		if err := c.doUnsetDNSScutil(); err != nil {
			return err
		}
	case pbconfig.Connection_Preferences_MacOS_RESOLVCONF:
		if len(c.c.Preferences.MacosPrefs.ResolvConf) > 0 {
			if err := os.WriteFile("/etc/resolv.conf", c.c.Preferences.MacosPrefs.ResolvConf, 0644); err != nil {
				return err
			}
		}
	case pbconfig.Connection_Preferences_MacOS_NETWORKSETUP:
		if err := c.doUnSetDNSNetworkSetup(); err != nil {
			return err
		}
	default:
	}
	return nil
}

func getNetworkSetupServices() ([]string, error) {
	c := exec.Command("networksetup", "-listallnetworkservices")
	out, err := c.CombinedOutput()
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
	zap.L().Debug("Executing cmd", zap.String("cmd", fmt.Sprintf("networksetup %s", strings.Join(cmd, " "))))
	if o, err := exec.Command("networksetup", cmd...).CombinedOutput(); err != nil {
		return errors.Errorf("Could not set dns servers: %s. %+v", string(o), err)
	}

	cmd = []string{"-setsearchdomains", svc}
	cmd = append(cmd, networkDomains...)
	zap.L().Debug("Executing cmd", zap.String("cmd", fmt.Sprintf("networksetup %s", strings.Join(cmd, " "))))
	if o, err := exec.Command("networksetup", cmd...).CombinedOutput(); err != nil {
		return errors.Errorf("Could not set dns search domains: %s. %+v", string(o), err)
	}
	return nil
}

func (c *Controller) doUnSetDNSNetworkSetup() error {
	zap.L().Debug("Unsetting DNS using networksetup")
	if c.c.Preferences.MacosPrefs.NetworkSetupConfig != nil {
		for _, svc := range c.c.Preferences.MacosPrefs.NetworkSetupConfig.Services {
			if err := setNetworkSetupDNSServers(svc.Name, svc.DnsServers, svc.DnsDomains); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *Controller) doSetDNSScutil() error {
	arg := fmt.Sprintf(`
open
d.init
d.add ServerAddresses * %s
d.add SearchDomains * %s
d.add SupplementalMatchDomains * %s
d.add InterfaceName %s
set State:/Network/Service/octelium/DNS
quit
`, strings.Join(c.getClusterDNSServers(), " "),
		strings.Join(c.getDNSSearchDomains(), " "),
		strings.Join(c.getDNSSearchDomains(), " "),
		c.c.Preferences.DeviceName)

	if err := c.doRunScutil(arg); err != nil {
		return err
	}

	c.c.Preferences.MacosPrefs.DnsMode = pbconfig.Connection_Preferences_MacOS_SCUTIL
	return nil
}

func (c *Controller) doUnsetDNSScutil() error {
	arg := `
open
remove State:/Network/Service/octelium/DNS
quit
`
	return c.doRunScutil(arg)
}

func (c *Controller) doRunScutil(arg string) error {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(arg)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	zap.L().Debug("Running scutil command", zap.String("input", arg))
	if err := cmd.Run(); err != nil {
		return errors.Errorf("Could not run scutil command: %s: stderr: %s", arg, stderr.String())
	}
	return nil
}
