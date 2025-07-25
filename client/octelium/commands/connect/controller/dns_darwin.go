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
	if err := c.doSetDNSNetworkSetup(); err != nil {
		zap.S().Errorf("Could not set DNS via networksetup: %+v. Fallback to setting resolv.conf", err)
		return c.doSetDNSResolvConf()
	}

	return nil
}

func (c *Controller) doSetDNSNetworkSetup() error {
	zap.S().Debugf("Setting DNS via networksetup")
	netServices, err := getNetworkSetupServices()
	if err != nil {
		return err
	}

	zap.S().Debugf("Found network services: %+q", netServices)

	c.c.Preferences.MacosPrefs.NetworkSetupConfig = &pbconfig.Connection_Preferences_MacOS_NetworkSetupConfig{}
	networkSetupConfig := c.c.Preferences.MacosPrefs.NetworkSetupConfig

	if !c.dnsConfigSaved {
		for _, svc := range netServices {
			outServers, err := exec.Command("networksetup", "-getdnsservers", svc).CombinedOutput()
			if err != nil {
				return errors.Errorf("Could not get list network services: %+v. %s", err, string(outServers))
			}

			zap.S().Debugf("dns servers of svc: %s = %s", svc, string(outServers))

			outDomains, err := exec.Command("networksetup", "-getsearchdomains", svc).CombinedOutput()
			if err != nil {
				return errors.Errorf("Could not get list network services: %+v. %s", err, string(outServers))
			}

			zap.S().Debugf("search domains of svc: %s = %s", svc, string(outDomains))

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

		zap.S().Debugf("Stored networksetup config: %+v", networkSetupConfig)

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

	zap.S().Debugf("Unsetting DNS")
	if c.c.Preferences.MacosPrefs == nil {
		return nil
	}

	switch c.c.Preferences.MacosPrefs.DnsMode {
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
	zap.S().Debugf("Unsetting DNS using networksetup")
	if c.c.Preferences.MacosPrefs.NetworkSetupConfig != nil {
		for _, svc := range c.c.Preferences.MacosPrefs.NetworkSetupConfig.Services {
			if err := setNetworkSetupDNSServers(svc.Name, svc.DnsServers, svc.DnsDomains); err != nil {
				return err
			}
		}
	}

	return nil
}
