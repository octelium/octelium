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
	"os/exec"
	"strings"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (c *Controller) doSetDNS() error {

	if err := exec.Command("systemctl", "is-active", "--quiet", "systemd-resolved").Run(); err == nil {
		if err := c.doSetDNSResolvctl(); err == nil {
			return nil
		} else {
			zap.S().Debugf("Could not set DNS via systemd-resolved: %+v. Fallbacking...", err)
		}
	}

	zap.S().Debugf("Fallback to setting resolv.conf directly")

	return c.doSetDNSResolvConf()

}

func (c *Controller) doSetDNSResolvConf() error {

	if !c.dnsConfigSaved {
		oldResolvConf, err := os.ReadFile("/etc/resolv.conf")
		if err != nil {
			return err
		}
		c.c.Preferences.LinuxPrefs.ResolvConf = oldResolvConf
		c.dnsConfigSaved = true
	}

	resolvConfOpts, err := parseResolvConf(c.c.Preferences.LinuxPrefs.ResolvConf)
	if err != nil {
		zap.L().Warn("Could not parse resolv.conf", zap.Error(err))
	}

	if err := c._doSetDNSResolvConf(resolvConfOpts); err != nil {
		return err
	}

	c.c.Preferences.LinuxPrefs.DnsMode = cliconfigv1.Connection_Preferences_Linux_RESOLVCONF

	return nil
}

func (c *Controller) doSetDNSResolvctl() error {

	var isResolvectl bool

	var cmdBin string
	var cmdDNSArgs string
	var cmdDomainArgs string

	if _, err := exec.LookPath("resolvectl"); err == nil {
		isResolvectl = true
		cmdBin = "resolvectl"
	} else if _, err := exec.LookPath("systemd-resolve"); err == nil {
		cmdBin = "systemd-resolve"
	} else {
		return errors.Errorf("Could not find resolvectl or systemd-resolve")
	}

	if isResolvectl {
		cmdDNSArgs = fmt.Sprintf("dns %s %s", c.c.Preferences.DeviceName, strings.Join(c.getDNSServers(), " "))
		cmdDomainArgs = fmt.Sprintf("domain %s %s", c.c.Preferences.DeviceName,
			strings.Join(c.getDNSSearchDomains(), " "))
	} else {
		cmdDNSArgs = fmt.Sprintf("--interface %s", c.c.Preferences.DeviceName)

		dnsServers := c.getDNSServers()
		for _, s := range dnsServers {
			cmdDNSArgs = fmt.Sprintf("%s --set-dns %s", cmdDNSArgs, s)
		}

		cmdDomainArgs = fmt.Sprintf("--interface %s --set-domain %s", c.c.Preferences.DeviceName,
			c.c.Info.Cluster.Domain)
	}

	if b, err := exec.Command(cmdBin, strings.Split(cmdDNSArgs, " ")...).CombinedOutput(); err != nil {
		zap.S().Debugf("command error: %s", string(b))
		return err
	}

	if b, err := exec.Command(cmdBin, strings.Split(cmdDomainArgs, " ")...).CombinedOutput(); err != nil {
		zap.S().Debugf("command error: %s", string(b))
		return err
	}

	c.c.Preferences.LinuxPrefs.DnsMode = cliconfigv1.Connection_Preferences_Linux_RESOLVECTL_BIN

	return nil
}

func (c *Controller) doUnsetDNS() error {

	switch c.c.Preferences.LinuxPrefs.DnsMode {
	case cliconfigv1.Connection_Preferences_Linux_RESOLVCONF:
		if len(c.c.Preferences.LinuxPrefs.ResolvConf) > 0 {
			if err := os.WriteFile("/etc/resolv.conf", c.c.Preferences.LinuxPrefs.ResolvConf, 0644); err != nil {
				return err
			}
		}

	default:
	}
	return nil
}
