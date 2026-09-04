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
	"net/netip"
	"slices"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func (c *Controller) doSetDNS() error {
	if c.isNetstack {
		return nil
	}

	luid := c.getLUID()
	if luid == 0 {
		return errors.Errorf("The network device is not initialized")
	}

	if err := c.doSetDNSAdapter(luid); err != nil {
		return err
	}

	if err := c.setNRPT(); err != nil {
		zap.L().Warn("Could not set the NRPT rule. Falling back to the interface DNS config alone",
			zap.Error(err))
		return nil
	}

	if err := flushDNSResolverCache(); err != nil {
		zap.L().Debug("Could not flush the DNS resolver cache", zap.Error(err))
	}

	return nil
}

func (c *Controller) doSetDNSAdapter(luid winipcfg.LUID) error {
	dnsServers := c.getDNSServers()

	if c.c.Preferences.LocalDNS != nil && c.c.Preferences.LocalDNS.IsEnabled {

		{
			dnsAddrs := []netip.Addr{}
			for _, addr := range dnsServers {
				if govalidator.IsIPv4(addr) {
					netaddr, err := netip.ParseAddr(addr)
					if err != nil {
						return err
					}
					dnsAddrs = append(dnsAddrs, netaddr)
				}
			}
			if err := luid.SetDNS(windows.AF_INET, dnsAddrs, c.getDNSSearchDomains()); err != nil {
				return err
			}
		}

		{
			dnsAddrs := []netip.Addr{}
			for _, addr := range dnsServers {
				if govalidator.IsIPv6(addr) {
					netaddr, err := netip.ParseAddr(addr)
					if err != nil {
						return err
					}
					dnsAddrs = append(dnsAddrs, netaddr)
				}
			}
			if err := luid.SetDNS(windows.AF_INET6, dnsAddrs, c.getDNSSearchDomains()); err != nil {
				return err
			}
		}

		return nil
	}

	if c.ipv4Supported {
		dnsAddrs := []netip.Addr{}

		for _, addr := range dnsServers {
			if govalidator.IsIPv4(addr) {
				netaddr, err := netip.ParseAddr(addr)
				if err != nil {
					return err
				}
				dnsAddrs = append(dnsAddrs, netaddr)
			}
		}

		if err := luid.SetDNS(windows.AF_INET, dnsAddrs, c.getDNSSearchDomains()); err != nil {
			return err
		}
	}

	if c.ipv6Supported {
		dnsAddrs := []netip.Addr{}

		for _, addr := range dnsServers {
			if govalidator.IsIPv6(addr) {
				netaddr, err := netip.ParseAddr(addr)
				if err != nil {
					return err
				}
				dnsAddrs = append(dnsAddrs, netaddr)
			}
		}

		if err := luid.SetDNS(windows.AF_INET6, dnsAddrs, c.getDNSSearchDomains()); err != nil {
			return err
		}
	}

	return nil
}

func (c *Controller) doUnsetDNS() error {
	if c.isNetstack {
		return nil
	}

	var retErr error

	if err := c.unsetNRPT(); err != nil {
		zap.L().Warn("Could not unset the NRPT rule", zap.Error(err))
		retErr = err
	} else if err := flushDNSResolverCache(); err != nil {
		zap.L().Debug("Could not flush the DNS resolver cache", zap.Error(err))
	}

	luid := c.getLUID()
	if luid == 0 {
		return retErr
	}

	if err := luid.FlushDNS(windows.AF_INET); err != nil {
		zap.L().Debug("Could not flush the v4 DNS of the adapter", zap.Error(err))
	}
	if err := luid.FlushDNS(windows.AF_INET6); err != nil {
		zap.L().Debug("Could not flush the v6 DNS of the adapter", zap.Error(err))
	}
	/*
		if c.ipv4Supported {
			if err := luid.FlushDNS(windows.AF_INET); err != nil {
				return err
			}
		}

		if c.ipv6Supported {
			if err := luid.FlushDNS(windows.AF_INET6); err != nil {
				return err
			}
		}
	*/

	return retErr
}

const (
	nrptLocalBase  = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptGPBase     = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	tcpipParamsKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

	nrptVersion                 = 1
	nrptConfigOptionsDNSServers = 0x8
)

var (
	modDNSAPI                 = windows.NewLazySystemDLL("dnsapi.dll")
	procDNSFlushResolverCache = modDNSAPI.NewProc("DnsFlushResolverCache")
)

func flushDNSResolverCache() error {
	if err := procDNSFlushResolverCache.Find(); err != nil {
		return err
	}

	if ret, _, err := procDNSFlushResolverCache.Call(); ret == 0 {
		return err
	}

	return nil
}

func (c *Controller) getNRPTRulePath() (string, error) {
	if c.c.Info == nil || c.c.Info.Cluster == nil {
		return "", errors.Errorf("The Connection does not have Cluster info")
	}

	ruleKey, err := getNRPTRuleKey(c.c.Info.Cluster.Domain)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(`%s\%s`, nrptLocalBase, ruleKey), nil
}

func (c *Controller) setNRPT() error {
	if c.c.Info == nil || c.c.Info.Cluster == nil {
		return errors.Errorf("The Connection does not have Cluster info")
	}

	namespaces := getNRPTNamespaces(c.getDNSSearchDomains(), c.c.Info.Cluster.Domain, c.isFullDNS())
	if len(namespaces) == 0 {
		return errors.Errorf("Could not find any valid namespace for the NRPT rule")
	}

	var servers []string
	for _, server := range c.getDNSServers() {
		if govalidator.IsIP(server) && !slices.Contains(servers, server) {
			servers = append(servers, server)
		}
	}
	if len(servers) == 0 {
		return errors.Errorf("Could not find any valid DNS server for the NRPT rule")
	}

	rulePath, err := c.getNRPTRulePath()
	if err != nil {
		return err
	}

	marker, err := c.getManagedMarker()
	if err != nil {
		return err
	}

	zap.L().Debug("Setting the NRPT rule", zap.String("path", rulePath),
		zap.Strings("namespaces", namespaces), zap.Strings("servers", servers))

	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, rulePath, registry.SET_VALUE)
	if err != nil {
		return errors.Errorf("Could not create the NRPT rule key: %+v", err)
	}
	defer key.Close()

	if err := key.SetStringValue("Comment", marker); err != nil {
		return err
	}

	if err := key.SetDWordValue("Version", nrptVersion); err != nil {
		return err
	}

	if err := key.SetStringsValue("Name", namespaces); err != nil {
		return err
	}

	if err := key.SetStringValue("GenericDNSServers", strings.Join(servers, ";")); err != nil {
		return err
	}

	if err := key.SetDWordValue("ConfigOptions", nrptConfigOptionsDNSServers); err != nil {
		return err
	}

	warnOnNRPTOverrides()

	return nil
}

func (c *Controller) unsetNRPT() error {
	rulePath, err := c.getNRPTRulePath()
	if err != nil {
		return err
	}

	marker, err := c.getManagedMarker()
	if err != nil {
		return err
	}

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, rulePath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}

	comment, _, err := key.GetStringValue("Comment")
	key.Close()
	if err != nil || comment != marker {
		zap.L().Warn("The NRPT rule is not managed by this Cluster. Skipping its removal",
			zap.String("path", rulePath))
		return nil
	}

	zap.L().Debug("Removing the NRPT rule", zap.String("path", rulePath))

	return registry.DeleteKey(registry.LOCAL_MACHINE, rulePath)
}

func warnOnNRPTOverrides() {
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptGPBase,
		registry.ENUMERATE_SUB_KEYS); err == nil {
		names, err := key.ReadSubKeyNames(-1)
		key.Close()
		if err == nil && len(names) > 0 {
			zap.L().Warn("Group Policy NRPT rules are configured. Windows ignores local NRPT rules whenever they exist, so the Cluster's split DNS may not take effect",
				zap.Int("rules", len(names)))
		}
	}

	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, tcpipParamsKey,
		registry.QUERY_VALUE); err == nil {
		searchList, _, err := key.GetStringValue("SearchList")
		key.Close()
		if err == nil && strings.TrimSpace(searchList) != "" {
			zap.L().Warn("A global DNS SearchList is configured. Unqualified Service hostnames may not resolve. Use the fully qualified Service name instead",
				zap.String("searchList", searchList))
		}
	}
}
