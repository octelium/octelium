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
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (c *Controller) getCurrentDNS() net.IP {
	c.dnsServers.Lock()
	defer c.dnsServers.Unlock()
	if len(c.dnsServers.servers) == 0 {
		return nil
	}
	return c.dnsServers.servers[0]
}

func (c *Controller) SetDNS() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isClosed {
		return errors.Errorf("The controller is already closed")
	}

	return c.setDNS()
}

func (c *Controller) setDNS() error {

	dnsServers := c.getDNSServers()
	var curServers []net.IP
	for _, dnsServer := range dnsServers {
		if ip := net.ParseIP(dnsServer); ip != nil {
			curServers = append(curServers, ip)
		}
	}

	c.dnsServers.Lock()
	c.dnsServers.servers = curServers
	c.dnsServers.Unlock()

	clusterServers := c.getClusterDNSServers()
	c.clusterDNSServers.Lock()
	c.clusterDNSServers.servers = clusterServers
	c.clusterDNSServers.Unlock()

	if c.isNetstack || c.c.Preferences.IgnoreDNS || len(dnsServers) == 0 {
		zap.L().Debug("Ignoring setting DNS")
		return nil
	}

	zap.L().Debug("Setting DNS servers", zap.Strings("servers", dnsServers))

	if c.c.Preferences.RuntimeMode == cliconfigv1.Connection_Preferences_CONTAINER {
		zap.L().Debug("Container mode. Setting resolv.conf directly")
		if err := c.setResolvConf(); err != nil {
			zap.L().Warn("Could not set resolv.conf", zap.Error(err))
		}

		return nil
	}

	if err := c.doSetDNS(); err != nil {
		zap.L().Warn("Could not set DNS", zap.Error(err))
	}

	return nil
}

func (c *Controller) UnsetDNS() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.unsetDNS()
}

func (c *Controller) unsetDNS() error {
	zap.L().Debug("Unsetting DNS")
	if c.isNetstack || c.c.Preferences.IgnoreDNS {
		return nil
	}

	if c.c.Preferences.RuntimeMode == cliconfigv1.Connection_Preferences_CONTAINER {
		zap.L().Debug("Container mode. Restoring resolv.conf")
		if err := c.unsetResolvConf(); err != nil {
			zap.L().Warn("Could not restore resolv.conf", zap.Error(err))
		}

		return nil
	}

	if err := c.doUnsetDNS(); err != nil {
		zap.L().Warn("Could not unset DNS", zap.Error(err))
	}

	return nil
}

func (c *Controller) getDNSServers() []string {
	if c.c.Preferences.LocalDNS != nil && c.c.Preferences.LocalDNS.IsEnabled {
		if addr := c.getLocalDNSServerAddr(); addr != "" {
			if govalidator.IsIP(addr) {
				return []string{
					addr,
				}
			}
			host, _, _ := net.SplitHostPort(addr)
			return []string{
				host,
			}
		}
	}

	return c.getClusterDNSServers()
}

func (c *Controller) getClusterDNSServers() []string {
	if c.c.Connection.Dns == nil {
		return nil
	}

	var ret []string
	for _, s := range c.c.Connection.Dns.Servers {
		if govalidator.IsIPv6(s) && c.ipv6Supported {
			ret = append(ret, s)
		} else {
			if c.ipv4Supported {
				ret = append(ret, s)
			}
		}
	}
	return ret
}

func (c *Controller) GetClusterDNSServers() []string {
	c.clusterDNSServers.Lock()
	defer c.clusterDNSServers.Unlock()

	return slices.Clone(c.clusterDNSServers.servers)
}

func (c *Controller) getDNSSearchDomains() []string {
	return []string{
		fmt.Sprintf("local.%s", c.c.Info.Cluster.Domain),
	}
}

func getNRPTNamespaces(searchDomains []string, clusterDomain string) []string {
	normalize := func(arg string) string {
		return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(arg), "."))
	}

	clusterDomain = normalize(clusterDomain)

	var ret []string
	for _, domain := range searchDomains {
		domain = normalize(domain)
		if domain == "" || !govalidator.IsDNSName(domain) {
			continue
		}

		if clusterDomain == domain || strings.HasSuffix(clusterDomain, fmt.Sprintf(".%s", domain)) {
			zap.L().Warn("Refusing to set an NRPT rule that captures the Cluster domain itself",
				zap.String("domain", domain), zap.String("clusterDomain", clusterDomain))
			continue
		}

		namespace := fmt.Sprintf(".%s", domain)
		if !slices.Contains(ret, namespace) {
			ret = append(ret, namespace)
		}
	}

	return ret
}

func getNRPTRuleKey(clusterDomain string) (string, error) {
	clusterDomain = strings.ToLower(strings.TrimSpace(clusterDomain))
	if clusterDomain == "" || !govalidator.IsDNSName(clusterDomain) {
		return "", errors.Errorf("Invalid Cluster domain: %q", clusterDomain)
	}

	h := sha256.Sum256([]byte(fmt.Sprintf("octelium-nrpt-%s", clusterDomain)))

	return fmt.Sprintf("{%x-%x-%x-%x-%x}", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16]), nil
}

const (
	resolvConfPath             = "/etc/resolv.conf"
	resolvConfMaxNameservers   = 3
	resolvConfMaxSearchDomains = 6
	resolvConfDefaultMode      = os.FileMode(0644)
)

type resolvConfState struct {
	path       string
	saved      bool
	written    bool
	existed    bool
	isSymlink  bool
	linkTarget string
	content    []byte
	mode       os.FileMode
}

func (s *resolvConfState) getPath() string {
	if s.path != "" {
		return s.path
	}

	return resolvConfPath
}

func (c *Controller) saveResolvConf() error {
	if c.resolvConf.saved {
		return nil
	}
	c.resolvConf.saved = true

	path := c.resolvConf.getPath()

	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		c.resolvConf.saved = false
		return err
	}

	c.resolvConf.existed = true
	c.resolvConf.mode = fi.Mode().Perm()

	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			c.resolvConf.saved = false
			return err
		}
		c.resolvConf.isSymlink = true
		c.resolvConf.linkTarget = target
		c.resolvConf.mode = resolvConfDefaultMode
	}

	content, err := os.ReadFile(path)
	if err != nil {
		zap.L().Debug("Could not read the current resolv.conf", zap.Error(err))
	} else {
		c.resolvConf.content = content
	}

	zap.L().Debug("Saved the current resolv.conf",
		zap.Bool("isSymlink", c.resolvConf.isSymlink),
		zap.String("linkTarget", c.resolvConf.linkTarget))

	return nil
}

func (c *Controller) getResolvConfOpts() (*resolvConfOpts, error) {
	var nameservers []string
	for _, ns := range c.getDNSServers() {
		if govalidator.IsIP(ns) {
			nameservers = append(nameservers, ns)
		}
	}
	if len(nameservers) == 0 {
		return nil, errors.Errorf("No valid DNS servers to set in %s", resolvConfPath)
	}
	if len(nameservers) > resolvConfMaxNameservers {
		nameservers = nameservers[:resolvConfMaxNameservers]
	}

	ret := &resolvConfOpts{
		Nameservers:   nameservers,
		SearchDomains: c.getDNSSearchDomains(),
	}

	if prev, err := parseResolvConf(c.resolvConf.content); err == nil && prev != nil {
		for _, domain := range prev.SearchDomains {
			if !slices.Contains(ret.SearchDomains, domain) {
				ret.SearchDomains = append(ret.SearchDomains, domain)
			}
		}
		ret.Options = prev.Options
	}

	if len(ret.SearchDomains) > resolvConfMaxSearchDomains {
		ret.SearchDomains = ret.SearchDomains[:resolvConfMaxSearchDomains]
	}

	return ret, nil
}

func (c *Controller) setResolvConf() error {
	if err := c.saveResolvConf(); err != nil {
		return err
	}

	opts, err := c.getResolvConfOpts()
	if err != nil {
		return err
	}

	content, err := generateResolvConf(opts)
	if err != nil {
		return errors.Errorf("Could not generate the resolv.conf content: %+v", err)
	}

	zap.L().Debug("Setting resolv.conf", zap.String("content", content))

	if err := c.writeResolvConf([]byte(content)); err != nil {
		return err
	}

	c.resolvConf.written = true

	return nil
}

func (c *Controller) writeResolvConf(content []byte) error {
	if c.resolvConf.isSymlink {
		return replaceResolvConf(c.resolvConf.getPath(), content, c.resolvConf.mode)
	}

	return writeResolvConfInPlace(c.resolvConf.getPath(), content, c.resolvConf.mode)
}

func (c *Controller) unsetResolvConf() error {
	if !c.resolvConf.written {
		return nil
	}
	c.resolvConf.written = false

	zap.L().Debug("Restoring resolv.conf",
		zap.Bool("existed", c.resolvConf.existed),
		zap.Bool("isSymlink", c.resolvConf.isSymlink))

	path := c.resolvConf.getPath()

	if !c.resolvConf.existed {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	if c.resolvConf.isSymlink {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return os.Symlink(c.resolvConf.linkTarget, path)
	}

	return writeResolvConfInPlace(path, c.resolvConf.content, c.resolvConf.mode)
}

func writeResolvConfInPlace(path string, content []byte, mode os.FileMode) error {
	if mode == 0 {
		mode = resolvConfDefaultMode
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return errors.Errorf("Could not open %s: %+v", path, err)
	}

	if _, err := f.Write(content); err != nil {
		f.Close()
		return errors.Errorf("Could not write to %s: %+v", path, err)
	}

	if err := f.Close(); err != nil {
		return errors.Errorf("Could not write to %s: %+v", path, err)
	}

	return nil
}

func replaceResolvConf(path string, content []byte, mode os.FileMode) error {
	if mode == 0 {
		mode = resolvConfDefaultMode
	}

	f, err := os.CreateTemp(filepath.Dir(path),
		fmt.Sprintf("%s.octelium-*", filepath.Base(path)))
	if err != nil {
		return errors.Errorf("Could not create a temp file for %s: %+v", path, err)
	}
	tmpPath := f.Name()

	if _, err := f.Write(content); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return errors.Errorf("Could not write to %s: %+v", tmpPath, err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return errors.Errorf("Could not write to %s: %+v", tmpPath, err)
	}

	if err := os.Chmod(tmpPath, mode); err != nil {
		os.Remove(tmpPath)
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return errors.Errorf("Could not replace %s: %+v", path, err)
	}

	return nil
}

type resolvConfOpts struct {
	Nameservers   []string
	SearchDomains []string
	Options       []string
}

func parseResolvConf(resolvConfBytes []byte) (*resolvConfOpts, error) {
	config := &resolvConfOpts{}
	scanner := bufio.NewScanner(bytes.NewBuffer(resolvConfBytes))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		parts := strings.Fields(line)

		if len(parts) == 0 {
			continue
		}

		keyword := parts[0]
		values := parts[1:]

		switch keyword {
		case "nameserver":
			if len(values) > 0 {
				ip := net.ParseIP(values[0])
				if ip != nil {
					config.Nameservers = append(config.Nameservers, values[0])
				}
			}
		case "search":
			config.SearchDomains = append(config.SearchDomains, values...)
		case "options":
			config.Options = append(config.Options, values...)
		default:
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.Errorf("Could not read resolv.conf: %+v", err)
	}

	return config, nil
}

func generateResolvConf(config *resolvConfOpts) (string, error) {
	if config == nil {
		return "", fmt.Errorf("resolvConfOpts struct cannot be nil")
	}

	var sb strings.Builder

	for _, ns := range config.Nameservers {
		sb.WriteString("nameserver ")
		sb.WriteString(ns)
		sb.WriteString("\n")
	}

	if len(config.SearchDomains) > 0 {
		sb.WriteString("search ")
		sb.WriteString(strings.Join(config.SearchDomains, " "))
		sb.WriteString("\n")
	}

	if len(config.Options) > 0 {
		sb.WriteString("options ")
		sb.WriteString(strings.Join(config.Options, " "))
		sb.WriteString("\n")
	}

	return sb.String(), nil
}

func (c *Controller) getLocalDNSServerAddr() string {
	if c.c.Preferences.LocalDNS != nil && c.c.Preferences.LocalDNS.ListenAddress != "" {
		return c.c.Preferences.LocalDNS.ListenAddress
	}
	if cliutils.IsDarwin() || cliutils.IsWindows() {
		return "127.0.0.1:53"
	}

	return "127.0.0.100:53"

	/*
		if len(c.c.Connection.Addresses) > 0 {
			if c.ipv6Supported && c.c.Connection.Addresses[0].V6 != "" {
				addr, _, _ := net.ParseCIDR(c.c.Connection.Addresses[0].V6)
				return net.JoinHostPort(addr.String(), "53")
			}
			if c.ipv4Supported && c.c.Connection.Addresses[0].V4 != "" {
				addr, _, _ := net.ParseCIDR(c.c.Connection.Addresses[0].V4)
				return net.JoinHostPort(addr.String(), "53")
			}
		}



		return ""
	*/
}
