//go:build darwin
// +build darwin

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
	"errors"
	"fmt"
	"os"
	"slices"
	"syscall"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
)

func cleanupOwnerRunning(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

func reconcilePlatformCleanup(cleanup *cliconfigv1.ConnectionCleanup) error {
	dns := cleanup.GetDns()
	if dns == nil {
		return nil
	}
	switch cfg := dns.Config.(type) {
	case *cliconfigv1.ConnectionCleanup_DNS_ResolvConf_:
		return restoreCleanupResolvConf(cfg.ResolvConf)
	case *cliconfigv1.ConnectionCleanup_DNS_Macos:
		return reconcileMacOSDNS(cfg.Macos)
	default:
		return nil
	}
}

func reconcileMacOSDNS(cfg *cliconfigv1.ConnectionCleanup_DNS_MacOS) error {
	if cfg == nil {
		return nil
	}
	var retErr error
	if cfg.ScutilKey != "" {
		_, err := runOSCmdInput(fmt.Sprintf("open\nremove %s\nquit\n", cfg.ScutilKey), "scutil")
		retErr = errors.Join(retErr, err)
	}
	for _, svc := range cfg.Services {
		current, err := getNetworkSetupServiceConfig(svc.Name)
		if err != nil {
			retErr = errors.Join(retErr, err)
			continue
		}
		if !slices.Equal(current.DnsServers, svc.InstalledDNSServers) ||
			!slices.Equal(current.DnsDomains, svc.InstalledDNSDomains) {
			continue
		}
		retErr = errors.Join(retErr,
			setNetworkSetupDNSServers(svc.Name, svc.DnsServers, svc.DnsDomains))
	}
	return retErr
}
