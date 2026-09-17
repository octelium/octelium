//go:build linux
// +build linux

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
	"os"
	"os/exec"
	"syscall"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/vishvananda/netlink"
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
	var retErr error
	if dns := cleanup.GetDns(); dns != nil {
		switch cfg := dns.Config.(type) {
		case *cliconfigv1.ConnectionCleanup_DNS_ResolvConf_:
			retErr = errors.Join(retErr, restoreCleanupResolvConf(cfg.ResolvConf))
		case *cliconfigv1.ConnectionCleanup_DNS_SystemdResolved_:
			retErr = errors.Join(retErr, reconcileSystemdResolved(cfg.SystemdResolved))
		}
	}
	retErr = errors.Join(retErr, reconcileLinuxDevice(cleanup.GetDevice()))
	return retErr
}

func reconcileSystemdResolved(cfg *cliconfigv1.ConnectionCleanup_DNS_SystemdResolved) error {
	if cfg == nil || cfg.DeviceName == "" {
		return nil
	}
	if _, err := netlink.LinkByName(cfg.DeviceName); err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return err
	}
	cmdBin := "systemd-resolve"
	if cfg.IsResolvectl {
		cmdBin = "resolvectl"
	}
	if _, err := exec.LookPath(cmdBin); err != nil {
		return err
	}
	_, err := runOSCmdOutput(cmdBin, getResolvctlRevertArgs(cfg.IsResolvectl, cfg.DeviceName)...)
	return err
}

func reconcileLinuxDevice(cfg *cliconfigv1.ConnectionCleanup_Device) error {
	if cfg == nil || cfg.Name == "" || cfg.Type == cliconfigv1.ConnectionCleanup_Device_NETSTACK {
		return nil
	}
	link, err := netlink.LinkByName(cfg.Name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return err
	}
	if cfg.Type == cliconfigv1.ConnectionCleanup_Device_LINUX_WIREGUARD && link.Type() != "wireguard" {
		return nil
	}
	return netlink.LinkDel(link)
}
