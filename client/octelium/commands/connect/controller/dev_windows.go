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
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"golang.zx2c4.com/wireguard/windows/version"
)

func setTunDev() error {
	return nil
}

func (c *Controller) doInitDev(ctx context.Context) error {
	err := c.doInitDevTUN(ctx)
	if err == nil {
		return nil
	}
	if err := c.doInitDevNetstack(ctx); err != nil {
		return errors.Errorf("Could not init netstack dev: %+v", err)
	}
	return nil
}

func (c *Controller) doInitDevTUN(ctx context.Context) error {

	var err error

	zap.S().Debugf("getting conf")
	conf, err := c.getWgConf()
	if err != nil {
		return err
	}

	logPrefix := fmt.Sprintf("[%s] ", conf.Name)
	log.SetPrefix(logPrefix)

	zap.S().Debugf("Starting", version.UserAgent())

	zap.S().Debugf("Watching network interfaces")

	if err := c.watchInterface(); err != nil {
		return err
	}

	if err := conf.ResolveEndpoints(); err != nil {
		return err
	}

	guid, err := c.getGUID()
	if err != nil {
		return err
	}

	log.Println("Creating network adapter")
	for i := 0; i < 15; i++ {
		if i > 0 {
			time.Sleep(time.Second)
			log.Printf("Retrying adapter creation after failure because system just booted (T+%v): %v", windows.DurationSinceBoot(), err)
		}
		c.opts.adapter, err = driver.CreateAdapter("octelium", "WireGuard", guid)
		if err == nil || !services.StartedAtBoot() {
			break
		}
	}
	if err != nil {
		return err
	}

	driverVersion, err := driver.RunningVersion()
	if err != nil {
		log.Printf("Warning: unable to determine driver version: %v", err)
	} else {
		log.Printf("Using WireGuardNT/%d.%d", (driverVersion>>16)&0xffff, driverVersion&0xffff)
	}

	err = c.opts.adapter.SetLogging(driver.AdapterLogOn)
	if err != nil {
		return err
	}

	err = c.opts.adapter.SetConfiguration(conf.ToDriverConfiguration())
	if err != nil {
		return err
	}

	if err := c.doSetDevUp(); err != nil {
		return err
	}

	c.configureIface()

	return nil
}

func (c *Controller) doSetDevUp() error {
	if err := c.opts.adapter.SetAdapterState(driver.AdapterStateUp); err != nil {
		return err
	}

	return nil
}

func (c *Controller) doDeleteDev() error {
	if c.isNetstack {
		return nil
	}

	if c.opts.adapter == nil {
		return nil
	}

	c.destroyIface()
	c.opts.adapter.Close()

	return nil
}

func (c *Controller) doSetDevAddrs() error {

	if c.isNetstack {
		return nil
	}

	ipv4Nets := []netip.Prefix{}
	ipv6Nets := []netip.Prefix{}
	for _, addr := range c.c.Connection.Addresses {
		if c.ipv4Supported && addr.V4 != "" {
			ipnet, err := netip.ParsePrefix(addr.V4)
			if err != nil {
				return err
			}

			ipv4Nets = append(ipv4Nets, ipnet)
		}

		if c.ipv6Supported && addr.V6 != "" {
			ipnet, err := netip.ParsePrefix(addr.V6)
			if err != nil {
				return err
			}
			ipv6Nets = append(ipv6Nets, ipnet)
		}
	}

	if c.ipv4Supported && len(ipv4Nets) > 0 {
		if err := c.opts.adapter.LUID().SetIPAddressesForFamily(windows.AF_INET, ipv4Nets); err != nil {
			return err
		}
	}

	if c.ipv6Supported && len(ipv6Nets) > 0 {
		if err := c.opts.adapter.LUID().SetIPAddressesForFamily(windows.AF_INET6, ipv6Nets); err != nil {
			return err
		}
	}

	if err := c.setIPIF(); err != nil {
		return err
	}

	return nil
}

func (c *Controller) getGUID() (*windows.GUID, error) {

	arg := "octelium.com"
	h := sha256.New()
	_, err := h.Write([]byte(arg))
	if err != nil {
		return nil, err
	}
	bs := h.Sum(nil)

	var data4 [8]byte

	copy(data4[:], bs[8:16])

	ret := &windows.GUID{
		Data1: binary.LittleEndian.Uint32(bs[:4]),
		Data2: binary.LittleEndian.Uint16(bs[4:6]),
		Data3: binary.LittleEndian.Uint16(bs[6:8]),
		Data4: data4,
	}

	zap.S().Debugf("GUID of %s = %s", arg, ret.String())

	return ret, nil
}

/*
func (c *Controller) enableFirewall(dnsServers []net.IP) error {
	return firewall.EnableFirewall(uint64(c.getLUID()), true, dnsServers)
}

*/

type interfaceWatcherEvent struct {
	adapter *driver.Adapter
	luid    winipcfg.LUID
	family  winipcfg.AddressFamily
}

type interfaceWatcher struct {
	mu                      sync.Mutex
	interfaceChangeCallback winipcfg.ChangeCallback
	changeCallbacks4        []winipcfg.ChangeCallback
	changeCallbacks6        []winipcfg.ChangeCallback
	storedEvents            []interfaceWatcherEvent
}

func (c *Controller) watchInterface() error {
	iw := &interfaceWatcher{}
	c.opts.ifaceWatcher = iw

	var err error
	iw.interfaceChangeCallback, err = winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		iw.mu.Lock()
		defer iw.mu.Unlock()

		if notificationType != winipcfg.MibAddInstance {
			return
		}
		if c.tundev == nil {
			iw.storedEvents = append(iw.storedEvents, interfaceWatcherEvent{c.opts.adapter, iface.InterfaceLUID, iface.Family})
			return
		}

		if iface.InterfaceLUID != c.opts.adapter.LUID() {
			return
		}

		if err := c.doConfigureIface(); err != nil {
			zap.S().Errorf("Could not configure interface: %+v", err)
		}
	})
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) doConfigureIface() error {

	zap.S().Debugf("Configuring the interface.....")

	if err := c.doSetDevAddrs(); err != nil {
		zap.S().Debugf("Could not set addresses at cb: %+v", err)
		return err
	}

	if err := c.doSetRoutes(); err != nil {
		zap.S().Debugf("Could not set routes at cb: %+v", err)
		return err
	}

	if err := c.doSetDNS(); err != nil {
		zap.S().Debugf("Could not set DNS at cb: %+v", err)
		return err
	}

	zap.S().Debugf("Successfully configured the interface")
	return nil
}

func (c *Controller) configureIface() {
	iw := c.opts.ifaceWatcher
	iw.mu.Lock()
	defer iw.mu.Unlock()

	for _, event := range iw.storedEvents {
		if event.luid == c.opts.adapter.LUID() {
			if err := c.doConfigureIface(); err != nil {
				zap.S().Errorf("Could not configure interface: %+v", err)
			}
		}
	}
	iw.storedEvents = nil
}

func (c *Controller) destroyIface() error {

	iw := c.opts.ifaceWatcher
	if iw == nil {
		return nil
	}

	iw.mu.Lock()
	changeCallbacks4 := iw.changeCallbacks4
	changeCallbacks6 := iw.changeCallbacks6
	interfaceChangeCallback := iw.interfaceChangeCallback
	luid := c.opts.adapter.LUID()
	iw.mu.Unlock()

	if interfaceChangeCallback != nil {
		interfaceChangeCallback.Unregister()
	}
	for _, cb := range changeCallbacks4 {
		cb.Unregister()
	}
	for _, cb := range changeCallbacks6 {
		cb.Unregister()
	}

	iw.mu.Lock()
	if interfaceChangeCallback == iw.interfaceChangeCallback {
		iw.interfaceChangeCallback = nil
	}
	for len(changeCallbacks4) > 0 && len(iw.changeCallbacks4) > 0 {
		iw.changeCallbacks4 = iw.changeCallbacks4[1:]
		changeCallbacks4 = changeCallbacks4[1:]
	}
	for len(changeCallbacks6) > 0 && len(iw.changeCallbacks6) > 0 {
		iw.changeCallbacks6 = iw.changeCallbacks6[1:]
		changeCallbacks6 = changeCallbacks6[1:]
	}

	// firewall.DisableFirewall()

	if c.ipv4Supported {
		luid.FlushRoutes(windows.AF_INET)
		luid.FlushIPAddresses(windows.AF_INET)
		luid.FlushDNS(windows.AF_INET)
	}

	if c.ipv6Supported {
		luid.FlushRoutes(windows.AF_INET6)
		luid.FlushIPAddresses(windows.AF_INET6)
		luid.FlushDNS(windows.AF_INET6)
	}

	iw.mu.Unlock()

	return nil
}
