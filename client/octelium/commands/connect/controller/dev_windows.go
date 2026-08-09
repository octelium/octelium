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
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"golang.zx2c4.com/wireguard/windows/version"
)

func setTunDev() error {
	return nil
}

func (c *Controller) doInitDev(ctx context.Context) error {
	if c.isQUIC {
		err := c.doInitDevTUNQUICV0(ctx)
		if err == nil {
			zap.L().Debug("QUICV0 mode chosen: Wintun mode")
			return nil
		}
		zap.L().Debug("Could not init the Wintun implementation. Trying gVisor netstack mode.",
			zap.Error(err))

		c.unwindPartialDev()
	} else {
		err := c.doInitDevTUN(ctx)
		if err == nil {
			return nil
		}
		zap.L().Debug("Could not init TUN implementation. Trying gVisor netstack mode.",
			zap.Error(err))

		c.unwindPartialDev()
	}

	if err := c.doInitDevNetstack(ctx); err != nil {
		return errors.Errorf("Could not init netstack dev: %+v", err)
	}
	return nil
}

func (c *Controller) doInitDevTUNQUICV0(ctx context.Context) error {
	zap.L().Debug("Starting watching network interface",
		zap.String("userAgent", version.UserAgent()))

	if err := c.watchInterface(); err != nil {
		return err
	}

	if err := c.doSetTunDev(); err != nil {
		return err
	}

	if err := c.doInitDevQUICV0(ctx); err != nil {
		return err
	}

	c.configureIface()

	return nil
}

func (c *Controller) doSetTunDev() error {
	guid, err := c.getTunGUID()
	if err != nil {
		return err
	}

	name := c.getDevName("octelium-quicv0")

	zap.L().Debug("Creating the Wintun device",
		zap.String("name", name), zap.Int("mtu", c.getMTU()))

	var tundev tun.Device
	for i := 0; i < 15; i++ {
		if i > 0 {
			time.Sleep(time.Second)
			zap.L().Debug("Retrying the Wintun device creation after failure because system just booted",
				zap.Duration("sinceBoot", windows.DurationSinceBoot()), zap.Error(err))
		}

		tundev, err = tun.CreateTUNWithRequestedGUID(name, guid, c.getMTU())
		if err == nil || !services.StartedAtBoot() {
			break
		}
	}
	if err != nil {
		return errors.Errorf("Could not create the Wintun device: %+v", err)
	}

	c.tundev = tundev

	if realName, err := tundev.Name(); err == nil && realName != "" {
		c.c.Preferences.DeviceName = realName
	}

	zap.L().Debug("Successfully created the Wintun device",
		zap.String("name", c.c.Preferences.DeviceName),
		zap.Uint64("luid", uint64(c.getLUID())))

	return nil
}

func (c *Controller) doInitDevTUN(_ context.Context) error {

	var err error

	// zap.S().Debugf("getting conf")
	conf, err := c.getWgConf()
	if err != nil {
		return err
	}

	// logPrefix := fmt.Sprintf("[%s] ", conf.Name)
	// log.SetPrefix(logPrefix)

	zap.L().Debug("Stating watching network interface", zap.String("userAgent", version.UserAgent()))

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

	zap.L().Debug("Creating network adapter")
	for i := 0; i < 15; i++ {
		if i > 0 {
			time.Sleep(time.Second)
			zap.L().Debug("Retrying adapter creation after failure because system just booted",
				zap.Duration("sinceBoot", windows.DurationSinceBoot()), zap.Error(err))
		}
		c.opts.adapter, err = driver.CreateAdapter(
			strings.ReplaceAll(fmt.Sprintf("octelium-%s", c.c.Info.Cluster.Domain), ".", "-"),
			"WireGuard", guid)
		if err == nil || !services.StartedAtBoot() {
			break
		}
	}
	if err != nil {
		return err
	}

	driverVersion, err := driver.RunningVersion()
	if err != nil {
		zap.L().Warn("Could not determine driver version", zap.Error(err))
	} else {
		zap.L().Debug("Using WireGuardNT",
			zap.String("version", fmt.Sprintf("%d.%d", (driverVersion>>16)&0xffff, driverVersion&0xffff)))
	}

	err = c.opts.adapter.SetLogging(driver.AdapterLogOff)
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
	if c.opts.adapter == nil {
		return nil
	}

	if err := c.opts.adapter.SetAdapterState(driver.AdapterStateUp); err != nil {
		return err
	}

	return nil
}

func (c *Controller) doDeleteDev() error {
	if c.isNetstack {
		return nil
	}

	if err := c.destroyIface(); err != nil {
		zap.L().Debug("Could not destroy the interface", zap.Error(err))
	}

	if c.opts.adapter != nil {
		c.opts.adapter.Close()
		c.opts.adapter = nil
	}

	return nil
}

func (c *Controller) doSetDevAddrs() error {

	if c.isNetstack {
		return nil
	}

	luid := c.getLUID()
	if luid == 0 {
		return errors.Errorf("The network device is not initialized")
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
		if err := luid.SetIPAddressesForFamily(windows.AF_INET, ipv4Nets); err != nil {
			return err
		}
	}

	if c.ipv6Supported && len(ipv6Nets) > 0 {
		if err := luid.SetIPAddressesForFamily(windows.AF_INET6, ipv6Nets); err != nil {
			return err
		}
	}

	if err := c.setIPIF(); err != nil {
		return err
	}

	return nil
}

func (c *Controller) getGUID() (*windows.GUID, error) {
	return c.getGUIDFromSeed("octelium")
}

func (c *Controller) getTunGUID() (*windows.GUID, error) {
	return c.getGUIDFromSeed("octelium-quicv0")
}

func (c *Controller) getGUIDFromSeed(seed string) (*windows.GUID, error) {
	if c.c.Info == nil || c.c.Info.Cluster == nil {
		return nil, errors.Errorf("The Connection does not have Cluster info")
	}

	arg := fmt.Sprintf("%s-%s", seed, c.c.Info.Cluster.Domain)
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

	zap.L().Debug("Got adapter GUID", zap.String("guid", ret.String()))

	return ret, nil
}

func (c *Controller) getDevName(prefix string) string {
	return strings.ReplaceAll(
		fmt.Sprintf("%s-%s", prefix, c.c.Info.Cluster.Domain), ".", "-")
}

func (c *Controller) getLUID() winipcfg.LUID {
	if c.opts.adapter != nil {
		return c.opts.adapter.LUID()
	}

	if nativeTun, ok := c.tundev.(*tun.NativeTun); ok {
		return winipcfg.LUID(nativeTun.LUID())
	}

	return 0
}

/*
func (c *Controller) enableFirewall(dnsServers []net.IP) error {
	return firewall.EnableFirewall(uint64(c.getLUID()), true, dnsServers)
}

*/

const maxStoredInterfaceEvents = 200

type interfaceWatcherEvent struct {
	luid   winipcfg.LUID
	family winipcfg.AddressFamily
}

type interfaceWatcher struct {
	mu                      sync.Mutex
	luid                    winipcfg.LUID
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
		if notificationType != winipcfg.MibAddInstance {
			return
		}

		if !c.mu.TryLock() {
			zap.L().Debug("Could not acquire the controller lock. Skipping the interface change event")
			return
		}
		defer c.mu.Unlock()

		iw.mu.Lock()
		defer iw.mu.Unlock()

		if c.isClosed {
			return
		}

		if iw.luid == 0 {
			if len(iw.storedEvents) >= maxStoredInterfaceEvents {
				zap.L().Debug("Dropping interface change event. Too many stored events",
					zap.Uint64("luid", uint64(iface.InterfaceLUID)))
				return
			}
			iw.storedEvents = append(iw.storedEvents,
				interfaceWatcherEvent{iface.InterfaceLUID, iface.Family})
			return
		}

		if iface.InterfaceLUID != iw.luid {
			return
		}

		if err := c.doConfigureIface(); err != nil {
			zap.L().Error("Could not configure interface", zap.Error(err))
		}
	})
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) doConfigureIface() error {

	zap.L().Debug("Configuring the interface.....")

	if err := c.doSetDevAddrs(); err != nil {
		zap.L().Warn("Could not set addresses at cb", zap.Error(err))
		return err
	}

	if err := c.doSetRoutes(); err != nil {
		zap.L().Warn("Could not set routes at cb: %+v", zap.Error(err))
		return err
	}

	if err := c.doSetDNS(); err != nil {
		zap.L().Warn("Could not set DNS", zap.Error(err))
		return err
	}

	zap.L().Debug("Successfully configured the interface")
	return nil
}

func (c *Controller) configureIface() {
	iw := c.opts.ifaceWatcher
	luid := c.getLUID()
	if iw == nil || luid == 0 {
		return
	}

	iw.mu.Lock()
	iw.luid = luid
	iw.storedEvents = nil
	iw.mu.Unlock()

	if err := c.doConfigureIface(); err != nil {
		zap.L().Error("Could not configure interface", zap.Error(err))
	}
}

func (c *Controller) destroyIface() error {

	iw := c.opts.ifaceWatcher
	luid := c.getLUID()
	if iw == nil || luid == 0 {
		return nil
	}

	iw.mu.Lock()
	changeCallbacks4 := iw.changeCallbacks4
	changeCallbacks6 := iw.changeCallbacks6
	interfaceChangeCallback := iw.interfaceChangeCallback
	iw.luid = 0
	iw.storedEvents = nil
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

func (c *Controller) unwindPartialDev() {
	if c.quicEngine != nil {
		if err := c.quicEngine.close(); err != nil {
			zap.L().Debug("Could not close the QUIC engine", zap.Error(err))
		}
		c.quicEngine = nil
	}

	if c.opts.adapter != nil || c.tundev != nil {
		if err := c.destroyIface(); err != nil {
			zap.L().Debug("Could not destroy the interface", zap.Error(err))
		}
	}

	if c.opts.adapter != nil {
		if err := c.opts.adapter.Close(); err != nil {
			zap.L().Debug("Could not close the adapter", zap.Error(err))
		}
		c.opts.adapter = nil
	}

	if c.tundev != nil {
		if err := c.tundev.Close(); err != nil {
			zap.L().Debug("Could not close the TUN device", zap.Error(err))
		}
		c.tundev = nil
	}

	if iw := c.opts.ifaceWatcher; iw != nil {
		iw.mu.Lock()
		cb := iw.interfaceChangeCallback
		iw.interfaceChangeCallback = nil
		iw.luid = 0
		iw.storedEvents = nil
		iw.mu.Unlock()

		if cb != nil {
			cb.Unregister()
		}

		c.opts.ifaceWatcher = nil
	}
}
