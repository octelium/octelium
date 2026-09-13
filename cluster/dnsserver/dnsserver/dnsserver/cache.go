/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package dnsserver

import (
	"net"
	"sync"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
)

type cache struct {
	sync.RWMutex
	cMap map[string]*cacheVal
}

type cacheVal struct {
	svc *corev1.Service
}

func newCache() *cache {
	return &cache{
		cMap: make(map[string]*cacheVal),
	}
}

func (c *cache) set(svc *corev1.Service) {

	cacheVal := &cacheVal{
		svc: svc,
	}

	if !ucorev1.ToService(svc).HasAddresses() {
		c.delete(svc)
		return
	}

	c.Lock()

	if svc.Status.PrimaryHostname != "" {
		c.cMap[svc.Status.PrimaryHostname] = cacheVal
	}

	for _, hostname := range svc.Status.AdditionalHostnames {
		c.cMap[hostname] = cacheVal
	}

	c.Unlock()
}

func (c *cache) delete(svc *corev1.Service) {

	c.Lock()

	if svc.Status.PrimaryHostname != "" {
		delete(c.cMap, svc.Status.PrimaryHostname)
	}

	for _, hostname := range svc.Status.AdditionalHostnames {
		delete(c.cMap, hostname)
	}

	c.Unlock()
}

func (c *cache) get(arg string, typ uint16) net.IP {
	if arg == "" {
		arg = "default.default"
	}
	c.RLock()
	defer c.RUnlock()

	res, ok := c.cMap[arg]
	if !ok {
		return nil
	}

	var addrs []string
	switch typ {
	case dns.TypeA:
		addrs = ucorev1.ToService(res.svc).AddressesV4()
	case dns.TypeAAAA:
		addrs = ucorev1.ToService(res.svc).AddressesV6()
	default:
		return nil
	}

	if len(addrs) == 0 {
		return nil
	}

	return net.ParseIP(addrs[utilrand.GetRandomRangeMath(0, len(addrs)-1)])
}

func (c *cache) has(arg string) bool {
	if arg == "" {
		arg = "default.default"
	}
	c.RLock()
	defer c.RUnlock()

	res, ok := c.cMap[arg]
	return ok && res != nil
}
