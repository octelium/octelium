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
	"net"
	"text/template"

	"github.com/asaskevich/govalidator"
	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"go.uber.org/zap"
)

const resolvConfTemplate = `
{{range .Servers}}
nameserver {{.}}
{{end}}
nameserver 8.8.8.8

search {{range .Domains}}{{.}} {{end}}
`

type resolvConfArgs struct {
	Servers []string
	Domains []string
}

func (c *Controller) getResolvConf() ([]byte, error) {
	t, err := template.New("resolvconf").Parse(resolvConfTemplate)
	if err != nil {
		return nil, err
	}

	var tpl bytes.Buffer

	args := &resolvConfArgs{
		Servers: c.getDNSServers(),
		Domains: c.getDNSSearchDomains(),
	}

	if err := t.Execute(&tpl, args); err != nil {
		return nil, err
	}

	return tpl.Bytes(), nil

}

func (c *Controller) getCurrentDNS() net.IP {
	c.dnsServers.Lock()
	defer c.dnsServers.Unlock()
	if len(c.dnsServers.servers) == 0 {
		return nil
	}
	return c.dnsServers.servers[0]
}

func (c *Controller) SetDNS() error {

	if c.c.Preferences.RuntimeMode == cliconfigv1.Connection_Preferences_CONTAINER {
		zap.S().Debugf("Container mode. Not setting DNS")
		return nil
	}

	dnsServers := c.getDNSServers()
	var curServers []net.IP
	for _, dnsServer := range dnsServers {
		curServers = append(curServers, net.ParseIP(dnsServer))
	}

	c.dnsServers.Lock()
	c.dnsServers.servers = curServers
	c.dnsServers.Unlock()

	if c.isNetstack || c.c.Preferences.IgnoreDNS || len(dnsServers) == 0 {
		zap.S().Debugf("Ignoring setting DNS")
		return nil
	}

	if err := c.doSetDNS(); err != nil {
		zap.S().Errorf("Could not set DNS: %s", err)
	}
	return nil
}

func (c *Controller) UnsetDNS() error {
	zap.S().Debugf("Unsetting DNS")
	if c.isNetstack || c.c.Preferences.IgnoreDNS {
		return nil
	}
	if c.c.Preferences.RuntimeMode == cliconfigv1.Connection_Preferences_CONTAINER {
		zap.S().Debugf("Container mode. Not unsetting DNS")
		return nil
	}

	if err := c.doUnsetDNS(); err != nil {
		zap.S().Errorf("Could not unset DNS: %s", err)
	}
	return nil
}

func (c *Controller) getDNSServers() []string {
	if c.c.Preferences.LocalDNS.IsEnabled {
		host, _, _ := net.SplitHostPort(c.c.Preferences.LocalDNS.ListenAddress)
		return []string{
			host,
		}
	}

	return c.getClusterDNSServers()
}

func (c *Controller) getClusterDNSServers() []string {
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
	return c.getClusterDNSServers()
}

func (c *Controller) getDNSSearchDomains() []string {
	return []string{
		fmt.Sprintf("local.%s", c.c.Info.Cluster.Domain),
	}
}
