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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func (c *Controller) toUAPI() string {

	var output strings.Builder
	output.WriteString(fmt.Sprintf("private_key=%s\n", wgKeyB64ToHex(c.wgPrivateKey.String())))

	output.WriteString("replace_peers=true\n")

	for _, gw := range c.c.Connection.Gateways {
		output.WriteString(fmt.Sprintf("public_key=%s\n", wgKeyB64ToHex(gw.Wireguard.PublicKey)))
		output.WriteString(fmt.Sprintf("endpoint=%s\n", net.JoinHostPort(gw.Addresses[0], fmt.Sprintf("%d", gw.Wireguard.Port))))
		output.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", c.c.Preferences.KeepAliveSeconds))

		output.WriteString("replace_allowed_ips=true\n")

		for _, svcCIDR := range gw.CIDRs {
			ip, _, _ := net.ParseCIDR(svcCIDR)
			if govalidator.IsIPv4(ip.String()) && c.ipv4Supported {
				output.WriteString(fmt.Sprintf("allowed_ip=%s\n", svcCIDR))
			} else if govalidator.IsIPv6(ip.String()) && c.ipv6Supported {
				output.WriteString(fmt.Sprintf("allowed_ip=%s\n", svcCIDR))
			}
		}

	}
	return output.String()
}

func wgKeyB64ToHex(arg string) string {
	k, _ := base64.StdEncoding.DecodeString(arg)
	return hex.EncodeToString(k[:])
}

func fromUAPI(arg string) *wgtypes.Config {
	// Used ONLY for testing puproses. Not complete translation.

	ret := &wgtypes.Config{}

	scanner := bufio.NewScanner(strings.NewReader(arg))

	keyFromHex := func(val string) wgtypes.Key {
		k, _ := hex.DecodeString(val)
		key, _ := wgtypes.ParseKey(base64.StdEncoding.EncodeToString(k))
		return key
	}

	for scanner.Scan() {
		line := scanner.Text()
		lst := strings.Split(line, "=")
		key := lst[0]
		val := lst[1]

		switch key {
		case "private_key":
			sk := keyFromHex(val)
			ret.PrivateKey = &sk
		case "listen_port":
			port, _ := strconv.Atoi(val)
			ret.ListenPort = &port
		case "public_key":
			ret.Peers = append(ret.Peers, wgtypes.PeerConfig{
				PublicKey: keyFromHex(val),
				Endpoint:  &net.UDPAddr{},
			})
		case "allowed_ip":
			idx := len(ret.Peers) - 1
			_, ipnet, _ := net.ParseCIDR(val)
			ret.Peers[idx].AllowedIPs = append(ret.Peers[idx].AllowedIPs, *ipnet)
		}

	}
	return ret
}
