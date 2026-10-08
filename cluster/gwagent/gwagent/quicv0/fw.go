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

package quicv0

import (
	"net"

	"github.com/coreos/go-iptables/iptables"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"go.uber.org/zap"
)

const (
	fwChain     = "octelium-quic-fw"
	inputChain  = "octelium-quic-in"
	tableFilter = "filter"
)

type fwRule struct {
	isV6  bool
	chain string
	spec  []string
}

func getFWRules(gw *corev1.Gateway, cc *corev1.ClusterConfig) []fwRule {
	connSubnet := cc.Status.Network.QuicConnSubnet
	gwSubnet := gw.Status.Cidr

	hasV4 := gwSubnet.V4 != ""
	hasV6 := gwSubnet.V6 != ""

	ruleICMP := func(connSubnet, svcSubnet string) []string {
		return []string{
			"-i", devName,
			"-s", connSubnet,
			"-d", svcSubnet,
			"-p", "icmp",
			"-j", "ACCEPT",
		}
	}

	ruleBlockGWOut := func(connSubnet, gwIPRange string) []string {
		return []string{
			"-i", devName,
			"-s", connSubnet,
			"-d", gwIPRange,
			"-j", "DROP",
		}
	}

	ruleAllowSvc := func(connSubnet, svcSubnet string) []string {
		return []string{
			"-i", devName,
			"-s", connSubnet,
			"-d", svcSubnet,
			"-j", "ACCEPT",
		}
	}

	defaultRule := func(connSubnet string) []string {
		return []string{
			"-i", devName,
			"-s", connSubnet,
			"-j", "DROP",
		}
	}

	var ret []fwRule

	if hasV4 {
		gwRange := &net.IPNet{
			IP:   umetav1.ToDualStackNetwork(gwSubnet).ToGo().V4.IP,
			Mask: net.CIDRMask(28, 32),
		}

		ret = append(ret,
			fwRule{chain: fwChain, spec: ruleICMP(connSubnet.V4, gwSubnet.V4)},
			fwRule{chain: fwChain, spec: ruleBlockGWOut(connSubnet.V4, gwRange.String())},
			fwRule{chain: fwChain, spec: ruleAllowSvc(connSubnet.V4, gwSubnet.V4)},
			fwRule{chain: fwChain, spec: defaultRule(connSubnet.V4)},
			fwRule{chain: inputChain, spec: ruleICMP(connSubnet.V4, gwSubnet.V4)},
			fwRule{chain: inputChain, spec: ruleBlockGWOut(connSubnet.V4, gwRange.String())},
			fwRule{chain: inputChain, spec: defaultRule(connSubnet.V4)},
		)
	}

	if hasV6 {
		gwRange := &net.IPNet{
			IP:   umetav1.ToDualStackNetwork(gwSubnet).ToGo().V6.IP,
			Mask: net.CIDRMask(124, 128),
		}

		ret = append(ret,
			fwRule{isV6: true, chain: fwChain, spec: ruleICMP(connSubnet.V6, gwSubnet.V6)},
			fwRule{isV6: true, chain: fwChain, spec: ruleBlockGWOut(connSubnet.V6, gwRange.String())},
			fwRule{isV6: true, chain: fwChain, spec: ruleAllowSvc(connSubnet.V6, gwSubnet.V6)},
			fwRule{isV6: true, chain: fwChain, spec: defaultRule(connSubnet.V6)},
			fwRule{isV6: true, chain: inputChain, spec: ruleICMP(connSubnet.V6, gwSubnet.V6)},
			fwRule{isV6: true, chain: inputChain, spec: ruleBlockGWOut(connSubnet.V6, gwRange.String())},
			fwRule{isV6: true, chain: inputChain, spec: defaultRule(connSubnet.V6)},
		)
	}

	return ret
}

type iptablesCtl struct {
	iptv4 *iptables.IPTables
	iptv6 *iptables.IPTables
}

func newIPTables() (*iptablesCtl, error) {
	iptv4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, err
	}

	iptv6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return nil, err
	}

	return &iptablesCtl{iptv4: iptv4, iptv6: iptv6}, nil
}

func (i *iptablesCtl) get(isV6 bool) *iptables.IPTables {
	if isV6 {
		return i.iptv6
	}
	return i.iptv4
}

func (i *iptablesCtl) OnAdd(gw *corev1.Gateway, cc *corev1.ClusterConfig) error {
	hasV4 := gw.Status.Cidr.V4 != ""
	hasV6 := gw.Status.Cidr.V6 != ""

	var families []bool
	if hasV4 {
		families = append(families, false)
	}
	if hasV6 {
		families = append(families, true)
	}

	for _, isV6 := range families {
		if err := i.get(isV6).NewChain(tableFilter, fwChain); err != nil {
			return err
		}
		if err := i.get(isV6).NewChain(tableFilter, inputChain); err != nil {
			return err
		}
	}

	for _, rule := range getFWRules(gw, cc) {
		if err := i.get(rule.isV6).Append(tableFilter, rule.chain, rule.spec...); err != nil {
			return err
		}
	}

	for _, isV6 := range families {
		if err := i.get(isV6).Insert(tableFilter, "FORWARD", 1, "-j", fwChain); err != nil {
			return err
		}
		if err := i.get(isV6).Insert(tableFilter, "INPUT", 1, "-j", inputChain); err != nil {
			return err
		}
	}

	return nil
}

func (i *iptablesCtl) OnDelete() {
	for _, isV6 := range []bool{false, true} {
		ipt := i.get(isV6)

		ipt.DeleteIfExists(tableFilter, "FORWARD", "-j", fwChain)
		ipt.DeleteIfExists(tableFilter, "INPUT", "-j", inputChain)

		for _, chain := range []string{fwChain, inputChain} {
			if exists, err := ipt.ChainExists(tableFilter, chain); err != nil || !exists {
				continue
			}
			if err := ipt.ClearAndDeleteChain(tableFilter, chain); err != nil {
				zap.L().Debug("Could not delete the QUICv0 chain", zap.String("chain", chain), zap.Error(err))
			}
		}
	}
}

func setFirewall(gw *corev1.Gateway, cc *corev1.ClusterConfig) error {
	ipt, err := newIPTables()
	if err != nil {
		return err
	}

	ipt.OnDelete()

	return ipt.OnAdd(gw, cc)
}

func unsetFirewall() {
	ipt, err := newIPTables()
	if err != nil {
		zap.L().Debug("Could not create the iptables client", zap.Error(err))
		return
	}

	ipt.OnDelete()
}
