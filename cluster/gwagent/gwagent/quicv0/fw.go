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
	"github.com/coreos/go-iptables/iptables"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	tableFilter  = "filter"
	chainForward = "FORWARD"
)

type fwRule struct {
	isV6 bool
	spec []string
}

func getFWRules(gw *corev1.Gateway, cc *corev1.ClusterConfig) []fwRule {
	connSubnet := cc.Status.Network.QuicConnSubnet
	gwSubnet := gw.Status.Cidr

	ruleAllowSvc := func(connSubnet, svcSubnet string) []string {
		return []string{
			"-i", devName,
			"-s", connSubnet,
			"-d", svcSubnet,
			"-j", "ACCEPT",
		}
	}

	var ret []fwRule

	if gwSubnet.V4 != "" {
		ret = append(ret, fwRule{spec: ruleAllowSvc(connSubnet.V4, gwSubnet.V4)})
	}

	if gwSubnet.V6 != "" {
		ret = append(ret, fwRule{isV6: true, spec: ruleAllowSvc(connSubnet.V6, gwSubnet.V6)})
	}

	return ret
}

type legacyChain struct {
	parent string
	chain  string
}

var legacyChains = []legacyChain{
	{parent: chainForward, chain: "octelium-quic-fw"},
	{parent: "INPUT", chain: "octelium-quic-in"},
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

func (i *iptablesCtl) OnAdd(rules []fwRule) error {
	for _, rule := range rules {
		if err := deleteRules(i.get(rule.isV6), chainForward, rule.spec...); err != nil {
			return err
		}
		if err := i.get(rule.isV6).Insert(tableFilter, chainForward, 1, rule.spec...); err != nil {
			return err
		}
	}

	return nil
}

func (i *iptablesCtl) OnDelete(rules []fwRule) {
	for _, rule := range rules {
		if err := deleteRules(i.get(rule.isV6), chainForward, rule.spec...); err != nil {
			zap.L().Warn("Could not delete the QUICv0 firewall rule",
				zap.Strings("spec", rule.spec), zap.Error(err))
		}
	}
}

func (i *iptablesCtl) deleteLegacyChains() {
	for _, isV6 := range []bool{false, true} {
		ipt := i.get(isV6)

		for _, legacy := range legacyChains {
			if exists, err := ipt.ChainExists(tableFilter, legacy.chain); err != nil || !exists {
				continue
			}

			zap.L().Debug("Deleting the legacy QUICv0 chain",
				zap.String("chain", legacy.chain), zap.Bool("isV6", isV6))

			if err := deleteRules(ipt, legacy.parent, "-j", legacy.chain); err != nil {
				zap.L().Warn("Could not delete the jump rules to the legacy QUICv0 chain",
					zap.String("chain", legacy.chain), zap.Error(err))
				continue
			}

			if err := ipt.ClearAndDeleteChain(tableFilter, legacy.chain); err != nil {
				zap.L().Warn("Could not delete the legacy QUICv0 chain",
					zap.String("chain", legacy.chain), zap.Error(err))
			}
		}
	}
}

const maxDuplicateRules = 64

func deleteRules(ipt *iptables.IPTables, chain string, spec ...string) error {
	for range maxDuplicateRules {
		exists, err := ipt.Exists(tableFilter, chain, spec...)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		if err := ipt.Delete(tableFilter, chain, spec...); err != nil {
			return err
		}
	}

	return errors.Errorf("Could not delete all the duplicate rules of the %s chain", chain)
}

func setFirewall(rules []fwRule) error {
	ipt, err := newIPTables()
	if err != nil {
		return err
	}

	ipt.deleteLegacyChains()

	return ipt.OnAdd(rules)
}

func unsetFirewall(rules []fwRule) {
	ipt, err := newIPTables()
	if err != nil {
		zap.L().Debug("Could not create the iptables client", zap.Error(err))
		return
	}

	ipt.OnDelete(rules)
	ipt.deleteLegacyChains()
}
