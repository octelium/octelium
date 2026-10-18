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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	osuser "os/user"
)

func newTstFWCC() *corev1.ClusterConfig {
	return &corev1.ClusterConfig{
		Status: &corev1.ClusterConfig_Status{
			Network: &corev1.ClusterConfig_Status_Network{
				QuicConnSubnet: &metav1.DualStackNetwork{
					V4: "100.66.0.0/16",
					V6: "fdee::2:0:0:0/80",
				},
			},
		},
	}
}

func newTstFWGW(v4, v6 string) *corev1.Gateway {
	return &corev1.Gateway{
		Status: &corev1.Gateway_Status{
			Cidr: &metav1.DualStackNetwork{
				V4: v4,
				V6: v6,
			},
		},
	}
}

func TestGetFWRules(t *testing.T) {
	cc := newTstFWCC()

	assert.Equal(t, []fwRule{
		{
			spec: []string{"-i", devName, "-s", "100.66.0.0/16", "-d", "100.64.1.0/24", "-j", "ACCEPT"},
		},
		{
			isV6: true,
			spec: []string{"-i", devName, "-s", "fdee::2:0:0:0/80", "-d", "fdee::100:0/112", "-j", "ACCEPT"},
		},
	}, getFWRules(newTstFWGW("100.64.1.0/24", "fdee::100:0/112"), cc))

	assert.Equal(t, []fwRule{
		{
			spec: []string{"-i", devName, "-s", "100.66.0.0/16", "-d", "100.64.1.0/24", "-j", "ACCEPT"},
		},
	}, getFWRules(newTstFWGW("100.64.1.0/24", ""), cc))

	assert.Equal(t, []fwRule{
		{
			isV6: true,
			spec: []string{"-i", devName, "-s", "fdee::2:0:0:0/80", "-d", "fdee::100:0/112", "-j", "ACCEPT"},
		},
	}, getFWRules(newTstFWGW("", "fdee::100:0/112"), cc))
}

func TestSetFirewall(t *testing.T) {
	{
		usr, err := osuser.Current()
		assert.Nil(t, err)
		if usr.Uid != "0" {
			zap.L().Warn("Skipping this test since the running user is not root")
			return
		}
	}

	rules := getFWRules(newTstFWGW("100.64.1.0/24", "fdee::100:0/112"), newTstFWCC())
	assert.Equal(t, 2, len(rules))

	ipt, err := newIPTables()
	assert.Nil(t, err)

	unsetFirewall(rules)
	t.Cleanup(func() {
		unsetFirewall(rules)
	})

	assertRuleExists := func(rule fwRule, expected bool) {
		exists, err := ipt.get(rule.isV6).Exists(tableFilter, chainForward, rule.spec...)
		assert.Nil(t, err)
		assert.Equal(t, expected, exists)
	}

	assertNoLegacyChains := func() {
		for _, isV6 := range []bool{false, true} {
			for _, legacy := range legacyChains {
				exists, err := ipt.get(isV6).ChainExists(tableFilter, legacy.chain)
				assert.Nil(t, err)
				assert.False(t, exists)
			}
		}
	}

	for _, isV6 := range []bool{false, true} {
		for _, legacy := range legacyChains {
			err = ipt.get(isV6).NewChain(tableFilter, legacy.chain)
			assert.Nil(t, err)
			err = ipt.get(isV6).Append(tableFilter, legacy.chain, "-i", devName, "-j", "DROP")
			assert.Nil(t, err)

			if !isV6 {
				for range 2 {
					err = ipt.get(isV6).Insert(tableFilter, legacy.parent, 1, "-j", legacy.chain)
					assert.Nil(t, err)
				}
			}
		}
	}

	for _, rule := range rules {
		for range 2 {
			err = ipt.get(rule.isV6).Insert(tableFilter, chainForward, 1, rule.spec...)
			assert.Nil(t, err)
		}
	}

	err = setFirewall(rules)
	assert.Nil(t, err)

	err = setFirewall(rules)
	assert.Nil(t, err)

	assertNoLegacyChains()

	for _, rule := range rules {
		assertRuleExists(rule, true)

		err = ipt.get(rule.isV6).Delete(tableFilter, chainForward, rule.spec...)
		assert.Nil(t, err)
		assertRuleExists(rule, false)
	}

	err = setFirewall(rules)
	assert.Nil(t, err)

	for _, rule := range rules {
		assertRuleExists(rule, true)
	}

	unsetFirewall(rules)

	for _, rule := range rules {
		assertRuleExists(rule, false)
	}
	assertNoLegacyChains()
}
