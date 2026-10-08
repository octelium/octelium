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
)

func TestGetFWRules(t *testing.T) {
	cc := &corev1.ClusterConfig{
		Status: &corev1.ClusterConfig_Status{
			Network: &corev1.ClusterConfig_Status_Network{
				QuicConnSubnet: &metav1.DualStackNetwork{
					V4: "100.66.0.0/16",
					V6: "fdee::2:0:0:0/80",
				},
			},
		},
	}

	newGW := func(v4, v6 string) *corev1.Gateway {
		return &corev1.Gateway{
			Status: &corev1.Gateway_Status{
				Cidr: &metav1.DualStackNetwork{
					V4: v4,
					V6: v6,
				},
			},
		}
	}

	byChain := func(rules []fwRule, isV6 bool, chain string) [][]string {
		var ret [][]string
		for _, rule := range rules {
			if rule.isV6 == isV6 && rule.chain == chain {
				ret = append(ret, rule.spec)
			}
		}
		return ret
	}

	{
		rules := getFWRules(newGW("100.64.1.0/24", "fdee::100:0/112"), cc)
		assert.Equal(t, 14, len(rules))

		assert.Equal(t, [][]string{
			{"-i", devName, "-s", "100.66.0.0/16", "-d", "100.64.1.0/24", "-p", "icmp", "-j", "ACCEPT"},
			{"-i", devName, "-s", "100.66.0.0/16", "-d", "100.64.1.0/28", "-j", "DROP"},
			{"-i", devName, "-s", "100.66.0.0/16", "-d", "100.64.1.0/24", "-j", "ACCEPT"},
			{"-i", devName, "-s", "100.66.0.0/16", "-j", "DROP"},
		}, byChain(rules, false, fwChain))

		assert.Equal(t, [][]string{
			{"-i", devName, "-s", "100.66.0.0/16", "-d", "100.64.1.0/24", "-p", "icmp", "-j", "ACCEPT"},
			{"-i", devName, "-s", "100.66.0.0/16", "-d", "100.64.1.0/28", "-j", "DROP"},
			{"-i", devName, "-s", "100.66.0.0/16", "-j", "DROP"},
		}, byChain(rules, false, inputChain))

		assert.Equal(t, [][]string{
			{"-i", devName, "-s", "fdee::2:0:0:0/80", "-d", "fdee::100:0/112", "-p", "icmp", "-j", "ACCEPT"},
			{"-i", devName, "-s", "fdee::2:0:0:0/80", "-d", "fdee::100:0/124", "-j", "DROP"},
			{"-i", devName, "-s", "fdee::2:0:0:0/80", "-d", "fdee::100:0/112", "-j", "ACCEPT"},
			{"-i", devName, "-s", "fdee::2:0:0:0/80", "-j", "DROP"},
		}, byChain(rules, true, fwChain))

		assert.Equal(t, [][]string{
			{"-i", devName, "-s", "fdee::2:0:0:0/80", "-d", "fdee::100:0/112", "-p", "icmp", "-j", "ACCEPT"},
			{"-i", devName, "-s", "fdee::2:0:0:0/80", "-d", "fdee::100:0/124", "-j", "DROP"},
			{"-i", devName, "-s", "fdee::2:0:0:0/80", "-j", "DROP"},
		}, byChain(rules, true, inputChain))
	}

	{
		rules := getFWRules(newGW("100.64.1.0/24", ""), cc)
		assert.Equal(t, 7, len(rules))
		for _, rule := range rules {
			assert.False(t, rule.isV6)
		}
	}

	{
		rules := getFWRules(newGW("", "fdee::100:0/112"), cc)
		assert.Equal(t, 7, len(rules))
		for _, rule := range rules {
			assert.True(t, rule.isV6)
		}
	}
}
