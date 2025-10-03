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

package gw

import (
	"encoding/json"
	"os"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func addCNI(gw *corev1.Gateway, cc *corev1.ClusterConfig) error {
	if cc.Status == nil || cc.Status.Network == nil || cc.Status.Network.ClusterNetwork == nil {
		return errors.Errorf("ClusterNetwork addrs are not set")
	}

	v4Net := cc.Status.Network.ClusterNetwork.V4
	v6Net := cc.Status.Network.ClusterNetwork.V6

	rangeStartAddr, err := vutils.GetDualStackIPByIndex(gw.Status.Cidr, 16)
	if err != nil {
		return err
	}

	mode := ucorev1.ToClusterConfig(cc).GetNetworkMode()

	cni := map[string]any{
		"cniVersion":   "0.3.1",
		"name":         "octelium",
		"type":         "bridge",
		"bridge":       "octelium-bridge",
		"isGateway":    true,
		"forceAddress": false,
		"ipMasq":       false,
		"hairpinMode":  true,
		"ipam": map[string]any{
			"type":    "host-local",
			"dataDir": "/run/cni-ipam-state",
			"routes": func() []map[string]any {
				switch mode {
				case corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK:
					return []map[string]any{
						{
							"dst": v4Net,
						},

						{
							"dst": v6Net,
						},
					}
				case corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY:
					return []map[string]any{
						{
							"dst": v4Net,
						},
					}
				case corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY:
					return []map[string]any{
						{
							"dst": v6Net,
						},
					}
				default:
					return nil
				}

			}(),
			"ranges": func() [][]map[string]any {
				switch mode {
				case corev1.ClusterConfig_Status_NetworkConfig_DUAL_STACK:
					return [][]map[string]any{
						{
							{
								"subnet":     gw.Status.Cidr.V4,
								"rangeStart": rangeStartAddr.Ipv4,
							},
						},

						{
							{
								"subnet":     gw.Status.Cidr.V6,
								"rangeStart": rangeStartAddr.Ipv6,
							},
						},
					}
				case corev1.ClusterConfig_Status_NetworkConfig_V4_ONLY:
					return [][]map[string]any{
						{
							{
								"subnet":     gw.Status.Cidr.V4,
								"rangeStart": rangeStartAddr.Ipv4,
							},
						},
					}
				case corev1.ClusterConfig_Status_NetworkConfig_V6_ONLY:
					return [][]map[string]any{
						{
							{
								"subnet":     gw.Status.Cidr.V6,
								"rangeStart": rangeStartAddr.Ipv6,
							},
						},
					}
				default:
					return nil
				}
			}(),
		},
	}

	jsonBytes, err := json.MarshalIndent(cni, "", "    ")
	if err != nil {
		return err
	}

	zap.L().Debug("Writing CNI file", zap.String("content", string(jsonBytes)))

	if err := os.WriteFile("/etc/cni/multus/net.d/octelium.conf", jsonBytes, 0644); err != nil {
		return err
	}

	return nil
}

func deleteCNI(netw *corev1.Namespace) error {
	return os.Remove("/etc/cni/multus/net.d/octelium.conf")
}
