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

package nodeinit

import (
	"context"
	"os"
	"os/exec"

	"github.com/octelium/octelium/cluster/common/k8sutils"
	"go.uber.org/zap"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Run(ctx context.Context) error {

	if err := exec.Command("modprobe", "ip6table_filter").Run(); err != nil {
		zap.L().Warn("Could not modprobe ip6table_filter", zap.Error(err))
	}

	nodeName := os.Getenv("OCTELIUM_NODE")

	k8sC, err := k8sutils.NewClient(ctx, nil)
	if err != nil {
		return err
	}

	node, err := k8sC.CoreV1().Nodes().Get(ctx, nodeName, k8smetav1.GetOptions{})
	if err != nil {
		return err
	}

	_, ok := node.Labels["octelium.com/wireguard-installed"]
	if ok {
		return nil
	}

	err = exec.Command("modprobe", "wireguard").Run()
	if err == nil {
		node, err := k8sC.CoreV1().Nodes().Get(ctx, nodeName, k8smetav1.GetOptions{})
		if err != nil {
			return err
		}
		node.Labels["octelium.com/wireguard-installed"] = ""
		_, err = k8sC.CoreV1().Nodes().Update(ctx, node, k8smetav1.UpdateOptions{})
		if err != nil {
			return err
		}

		zap.L().Debug("WireGuard is installed! Exiting successfully...")
		return nil
	} else {
		zap.L().Warn("Could not modprobe wireguard", zap.Error(err))
	}

	return nil
}
