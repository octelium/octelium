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

package scenario

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultusReadiness(t *testing.T) {
	for _, fail := range []string{"", "helm", "kubectl"} {
		t.Run("failure="+fail, func(t *testing.T) {
			commands := map[string]string{}
			for _, name := range []string{"helm", "kubectl"} {
				commands[name] = `
printf '%s\0' "${0##*/}" "$@" >> "$OCTELIUM_E2E_COMMAND_LOG"
printf '\0' >> "$OCTELIUM_E2E_COMMAND_LOG"
`
				if name == fail {
					commands[name] += "exit 1\n"
				}
			}
			r, logPath := shellRunner(t, commands)
			r.Scenario = MustGet("k3s-flannel-nodes4-dedicated")

			err := r.stepMultus(t.Context(), r)
			if fail == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}

			data, err := os.ReadFile(logPath)
			require.NoError(t, err)
			calls := strings.Split(strings.TrimSuffix(string(data), "\x00\x00"), "\x00\x00")
			helmArgs := strings.Split(calls[0], "\x00")
			assert.Equal(t, "helm", helmArgs[0])
			assert.Contains(t, helmArgs, "hostCNIBinDir="+k3sFlannelBinDir)
			assert.Contains(t, helmArgs, "hostCNINetDir="+k3sFlannelNetDir)
			assert.Contains(t, helmArgs, `tolerations=[{"key":"octelium.com/gateway-init","operator":"Exists","effect":"NoSchedule"}]`)

			if fail == "helm" {
				require.Len(t, calls, 1, "a failed chart installation must stop preparation")
				return
			}
			require.Len(t, calls, 2)
			assert.Equal(t, []string{
				"kubectl", "rollout", "status", "daemonset", "-n", "kube-system",
				"-l", "app.kubernetes.io/instance=octelium-multus", "--timeout=10m",
			}, strings.Split(calls[1], "\x00"), "all Multus pods must be ready before preparation continues")
		})
	}
}

func TestStorageResourcesArgs(t *testing.T) {
	t.Run("no resources keep the chart preset", func(t *testing.T) {
		assert.Empty(t, storageResourcesArgs("master", nil))
		assert.Empty(t, storageResourcesArgs("master", &StorageResources{}))
	})

	t.Run("only the set values are passed", func(t *testing.T) {
		assert.Equal(t, []string{
			"--set primary.resources.requests.cpu=1",
			"--set primary.resources.requests.memory=512Mi",
			"--set primary.resources.limits.memory=2Gi",
		}, storageResourcesArgs("primary", &StorageResources{
			CPURequest:    "1",
			MemoryRequest: "512Mi",
			MemoryLimit:   "2Gi",
		}))

		assert.Equal(t, []string{
			"--set master.resources.limits.memory=4Gi",
		}, storageResourcesArgs("master", &StorageResources{
			MemoryLimit: "4Gi",
		}))
	})
}
