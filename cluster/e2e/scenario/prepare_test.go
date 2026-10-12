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
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	"sigs.k8s.io/yaml"
)

func TestCNIReadiness(t *testing.T) {
	for _, fail := range []string{"", "apply", "rollout"} {
		t.Run("failure="+fail, func(t *testing.T) {
			r, logPath := shellRunner(t, map[string]string{
				"kubectl": `
printf '%s\n' "$*" >> "$OCTELIUM_E2E_COMMAND_LOG"
if [ "$1" = apply ]; then
  cat > "$OCTELIUM_E2E_COMMAND_LOG-manifest"
fi
if [ "$1" = "$OCTELIUM_E2E_FAIL_COMMAND" ]; then
  exit 1
fi
`,
			})
			r.extraEnv["OCTELIUM_E2E_FAIL_COMMAND"] = fail

			err := r.stepCNIReadiness(t.Context(), r)
			if fail == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}

			data, err := os.ReadFile(logPath + "-manifest")
			require.NoError(t, err)
			ds := &appsv1.DaemonSet{}
			require.NoError(t, yaml.Unmarshal(data, ds))
			assert.Equal(t, "octelium-e2e-cni", ds.Name)
			assert.Equal(t, "kube-system", ds.Namespace)
			assert.False(t, ds.Spec.Template.Spec.HostNetwork,
				"the readiness check must exercise the CNI instead of bypassing it")
			assert.Empty(t, ds.Spec.Template.Spec.NodeSelector, "the check must cover every node")
			assert.Empty(t, ds.Spec.Template.Spec.Affinity)
			assert.Equal(t, ds.Spec.Selector.MatchLabels, ds.Spec.Template.Labels)

			data, err = os.ReadFile(logPath)
			require.NoError(t, err)
			calls := strings.Split(strings.TrimSpace(string(data)), "\n")
			if fail == "apply" {
				assert.Equal(t, []string{"apply -f -"}, calls)
				return
			}
			want := []string{
				"apply -f -",
				"rollout status daemonset/octelium-e2e-cni -n kube-system --timeout=5m",
			}
			if fail == "rollout" {
				want = append(want, "describe pods -n kube-system -l app.kubernetes.io/name=octelium-e2e-cni")
			} else {
				want = append(want, "delete daemonset/octelium-e2e-cni -n kube-system --wait=true --timeout=60s")
			}
			assert.Equal(t, want, calls, "failed networking checks must keep the pods for diagnostics")
		})
	}
}

func TestPrepareChecksCNIBeforeStorage(t *testing.T) {
	r := &Runner{}
	var names []string
	for _, step := range r.prepareSteps() {
		names = append(names, step.Name)
	}
	multus := slices.Index(names, "cni/multus")
	readiness := slices.Index(names, "cni/readiness")
	redis := slices.Index(names, "storage/redis")
	postgres := slices.Index(names, "storage/postgres")
	for _, idx := range []int{multus, readiness, redis, postgres} {
		require.NotEqual(t, -1, idx)
	}
	assert.Less(t, multus, readiness)
	assert.Less(t, readiness, redis)
	assert.Less(t, readiness, postgres)
}

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
