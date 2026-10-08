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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	AgentNamePrefix = "octelium-e2e-agent-"

	agentNetwork        = "octelium-e2e"
	agentNetworkSubnet  = "172.29.0.0/16"
	agentNetworkGateway = "172.29.0.1"
	agentNetworkIPRange = "172.29.128.0/17"

	agentDataDirDefault  = "/mnt/octelium-e2e"
	agentDataDirFallback = "/var/lib/octelium-e2e"

	mirrorImage = "registry:2"
	mirrorPort  = 5000

	gatewayHostsMarker = "# octelium-e2e-gateway"
)

type registryMirror struct {
	name     string
	ip       string
	registry string
	remote   string
}

var registryMirrors = []registryMirror{
	{
		name:     "octelium-e2e-mirror-docker",
		ip:       "172.29.0.2",
		registry: "docker.io",
		remote:   "https://registry-1.docker.io",
	},
	{
		name:     "octelium-e2e-mirror-ghcr",
		ip:       "172.29.0.3",
		registry: "ghcr.io",
		remote:   "https://ghcr.io",
	},
}

var agentArgsDefault = []string{
	"--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%",
	"--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%",
	"--kubelet-arg=image-gc-high-threshold=100",
	"--kubelet-arg=max-pods=60",
}

func AgentName(idx int) string {
	return fmt.Sprintf("%s%d", AgentNamePrefix, idx)
}

func IsAgentNode(name string) bool {
	return strings.HasPrefix(name, AgentNamePrefix)
}

func (p *K3s) agentDataDir() string {
	if p.AgentDataDir != "" && p.AgentDataDir != agentDataDirDefault {
		return p.AgentDataDir
	}

	if info, err := os.Stat(filepath.Dir(agentDataDirDefault)); err == nil && info.IsDir() {
		return agentDataDirDefault
	}

	return agentDataDirFallback
}

func (p *K3s) agentArgs() []string {
	if len(p.AgentArgs) > 0 {
		return p.AgentArgs
	}
	return agentArgsDefault
}

func registriesYAML() string {
	var b strings.Builder
	b.WriteString("mirrors:\n")
	for _, m := range registryMirrors {
		fmt.Fprintf(&b, "  %s:\n    endpoint:\n      - \"http://%s:%d\"\n", m.registry, m.ip, mirrorPort)
	}
	return b.String()
}

func (p *K3s) stepWaitServerReady(ctx context.Context, r *Runner) error {
	k8sC, err := r.K8sC()
	if err != nil {
		return err
	}

	return pollUntil(ctx, "the k3s server node to become Ready", 10*minute, 3*second,
		func(ctx context.Context) error {
			nodes, err := k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{
				LabelSelector: nodeSelectorServer,
			})
			if err != nil {
				return err
			}
			if len(nodes.Items) == 0 {
				return errors.Errorf("The k3s server node has not registered yet")
			}

			for i := range nodes.Items {
				if reason := nodeNotReady(&nodes.Items[i]); reason != "" {
					return errors.Errorf("%s", reason)
				}
			}

			return nil
		})
}

func (p *K3s) stepAgentNetwork(ctx context.Context, r *Runner) error {
	return r.Bash(ctx, fmt.Sprintf(`
if sudo docker network inspect %[1]s >/dev/null 2>&1; then
  echo "the docker network %[1]s already exists"
  exit 0
fi

sudo docker network create \
  --driver bridge \
  --subnet %[2]s \
  --ip-range %[3]s \
  --gateway %[4]s \
  --opt com.docker.network.driver.mtu=1500 \
  %[1]s
`, agentNetwork, agentNetworkSubnet, agentNetworkIPRange, agentNetworkGateway))
}

func (p *K3s) stepAgentMirrors(ctx context.Context, r *Runner) error {
	dataDir := p.agentDataDir()

	var b strings.Builder
	for _, m := range registryMirrors {
		fmt.Fprintf(&b, `
if ! sudo docker inspect %[1]s >/dev/null 2>&1; then
  sudo mkdir -p %[2]s/%[1]s
  sudo docker run -d --name %[1]s --restart unless-stopped \
    --network %[3]s --ip %[4]s \
    -v %[2]s/%[1]s:/var/lib/registry \
    -e REGISTRY_PROXY_REMOTEURL=%[5]s \
    -e REGISTRY_HTTP_ADDR=0.0.0.0:%[6]d \
    -e REGISTRY_LOG_LEVEL=warn \
    %[7]s
fi
`, m.name, dataDir, agentNetwork, m.ip, m.remote, mirrorPort, mirrorImage)
	}

	fmt.Fprintf(&b, `
sudo mkdir -p %[1]s
printf '%%s' %[2]s | sudo tee %[1]s/registries.yaml >/dev/null
`, dataDir, shellQuote(registriesYAML()))

	return r.Bash(ctx, b.String())
}

func (p *K3s) stepStartAgents(ctx context.Context, r *Runner) error {
	serverIP, err := p.ExternalIP(ctx, r)
	if err != nil {
		return err
	}

	dataDir := p.agentDataDir()

	var args []string
	for _, arg := range p.agentArgs() {
		args = append(args, shellQuote(arg))
	}

	var b strings.Builder
	fmt.Fprintf(&b, `
VERSION=$(k3s --version | head -n1 | awk '{print $3}')
if [ -z "$VERSION" ]; then
  echo "could not determine the k3s server version" >&2
  exit 1
fi
IMAGE="rancher/k3s:${VERSION/+/-}"
sudo docker image inspect "$IMAGE" >/dev/null 2>&1 || sudo docker pull "$IMAGE"

TOKEN=$(sudo cat /var/lib/rancher/k3s/server/node-token)
if [ -z "$TOKEN" ]; then
  echo "could not read the k3s node token" >&2
  exit 1
fi

start_agent() {
  NAME="$1"
  if sudo docker inspect "$NAME" >/dev/null 2>&1; then
    echo "the agent $NAME already exists"
    return 0
  fi

  sudo mkdir -p %[1]s/"$NAME"
  sudo docker run -d --name "$NAME" --hostname "$NAME" \
    --privileged \
    --network %[2]s \
    --tmpfs /run --tmpfs /var/run \
    --ulimit nofile=1048576:1048576 \
    -v /lib/modules:/lib/modules:ro \
    -v %[1]s/"$NAME":/var/lib/rancher/k3s \
    -v %[1]s/registries.yaml:/etc/rancher/k3s/registries.yaml:ro \
    -e K3S_URL=https://%[3]s:6443 \
    -e K3S_TOKEN="$TOKEN" \
    "$IMAGE" agent --node-name "$NAME" %[4]s
}
`, dataDir, agentNetwork, serverIP, strings.Join(args, " "))

	for i := 1; i <= p.Agents; i++ {
		fmt.Fprintf(&b, "start_agent %s\n", AgentName(i))
	}

	b.WriteString(`sudo docker ps --filter name=^` + AgentNamePrefix +
		` --format '{{.Names}} {{.Status}} {{.Networks}}'` + "\n")

	if err := r.Bash(ctx, b.String()); err != nil {
		return errors.Errorf("%+v\n%s", err, p.agentDiagnostics(ctx, r))
	}

	zap.L().Info("Started the k3s agent nodes",
		zap.Int("agents", p.Agents), zap.String("server", serverIP))

	return nil
}

func (p *K3s) agentDiagnostics(ctx context.Context, r *Runner) string {
	if !p.hasAgents() {
		return ""
	}

	out, err := r.BashOutput(ctx, fmt.Sprintf(`
echo "--- agent containers ---"
sudo docker ps -a --filter name=^%[1]s --format '{{.Names}} {{.Status}}' 2>&1
for c in $(sudo docker ps -a --filter name=^%[1]s --format '{{.Names}}' 2>/dev/null | head -n 4); do
  echo "--- $c ---"
  sudo docker logs --tail 30 "$c" 2>&1
done
`, AgentNamePrefix))
	if err != nil {
		return fmt.Sprintf("<could not collect the agent diagnostics: %+v>\n%s", err, out)
	}

	return out
}

func (p *K3s) teardownAgents(ctx context.Context, r *Runner) error {
	return r.Bash(ctx, fmt.Sprintf(`
for c in $(sudo docker ps -aq --filter name=^octelium-e2e- 2>/dev/null); do
  sudo docker rm -f "$c" >/dev/null 2>&1 || true
done
sudo docker network rm %[1]s >/dev/null 2>&1 || true
sudo rm -rf %[2]s
sudo sed -i '/%[3]s$/d' /etc/hosts || true
`, agentNetwork, p.agentDataDir(), gatewayHostsMarker))
}

func stepGatewayHosts(ctx context.Context, r *Runner) error {
	out, err := r.BashOutput(ctx, "octeliumctl get gateway -o json")
	if err != nil {
		return errors.Errorf("Could not list the Gateways: %+v: %s", err, out)
	}

	gws := &corev1.GatewayList{}
	if err := pbutils.UnmarshalJSON([]byte(out), gws); err != nil {
		return errors.Errorf("Could not parse the Gateway list: %+v: %s", err, out)
	}

	script, err := gatewayHostsScript(gws.Items)
	if err != nil {
		return err
	}

	return r.Bash(ctx, script)
}

func gatewayHostsScript(gws []*corev1.Gateway) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "sudo sed -i '/%s$/d' /etc/hosts\n", gatewayHostsMarker)

	for _, gw := range gws {
		if gw.Status == nil || gw.Status.Hostname == "" || len(gw.Status.PublicIPs) == 0 {
			return "", errors.Errorf("The Gateway %s has no hostname or public address yet",
				gw.GetMetadata().GetName())
		}

		fmt.Fprintf(&b, "echo %s | sudo tee -a /etc/hosts >/dev/null\n", shellQuote(
			fmt.Sprintf("%s %s %s", gw.Status.PublicIPs[0], gw.Status.Hostname, gatewayHostsMarker)))
	}

	b.WriteString("grep -F '" + gatewayHostsMarker + "' /etc/hosts\n")

	return b.String(), nil
}
