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
	"slices"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	k3sPIDPath = "/tmp/octelium-e2e-k3s.pid"
	k3sLogPath = "/tmp/octelium-e2e-k3s.log"
)

const (
	k3sFlannelBinDir = "/var/lib/rancher/k3s/data/cni/"
	k3sFlannelNetDir = "/var/lib/rancher/k3s/agent/etc/cni/net.d"

	stdCNIBinDir = "/opt/cni/bin"
	stdCNINetDir = "/etc/cni/net.d"
)

const (
	ciliumChartVersion = "1.20.0"
	calicoChartVersion = "v3.32.1"
	cniPluginsVersion  = "v1.9.1"
)

const k3sClusterCIDRDefault = "10.42.0.0/16"

func k3sCNIPaths(cni CNI) CNIPaths {
	if cni == "" || cni == CNIFlannel {
		return CNIPaths{
			BinDir: k3sFlannelBinDir,
			NetDir: k3sFlannelNetDir,
		}
	}

	return CNIPaths{
		BinDir: stdCNIBinDir,
		NetDir: stdCNINetDir,
	}
}

type K3s struct {
	Kubeconfig  string
	CNI         CNI
	ClusterCIDR string
	ServerArgs  []string
	InstallExec []string
	Packages    []string
	Paths       CNIPaths
	DBHostPath  string

	Agents       int
	AgentDataDir string
	AgentArgs    []string
	Tuned        bool
}

func (p *K3s) withAgents(n int) {
	p.Agents = n
	p.addPackages("wireguard-tools")
}

func (p *K3s) tune() {
	p.Tuned = true

	args := []string{"--kube-proxy-arg=conntrack-max-per-core=0"}
	p.ServerArgs = append(p.ServerArgs, args...)
	p.InstallExec = append(p.InstallExec, args...)

	p.addPackages("wireguard-tools")
}

func (p *K3s) addPackages(pkgs ...string) {
	for _, pkg := range pkgs {
		if !slices.Contains(p.Packages, pkg) {
			p.Packages = append(p.Packages, pkg)
		}
	}
}

func (p *K3s) hasAgents() bool {
	return p.Agents > 0
}

func (p *K3s) Name() string { return "k3s" }

func (p *K3s) KubeconfigPath() string {
	if p.Kubeconfig != "" {
		return p.Kubeconfig
	}
	return "/etc/rancher/k3s/k3s.yaml"
}

func (p *K3s) CNIPaths() CNIPaths { return p.Paths }

func (p *K3s) Provision(ctx context.Context, r *Runner) error {
	return runSteps(ctx, r, "provision", p.provisionSteps())
}

func (p *K3s) provisionSteps() []Step {
	noAgents := func(*Runner) bool { return !p.hasAgents() }

	return []Step{
		{Name: "host/sysctls", Run: p.stepSysctls},
		{Name: "host/packages", Run: p.stepPackages},
		{
			Name: "host/tuning",
			Skip: func(*Runner) bool { return !p.Tuned },
			Run:  p.stepTuning,
		},
		{Name: "host/storage-dir", Run: p.stepStorageDir},
		{Name: "host/kubectl", Run: p.stepKubectl},
		{Name: "host/helm", Run: p.stepHelm},
		{Name: "k3s/install", Run: p.stepInstallK3s},
		{Name: "k3s/start", Run: p.stepStartK3s},
		{Name: "k3s/server-ready", Skip: noAgents, Run: p.stepWaitServerReady},
		{Name: "agents/network", Skip: noAgents, Run: p.stepAgentNetwork},
		{Name: "agents/mirrors", Skip: noAgents, Run: p.stepAgentMirrors},
		{Name: "agents/start", Skip: noAgents, Run: p.stepStartAgents},
		{Name: "k3s/nodes-registered", Run: p.stepWaitNodesRegistered},
		{
			Name: "cni/install",
			Skip: p.skipCNIInstall,
			Run:  p.stepInstallCNI,
		},
		{
			Name: "cni/plugins",
			Skip: p.skipCNIInstall,
			Run:  p.stepInstallCNIPlugins,
		},
		{Name: "k3s/nodes-ready", Run: p.stepWaitNodesReady},
		{Name: "k3s/node-labels", Run: p.stepLabelNodes},
		{Name: "k3s/node-public-ip", Run: p.stepAnnotatePublicIP},
	}
}

func (p *K3s) Teardown(ctx context.Context, r *Runner) error {
	if p.hasAgents() {
		if err := p.teardownAgents(ctx, r); err != nil {
			zap.L().Warn("Could not fully remove the agent nodes", zap.Error(err))
		}
	}

	return r.Bash(ctx, fmt.Sprintf(`
if [ -x /usr/local/bin/k3s-killall.sh ]; then
  sudo /usr/local/bin/k3s-killall.sh || true
fi
if [ -x /usr/local/bin/k3s-uninstall.sh ]; then
  sudo /usr/local/bin/k3s-uninstall.sh || true
fi
if [ -f %[1]s ]; then
  sudo kill "$(cat %[1]s)" 2>/dev/null || true
  sudo rm -f %[1]s
fi
`, k3sPIDPath))
}

func (p *K3s) ExternalIP(ctx context.Context, r *Runner) (string, error) {
	out, err := r.BashOutput(ctx,
		`ip addr show $(ip route show default | awk '/default/ {print $5}' | head -n1) `+
			`| grep "inet " | awk '{print $2}' | cut -d'/' -f1 | head -n1`)
	if err != nil {
		return "", errors.Errorf("Could not determine the host external IP: %+v: %s", err, out)
	}

	out = strings.TrimSpace(out)
	if !govalidator.IsIP(out) {
		return "", errors.Errorf("Could not determine a valid host external IP, got %q", out)
	}

	return out, nil
}

func (p *K3s) stepSysctls(ctx context.Context, r *Runner) error {
	return r.Bash(ctx, `
sudo sysctl -w kernel.pid_max=4194303
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
sudo sysctl -w fs.inotify.max_user_watches=1000000
sudo sysctl -w fs.inotify.max_user_instances=1000000

sudo mount --make-rshared /
sudo mkdir -p /usr/local/bin
`)
}

func (p *K3s) stepTuning(ctx context.Context, r *Runner) error {
	return r.Bash(ctx, hostTuningScript)
}

const hostTuningScript = `
sudo modprobe nf_conntrack || true

sudo sysctl -w fs.file-max=4194304
sudo sysctl -w fs.nr_open=4194304
sudo sysctl -w vm.max_map_count=1048576
sudo sysctl -w kernel.threads-max=4194303

sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.core.netdev_max_backlog=65536
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.ipv4.ip_local_port_range="10240 65535"
sudo sysctl -w net.ipv4.ip_local_reserved_ports="22022,30000-32767"
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
sudo sysctl -w net.ipv4.tcp_fin_timeout=15
sudo sysctl -w net.ipv4.tcp_max_tw_buckets=2000000
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.neigh.default.gc_thresh1=4096
sudo sysctl -w net.ipv4.neigh.default.gc_thresh2=8192
sudo sysctl -w net.ipv4.neigh.default.gc_thresh3=16384
sudo sysctl -w net.ipv6.neigh.default.gc_thresh1=4096
sudo sysctl -w net.ipv6.neigh.default.gc_thresh2=8192
sudo sysctl -w net.ipv6.neigh.default.gc_thresh3=16384
sudo sysctl -w net.netfilter.nf_conntrack_max=1048576 || true
echo 262144 | sudo tee /sys/module/nf_conntrack/parameters/hashsize >/dev/null || true

for unit in docker containerd; do
  sudo mkdir -p "/etc/systemd/system/${unit}.service.d"
  printf '[Service]\nLimitNOFILE=1048576\nLimitNPROC=infinity\nTasksMax=infinity\n' \
    | sudo tee "/etc/systemd/system/${unit}.service.d/octelium-e2e.conf" >/dev/null
done

sudo mkdir -p /etc/docker
CURRENT='{}'
if sudo test -s /etc/docker/daemon.json; then
  CURRENT=$(sudo cat /etc/docker/daemon.json)
fi
echo "$CURRENT" | jq '. + {"default-ulimits": {"nofile": {"Name": "nofile", "Hard": 1048576, "Soft": 1048576}}}' \
  | sudo tee /etc/docker/daemon.json.octelium-e2e >/dev/null
sudo mv /etc/docker/daemon.json.octelium-e2e /etc/docker/daemon.json

sudo systemctl daemon-reload
sudo systemctl restart containerd || true
sudo systemctl restart docker
timeout 120 bash -c 'until sudo docker info >/dev/null 2>&1; do sleep 1; done'

echo "host limits: file-max=$(cat /proc/sys/fs/file-max) nr_open=$(cat /proc/sys/fs/nr_open)"
sudo docker info --format 'docker default ulimits: {{json .DefaultUlimits}}' 2>/dev/null || true
`

func (p *K3s) stepPackages(ctx context.Context, r *Runner) error {
	pkgs := p.Packages
	if len(pkgs) == 0 {
		return nil
	}

	return r.Bash(ctx, fmt.Sprintf(`
sudo apt-get update
sudo apt-get install -y %s
`, strings.Join(pkgs, " ")))
}

func (p *K3s) stepStorageDir(ctx context.Context, r *Runner) error {
	if p.DBHostPath == "" {
		return nil
	}

	return r.Bash(ctx, fmt.Sprintf(`
sudo rm -rf %[1]s
sudo mkdir -p %[1]s
sudo chmod -R 777 %[1]s
`, p.DBHostPath))
}

func (p *K3s) stepKubectl(ctx context.Context, r *Runner) error {
	return r.Bash(ctx, `
if command -v kubectl >/dev/null 2>&1; then
  echo "kubectl already installed: $(command -v kubectl)"
  exit 0
fi

case "$(uname -m)" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

TMP=$(mktemp -d)
curl -fsSL -o "${TMP}/kubectl" \
  "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/${ARCH}/kubectl"
sudo install -m 0755 "${TMP}/kubectl" /usr/local/bin/kubectl
rm -rf "${TMP}"
`)
}

func (p *K3s) stepHelm(ctx context.Context, r *Runner) error {
	return r.Bash(ctx, `
if command -v helm >/dev/null 2>&1; then
  echo "helm already installed: $(command -v helm)"
  exit 0
fi

TMP=$(mktemp -d)
curl -fsSL -o "${TMP}/get_helm.sh" https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 "${TMP}/get_helm.sh"
sudo "${TMP}/get_helm.sh"
rm -rf "${TMP}"
`)
}

func (p *K3s) stepInstallK3s(ctx context.Context, r *Runner) error {
	return r.Bash(ctx, fmt.Sprintf(`
export INSTALL_K3S_SKIP_START=true
export INSTALL_K3S_SKIP_ENABLE=true
export INSTALL_K3S_EXEC=%q
curl -sfL https://get.k3s.io | sh -
`, strings.Join(p.InstallExec, " ")))
}

func (p *K3s) stepStartK3s(ctx context.Context, r *Runner) error {
	if err := r.Bash(ctx, fmt.Sprintf(`
if [ -f %[1]s ] && sudo kill -0 "$(cat %[1]s)" 2>/dev/null; then
  echo "k3s server is already running with pid $(cat %[1]s)"
  exit 0
fi

sudo rm -f %[1]s %[2]s
sudo sh -c 'nohup k3s server %[3]s --write-kubeconfig-mode 644 >%[2]s 2>&1 & echo $! > %[1]s'
`, k3sPIDPath, k3sLogPath, strings.Join(p.ServerArgs, " "))); err != nil {
		return err
	}

	kubeconfig := p.KubeconfigPath()

	err := pollUntil(ctx, "the k3s apiserver", 5*minute, 2*second, func(ctx context.Context) error {
		if err := p.checkRunning(ctx, r); err != nil {
			return fatal(err)
		}

		out, err := r.BashOutput(ctx, fmt.Sprintf(`
sudo test -f %[1]s || { echo "the kubeconfig is not written yet"; exit 1; }
sudo chmod 644 %[1]s
kubectl version --request-timeout=5s >/dev/null
`, kubeconfig))
		if err != nil {
			return errors.Errorf("%+v: %s", err, out)
		}
		return nil
	})
	if err != nil {
		return errors.Errorf("%+v\nk3s log:\n%s", err, p.logTail(ctx, r))
	}

	return nil
}

func (p *K3s) checkRunning(ctx context.Context, r *Runner) error {
	out, err := r.BashOutput(ctx, fmt.Sprintf(`
test -f %[1]s || { echo "no pidfile at %[1]s"; exit 1; }
sudo kill -0 "$(cat %[1]s)" 2>/dev/null || { echo "pid $(cat %[1]s) is gone"; exit 1; }
`, k3sPIDPath))
	if err != nil {
		return errors.Errorf("The k3s server is not running: %s", out)
	}
	return nil
}

func (p *K3s) logTail(ctx context.Context, r *Runner) string {
	out, err := r.BashOutput(ctx, fmt.Sprintf(`sudo tail -n 50 %s`, k3sLogPath))
	if err != nil {
		return fmt.Sprintf("<could not read %s: %+v>", k3sLogPath, err)
	}
	return out
}

func (p *K3s) stepWaitNodesRegistered(ctx context.Context, r *Runner) error {
	want := r.Scenario.Topology.Nodes
	if want < 1 {
		want = 1
	}

	err := pollUntil(ctx, fmt.Sprintf("%d node(s) to register", want),
		5*minute, 2*second, func(ctx context.Context) error {
			out, err := r.BashOutput(ctx, `kubectl get nodes --no-headers -o name | wc -l`)
			if err != nil {
				return errors.Errorf("%+v: %s", err, out)
			}

			got, err := strconv.Atoi(strings.TrimSpace(out))
			if err != nil {
				return errors.Errorf("Could not count the registered nodes: %s", out)
			}
			if got < want {
				return errors.Errorf("Only %d of %d nodes have registered", got, want)
			}
			return nil
		})
	if err != nil {
		return errors.Errorf("%+v\nk3s log:\n%s\n%s", err, p.logTail(ctx, r),
			p.agentDiagnostics(ctx, r))
	}

	return nil
}

func (p *K3s) stepWaitNodesReady(ctx context.Context, r *Runner) error {
	k8sC, err := r.K8sC()
	if err != nil {
		return err
	}

	err = pollUntil(ctx, "every node to become Ready", 10*minute, 5*second,
		func(ctx context.Context) error {
			nodes, err := k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{})
			if err != nil {
				return err
			}
			if len(nodes.Items) == 0 {
				return errors.Errorf("No node has registered")
			}

			var notReady []string
			for i := range nodes.Items {
				if reason := nodeNotReady(&nodes.Items[i]); reason != "" {
					notReady = append(notReady, reason)
				}
			}

			if len(notReady) > 0 {
				return errors.Errorf("%s", strings.Join(notReady, "; "))
			}
			return nil
		})
	if err != nil {
		return errors.Errorf("%+v\n%s", err, p.notReadyDiagnostics(ctx, r))
	}

	return r.Bash(ctx,
		`kubectl taint nodes --all node-role.kubernetes.io/control-plane- >/dev/null 2>&1 || true`)
}

func nodeNotReady(node *k8scorev1.Node) string {
	for _, c := range node.Status.Conditions {
		if c.Type != k8scorev1.NodeReady {
			continue
		}
		if c.Status == k8scorev1.ConditionTrue {
			return ""
		}
		return fmt.Sprintf("the node %s is %s: %s %s",
			node.Name, c.Status, c.Reason, c.Message)
	}

	return fmt.Sprintf("the node %s has no Ready condition yet", node.Name)
}

func (p *K3s) notReadyDiagnostics(ctx context.Context, r *Runner) string {
	if p.CNI == "" || p.CNI == CNIFlannel {
		return fmt.Sprintf("k3s log:\n%s\n%s", p.logTail(ctx, r), p.agentDiagnostics(ctx, r))
	}

	out, err := r.BashOutput(ctx, fmt.Sprintf(`
echo "--- CNI config in %[1]s ---"
sudo ls -la %[1]s 2>&1 | head -n 20
echo "--- CNI binaries in %[2]s ---"
sudo ls -la %[2]s 2>&1 | head -n 30
echo "--- pods ---"
kubectl get pods -A -o wide 2>&1 | head -n 40
`, p.Paths.NetDir, p.Paths.BinDir))
	if err != nil {
		out = fmt.Sprintf("<could not collect the CNI diagnostics: %+v>", err)
	}

	return fmt.Sprintf("The CNI %s did not make the node Ready.\n%s\nk3s log:\n%s",
		p.CNI, out, p.logTail(ctx, r))
}

const (
	nodeSelectorServer = "node-role.kubernetes.io/control-plane=true"
	nodeSelectorAgents = "!node-role.kubernetes.io/control-plane"
)

func labelNodesScript(selector string, labels []string) string {
	var b strings.Builder
	for _, label := range labels {
		fmt.Fprintf(&b, "kubectl label nodes %s --overwrite %s=\n", selector, label)
	}
	return b.String()
}

func (p *K3s) stepLabelNodes(ctx context.Context, r *Runner) error {
	topology := r.Scenario.Topology

	var b strings.Builder
	if p.hasAgents() {
		b.WriteString(labelNodesScript(fmt.Sprintf("-l '%s'", nodeSelectorServer), topology.Labels))
		b.WriteString(labelNodesScript(fmt.Sprintf("-l '%s'", nodeSelectorAgents), topology.AgentLabels))
	} else {
		b.WriteString(labelNodesScript("--all", topology.Labels))
	}

	if b.Len() == 0 {
		return nil
	}

	b.WriteString("kubectl wait --for=condition=Ready nodes --all --timeout=600s\n")

	return r.Bash(ctx, b.String())
}

func (p *K3s) stepAnnotatePublicIP(ctx context.Context, r *Runner) error {
	externalIP, err := p.ExternalIP(ctx, r)
	if err != nil {
		return err
	}

	zap.L().Debug("Annotating nodes with the test public IP", zap.String("addr", externalIP))

	if !p.hasAgents() {
		return r.Bash(ctx, fmt.Sprintf(
			`kubectl annotate nodes --all --overwrite octelium.com/public-ip-test=%s`, externalIP))
	}

	k8sC, err := r.K8sC()
	if err != nil {
		return err
	}

	nodes, err := k8sC.CoreV1().Nodes().List(ctx, k8smetav1.ListOptions{})
	if err != nil {
		return err
	}

	var b strings.Builder
	for i := range nodes.Items {
		addr := nodePublicIP(&nodes.Items[i], externalIP)
		if addr == "" {
			return errors.Errorf("The node %s has no InternalIP to publish its Gateway on",
				nodes.Items[i].Name)
		}

		fmt.Fprintf(&b, "kubectl annotate node %s --overwrite octelium.com/public-ip-test=%s\n",
			shellQuote(nodes.Items[i].Name), addr)
	}

	return r.Bash(ctx, b.String())
}

func isServerNode(node *k8scorev1.Node) bool {
	return node.Labels["node-role.kubernetes.io/control-plane"] == "true"
}

func nodePublicIP(node *k8scorev1.Node, serverIP string) string {
	if isServerNode(node) {
		return serverIP
	}

	for _, addr := range node.Status.Addresses {
		if addr.Type == k8scorev1.NodeInternalIP && govalidator.IsIPv4(addr.Address) {
			return addr.Address
		}
	}

	return ""
}

func (p *K3s) skipCNIInstall(r *Runner) bool {
	return p.CNI == "" || p.CNI == CNIFlannel
}

func (p *K3s) stepInstallCNIPlugins(ctx context.Context, r *Runner) error {
	return r.Bash(ctx, fmt.Sprintf(`
if [ -x %[1]s/bridge ] && [ -x %[1]s/host-local ]; then
  echo "the reference CNI plugins are already installed in %[1]s"
  exit 0
fi

case "$(uname -m)" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

TMP=$(mktemp -d)
curl -fsSL -o "${TMP}/cni-plugins.tgz" \
  "https://github.com/containernetworking/plugins/releases/download/%[2]s/cni-plugins-linux-${ARCH}-%[2]s.tgz"
sudo mkdir -p %[1]s
sudo tar -C %[1]s -xzf "${TMP}/cni-plugins.tgz"
rm -rf "${TMP}"

test -x %[1]s/bridge || { echo "the bridge plugin is still missing from %[1]s" >&2; exit 1; }
test -x %[1]s/host-local || { echo "the host-local plugin is still missing from %[1]s" >&2; exit 1; }
ls -la %[1]s
`, p.Paths.BinDir, cniPluginsVersion))
}

func (p *K3s) stepInstallCNI(ctx context.Context, r *Runner) error {
	switch p.CNI {
	case CNICilium:
		return p.installCilium(ctx, r)
	case CNICalico:
		return p.installCalico(ctx, r)
	default:
		return errors.Errorf("The k3s provisioner cannot install the CNI %q", p.CNI)
	}
}

func (p *K3s) installCilium(ctx context.Context, r *Runner) error {
	apiAddr, err := p.ExternalIP(ctx, r)
	if err != nil {
		return err
	}

	if err := r.Bash(ctx, fmt.Sprintf(`
helm repo add cilium https://helm.cilium.io/
helm repo update cilium
helm upgrade --install cilium cilium/cilium \
  --version %s \
  --namespace kube-system \
  --set operator.replicas=1 \
  --set ipam.mode=kubernetes \
  --set k8sServiceHost=%s \
  --set k8sServicePort=6443 \
  --set cni.binPath=%s \
  --set cni.confPath=%s \
  --set cni.exclusive=false \
  --set cni.chainingMode=portmap \
  --timeout 10m
`, ciliumChartVersion, apiAddr, p.Paths.BinDir, p.Paths.NetDir)); err != nil {
		return err
	}

	return p.waitCNIRollout(ctx, r, "kube-system", "daemonset/cilium")
}

func (p *K3s) installCalico(ctx context.Context, r *Runner) error {
	if err := r.Bash(ctx, fmt.Sprintf(`
helm repo add projectcalico https://docs.tigera.io/calico/charts
helm repo update projectcalico
helm template calico-crds projectcalico/crd.projectcalico.org.v1 --version %[1]s \
  | kubectl apply --server-side --force-conflicts -f -
kubectl create namespace tigera-operator --dry-run=client -o yaml | kubectl apply -f -
helm upgrade --install calico projectcalico/tigera-operator \
  --version %[1]s \
  --namespace tigera-operator \
  --set installation.cni.type=Calico \
  --set installation.cni.binDir=%[2]s \
  --set installation.cni.confDir=%[3]s \
  --set installation.calicoNetwork.bgp=Disabled \
  --set installation.calicoNetwork.hostPorts=Enabled \
  --set installation.calicoNetwork.ipPools[0].cidr=%[4]s \
  --set installation.calicoNetwork.ipPools[0].encapsulation=VXLAN \
  --set goldmane.enabled=false \
  --set whisker.enabled=false \
  --timeout 10m
`, calicoChartVersion, p.Paths.BinDir, p.Paths.NetDir, p.clusterCIDR())); err != nil {
		return err
	}

	if err := p.waitCNIRollout(ctx, r, "tigera-operator",
		"deployment/tigera-operator"); err != nil {
		return err
	}

	if err := p.waitCalicoInstallation(ctx, r); err != nil {
		return err
	}

	return p.waitCNIRollout(ctx, r, "calico-system", "daemonset/calico-node")
}

func (p *K3s) clusterCIDR() string {
	if p.ClusterCIDR != "" {
		return p.ClusterCIDR
	}
	return k3sClusterCIDRDefault
}

func (p *K3s) waitCalicoInstallation(ctx context.Context, r *Runner) error {
	return pollUntil(ctx, "the tigera-operator to reconcile the Installation",
		5*minute, 5*second, func(ctx context.Context) error {
			if _, err := r.BashOutput(ctx,
				`kubectl get namespace calico-system -o name`); err == nil {
				return nil
			}

			if msg := calicoDegraded(ctx, r); msg != "" {
				return errors.Errorf(
					"The operator has not created calico-system yet. %s", msg)
			}

			return errors.Errorf("The operator has not created calico-system yet")
		})
}

func calicoDegraded(ctx context.Context, r *Runner) string {
	out, err := r.BashOutput(ctx, `kubectl get tigerastatus -o jsonpath=`+
		`'{range .items[*]}{.metadata.name}{"="}`+
		`{.status.conditions[?(@.type=="Degraded")].status}{":"}`+
		`{.status.conditions[?(@.type=="Degraded")].message}{"\n"}{end}'`)
	if err != nil {
		return ""
	}

	var ret []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		name, rest, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		status, msg, _ := strings.Cut(rest, ":")
		if status == "True" {
			ret = append(ret, fmt.Sprintf("%s: %s", name, strings.TrimSpace(msg)))
		}
	}

	return strings.Join(ret, "; ")
}

func (p *K3s) waitCNIRollout(ctx context.Context, r *Runner, ns, target string) error {
	err := pollUntil(ctx, fmt.Sprintf("%s in %s to roll out", target, ns),
		10*minute, 5*second, func(ctx context.Context) error {
			out, err := r.BashOutput(ctx, fmt.Sprintf(
				"kubectl rollout status %s --namespace %s --timeout=30s",
				shellQuote(target), shellQuote(ns)))
			if err != nil {
				return errors.Errorf("%+v: %s", err, out)
			}
			return nil
		})
	if err != nil {
		return errors.Errorf("%+v\n%s", err, p.cniDiagnostics(ctx, r, ns))
	}

	return nil
}

func (p *K3s) cniDiagnostics(ctx context.Context, r *Runner, ns string) string {
	out, err := r.BashOutput(ctx, fmt.Sprintf(`
kubectl get pods --namespace %[1]s -o wide 2>&1 | head -n 30
kubectl get events --namespace %[1]s --sort-by=.lastTimestamp 2>&1 | tail -n 20
`, shellQuote(ns)))
	if err != nil {
		return fmt.Sprintf("<could not collect the %s diagnostics: %+v>", ns, err)
	}
	return out
}
