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
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	k3sPIDPath = "/tmp/octelium-e2e-k3s.pid"
	k3sLogPath = "/tmp/octelium-e2e-k3s.log"
)

type K3s struct {
	Kubeconfig  string
	ServerArgs  []string
	InstallExec []string
	Packages    []string
	Paths       CNIPaths
	DBHostPath  string
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
	return runSteps(ctx, r, "provision", []Step{
		{Name: "host/sysctls", Run: p.stepSysctls},
		{Name: "host/packages", Run: p.stepPackages},
		{Name: "host/storage-dir", Run: p.stepStorageDir},
		{Name: "host/kubectl", Run: p.stepKubectl},
		{Name: "host/helm", Run: p.stepHelm},
		{Name: "k3s/install", Run: p.stepInstallK3s},
		{Name: "k3s/start", Run: p.stepStartK3s},
		{Name: "k3s/nodes-ready", Run: p.stepWaitNodes},
		{Name: "k3s/node-labels", Run: p.stepLabelNodes},
		{Name: "k3s/node-public-ip", Run: p.stepAnnotatePublicIP},
	})
}

func (p *K3s) Teardown(ctx context.Context, r *Runner) error {
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

func (p *K3s) stepWaitNodes(ctx context.Context, r *Runner) error {
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
		return errors.Errorf("%+v\nk3s log:\n%s", err, p.logTail(ctx, r))
	}

	return r.Bash(ctx, `
kubectl wait --for=condition=Ready nodes --all --timeout=600s
kubectl taint nodes --all node-role.kubernetes.io/control-plane- >/dev/null 2>&1 || true
`)
}

func (p *K3s) stepLabelNodes(ctx context.Context, r *Runner) error {
	labels := r.Scenario.Topology.Labels
	if len(labels) == 0 {
		return nil
	}

	var b strings.Builder
	for _, label := range labels {
		fmt.Fprintf(&b, "kubectl label nodes --all --overwrite %s=\n", label)
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

	return r.Bash(ctx, fmt.Sprintf(
		`kubectl annotate nodes --all --overwrite octelium.com/public-ip-test=%s`, externalIP))
}
