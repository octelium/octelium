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

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

const scriptInstall = `
#!/usr/bin/env bash
set -e

DOMAIN="localhost"
VERSION=$GITHUB_REF_NAME
DEBIAN_FRONTEND=noninteractive
PG_PASSWORD=$(openssl rand -base64 12)
REDIS_PASSWORD=$(openssl rand -base64 12)

export OCTELIUM_DOMAIN="localhost"
export OCTELIUM_PRODUCTION=true
export KUBECONFIG="/etc/rancher/k3s/k3s.yaml"

echo "export OCTELIUM_DOMAIN=\"$OCTELIUM_DOMAIN\"" >> ~/.bashrc
echo "export OCTELIUM_PRODUCTION=\"$OCTELIUM_PRODUCTION\"" >> ~/.bashrc
echo "export KUBECONFIG=\"$KUBECONFIG\"" >> ~/.bashrc

if [ -f ~/.zshrc ]; then
  echo "export OCTELIUM_DOMAIN=\"$OCTELIUM_DOMAIN\"" >> ~/.zshrc
  echo "export OCTELIUM_PRODUCTION=\"$OCTELIUM_PRODUCTION\"" >> ~/.zshrc
  echo "export KUBECONFIG=\"$KUBECONFIG\"" >> ~/.zshrc
fi


sudo sysctl -w kernel.pid_max=4194303
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo sysctl -w net.core.rmem_max=7500000
sudo sysctl -w net.core.wmem_max=7500000
sudo sysctl -w fs.inotify.max_user_watches=1000000
sudo sysctl -w fs.inotify.max_user_instances=1000000

sudo mount --make-rshared /
sudo mkdir -p /usr/local/bin
sudo apt-get update
sudo apt-get install -y iputils-ping postgresql jq curl ssh

if [[ ":$PATH:" != *":/usr/local/bin:"* ]]; then
  export PATH="/usr/local/bin:$PATH"
fi


sudo rm -rf /mnt/octelium/db
sudo mkdir -p /mnt/octelium/db
sudo chmod -R 777 /mnt/octelium/db


curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo cp kubectl /usr/local/bin
sudo chmod 755 /usr/local/bin/kubectl

curl -fsSL https://octelium.com/install.sh | bash


export INSTALL_K3S_SKIP_START=true
export INSTALL_K3S_SKIP_ENABLE=true
export INSTALL_K3S_EXEC="--disable traefik"
curl -sfL https://get.k3s.io | sh -

curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
sudo ./get_helm.sh

sudo k3s server --disable traefik --docker --write-kubeconfig-mode 644 &>/dev/null &

echo "Installing k3s"

sleep 30
sudo chmod 644 /etc/rancher/k3s/k3s.yaml
kubectl wait --for=condition=Ready nodes --all --timeout=600s

kubectl taint nodes --all node-role.kubernetes.io/control-plane- >/dev/null 2>&1 || true

kubectl label nodes --all octelium.com/node=
kubectl label nodes --all octelium.com/node-mode-controlplane=
kubectl label nodes --all octelium.com/node-mode-dataplane=


kubectl wait --for=condition=Ready nodes --all --timeout=600s

DEVICE=$(ip route show default | ip route show default | awk '/default/ {print $5}')
DEFAULT_LINK_ADDR=$(ip addr show "$DEVICE" | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
EXTERNAL_IP=${DEFAULT_LINK_ADDR}

NODE_NAME=$(kubectl get nodes --no-headers -o jsonpath='{.items[0].metadata.name}')

kubectl annotate node ${NODE_NAME} octelium.com/public-ip-test=${EXTERNAL_IP}

cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: octelium-db-pvc
spec:
  resources:
    requests:
      storage: 5Gi
  accessModes:
    - ReadWriteOnce
EOF

kubectl create secret generic octelium-pg --from-literal=postgres-password=${PG_PASSWORD} --from-literal=password=${PG_PASSWORD}
kubectl create secret generic octelium-redis --from-literal=password=${REDIS_PASSWORD}

helm install --namespace kube-system octelium-multus oci://registry-1.docker.io/bitnamicharts/multus-cni --version 2.2.7 \
    --set hostCNIBinDir=/var/lib/rancher/k3s/data/cni/ --set hostCNINetDir=/var/lib/rancher/k3s/agent/etc/cni/net.d \
	--set image.repository=bitnamilegacy/multus-cni --set global.security.allowInsecureImages=true &>/dev/null

helm install octelium-redis oci://registry-1.docker.io/bitnamicharts/redis \
	--set auth.existingSecret=octelium-redis \
	--set auth.existingSecretPasswordKey=password \
	--set architecture=standalone \
	--set master.persistence.enabled=false \
	--set standalone.persistence.enabled=false \
	--set networkPolicy.enabled=false --version 20.8.0 \
	--set image.repository=bitnamilegacy/redis --set global.security.allowInsecureImages=true &>/dev/null

helm install --wait --timeout 30m0s octelium-pg oci://registry-1.docker.io/bitnamicharts/postgresql \
	--set primary.persistence.existingClaim=octelium-db-pvc \
	--set global.postgresql.auth.existingSecret=octelium-pg \
	--set global.postgresql.auth.database=octelium \
	--set global.postgresql.auth.username=octelium \
	--set primary.networkPolicy.enabled=false --version 16.4.14 \
	--set image.repository=bitnamilegacy/postgresql --set global.security.allowInsecureImages=true &>/dev/null

export OCTELIUM_REGION_EXTERNAL_IP=${EXTERNAL_IP}
export OCTELIUM_AUTH_TOKEN_SAVE_PATH="/tmp/octelium-auth-token"
export OCTELIUM_SKIP_MESSAGES="true"
octops init ${DOMAIN} --version ${VERSION} --bootstrap - <<EOF
spec:
  primaryStorage:
    postgresql:
      username: octelium
      password: ${PG_PASSWORD}
      host: octelium-pg-postgresql.default.svc
      database: octelium
      port: 5432
  secondaryStorage:
    redis:
      password: ${REDIS_PASSWORD}
      host: octelium-redis-master.default.svc
      port: 6379
  network:
    quicv0:
      enable: true
EOF

helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update

helm install my-otel open-telemetry/opentelemetry-collector -n octelium -f - <<EOF
mode: deployment
image:
  repository: "otel/opentelemetry-collector-contrib"
podLabels:
  octelium.com/component: "collector"
ports:
  otlp:
    enabled: true
    containerPort: 4317
    servicePort: 8080
    hostPort: 4317
    protocol: TCP
    appProtocol: grpc

fullnameOverride: octelium-collector

config:
  exporters:
    debug:
      verbosity: normal
  processors:
    batch: {}
    memory_limiter:
      check_interval: 2s
      limit_percentage: 80
      spike_limit_percentage: 25
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: ${env:MY_POD_IP}:4317
        http:
          endpoint: ${env:MY_POD_IP}:4318
  service:
    pipelines:
      logs:
        exporters:
          - debug
        processors:
          - memory_limiter
          - batch
        receivers:
          - otlp
      metrics:
        exporters:
          - debug
        processors:
          - memory_limiter
          - batch
        receivers:
          - otlp
      traces:
        exporters:
          - debug
        processors:
          - memory_limiter
          - batch
        receivers:
          - otlp
EOF

kubectl wait --for=condition=available deployment/octelium-ingress-dataplane --namespace octelium --timeout=600s
kubectl wait --for=condition=available deployment/octelium-ingress --namespace octelium --timeout=600s

kubectl wait --for=condition=available deployment/svc-default-octelium-api --namespace octelium --timeout=600s
kubectl wait --for=condition=available deployment/svc-auth-octelium-api --namespace octelium --timeout=600s
kubectl wait --for=condition=available deployment/svc-dns-octelium --namespace octelium --timeout=600s
kubectl wait --for=condition=available deployment/svc-demo-nginx-default --namespace octelium --timeout=600s
kubectl wait --for=condition=available deployment/svc-portal-default --namespace octelium --timeout=600s
kubectl wait --for=condition=available deployment/svc-default-default --namespace octelium --timeout=600s


AUTH_TOKEN=$(cat $OCTELIUM_AUTH_TOKEN_SAVE_PATH)

sleep 3

OCTELIUM_INSECURE_TLS=true octelium login --domain localhost --auth-token $AUTH_TOKEN

OCTELIUM_INSECURE_TLS=true octeliumctl create secret pg --value ${PG_PASSWORD}

source ~/.bashrc
echo -e "\e[1mThe Cluster has been successfully installed. Open a new tab to start using octelium and octeliumctl commands.\e[0m"
`

func (s *server) installCluster(ctx context.Context) error {
	return s.runScript(ctx, scriptInstall)
}

func (s *server) runScript(ctx context.Context, script string) error {

	tmpFile, err := os.CreateTemp("", "octelium-*.sh")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	tmpFile.Close()

	if err := os.WriteFile(tmpName, []byte(script), 0o700); err != nil {
		return err
	}

	cmd := exec.Command("bash", tmpName)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func (s *server) getCmd(ctx context.Context, cmdStr string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "bash", "-c", cmdStr)

	return cmd
}

func (s *server) runCmd(ctx context.Context, cmdStr string) error {
	cmd := s.getCmd(ctx, cmdStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	zap.L().Debug("Running cmd", zap.String("cmd", cmdStr))
	return cmd.Run()
}

func (s *server) startOcteliumConnectRootless(ctx context.Context, args []string) (*exec.Cmd, error) {
	cmdStr := "octelium connect"

	if len(args) > 0 {
		cmdStr = fmt.Sprintf("octelium connect %s", strings.Join(args, " "))
	}

	cmd := s.getCmd(ctx, cmdStr)
	cmd.Env = append(os.Environ(), "OCTELIUM_DEV=true")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	zap.L().Debug("Running cmd", zap.String("cmd", cmdStr))
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	time.Sleep(5 * time.Second)
	zap.L().Debug("Ended waiting for connect")

	return cmd, nil
}

func (s *server) startOcteliumConnect(ctx context.Context, args []string) (*exec.Cmd, error) {
	cmdStr := "sudo -E octelium connect"

	if len(args) > 0 {
		cmdStr = fmt.Sprintf("octelium connect %s", strings.Join(args, " "))
	}
	cmd := s.getCmd(ctx, cmdStr)
	cmd.Env = append(os.Environ(), "OCTELIUM_DEV=true")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	zap.L().Debug("Running cmd", zap.String("cmd", cmdStr))
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	time.Sleep(5 * time.Second)
	zap.L().Debug("Ended waiting for connect")

	return cmd, nil
}

func (s *server) ping(ctx context.Context, arg string) error {
	return s.runCmd(ctx, fmt.Sprintf("sudo ping -c 1 %s", arg))
}

func (s *server) startKubectlLog(ctx context.Context, arg string) error {
	cmd := s.getCmd(ctx, fmt.Sprintf("kubectl logs -f -n octelium %s", arg))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Start()
}
