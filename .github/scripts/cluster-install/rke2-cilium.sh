#!/usr/bin/env bash

DOMAIN="localhost"
VERSION=${GITHUB_REF_NAME}
DEBIAN_FRONTEND=noninteractive
IS_NAT=false
PG_PASSWORD=$(openssl rand -base64 12)
REDIS_PASSWORD=$(openssl rand -base64 12)
IS_UNINSTALL=false
IS_QUIC=false
FORCE_VM_IP=false


mkdir -p /usr/local/bin

if [[ ":$PATH:" != *":/usr/local/bin:"* ]]; then
  export PATH="/usr/local/bin:$PATH"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --quicv0) IS_QUIC=true; shift ;;
    --uninstall) IS_UNINSTALL=true; shift ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done


if [ -z "$DOMAIN" ]; then
  echo "Usage: $0 --domain "example.com"(REQUIRED) --public-ip "1.2.3.4"(OPTIONAL) --version "latest"(OPTIONAL) --nat (OPTIONAL)"
  exit 1
fi

if [ -z "$VERSION" ]; then
  VERSION="latest"
fi



rm -rf /mnt/octelium/db
mkdir -p /mnt/octelium/db
chmod -R 777 /mnt/octelium/db


DEVICE=$(ip route show default | awk '/default/ {print $5}')
DEFAULT_LINK_ADDR=$(ip addr show "$DEVICE" | grep "inet " | awk '{print $2}' | cut -d'/' -f1)


EXTERNAL_IP=$DEFAULT_LINK_ADDR

case "$(uname -m)" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) ARCH="unknown" ;;
esac


curl -fsSL https://octelium.com/install.sh | bash

curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${ARCH}/kubectl"
cp kubectl /usr/local/bin
chmod 755 /usr/local/bin/kubectl



curl -sfL https://get.rke2.io | sh -
mkdir -p /etc/rancher/rke2/
cat > /etc/rancher/rke2/config.yaml <<EOF
cni: none
disable: 
- rke2-ingress-nginx
- rke2-metrics-server
EOF

systemctl start rke2-server.service

export KUBECONFIG="/etc/rancher/rke2/rke2.yaml"

curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/latest/download/cilium-linux-${ARCH}.tar.gz
tar xzf cilium-linux-${ARCH}.tar.gz
sudo mv cilium /usr/local/bin/

cilium install \
  --set k8sServiceHost=${EXTERNAL_IP} \
  --set k8sServicePort=6443 \
  --set kubeProxyReplacement=true \
  --set cni.exclusive=false


cilium status --wait

mkdir -p /opt/cni/bin
wget https://github.com/containernetworking/plugins/releases/download/v1.9.0/cni-plugins-linux-${ARCH}-v1.9.0.tgz
tar -C /opt/cni/bin -xzf cni-plugins-linux-${ARCH}-v1.9.0.tgz

curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh


kubectl taint nodes --all node-role.kubernetes.io/control-plane- >/dev/null 2>&1 || true

kubectl label nodes --all octelium.com/node=
kubectl label nodes --all octelium.com/node-mode-controlplane=
kubectl label nodes --all octelium.com/node-mode-dataplane=


kubectl wait --for=condition=Ready nodes --all --timeout=600s


NODE_NAME=$(kubectl get nodes --no-headers -o jsonpath='{.items[0].metadata.name}')


kubectl annotate node ${NODE_NAME} octelium.com/public-ip-test=${DEFAULT_LINK_ADDR}


cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolume
metadata:
  name: octelium-db-pv
spec:
  storageClassName: manual
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  hostPath:
    path: /mnt/octelium/db
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: octelium-db-pvc
spec:
  storageClassName: manual
  resources:
    requests:
      storage: 5Gi
  accessModes:
    - ReadWriteOnce
EOF

kubectl create secret generic octelium-pg --from-literal=postgres-password=${PG_PASSWORD} --from-literal=password=${PG_PASSWORD}
kubectl create secret generic octelium-redis --from-literal=password=${REDIS_PASSWORD}



echo -e "\e[1mInstalling PostgreSQL, Redis and Multus. This can take a while to finish...\e[0m"

helm install --namespace kube-system octelium-multus oci://registry-1.docker.io/bitnamicharts/multus-cni --version 2.2.7 \
    --set hostCNIBinDir=/opt/cni/bin/ --set hostCNINetDir=/etc/cni/net.d \
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

echo -e "\e[1mInstalling the Octelium Cluster\e[0m"
OCTELIUM_REGION_EXTERNAL_IP=${EXTERNAL_IP} octops init ${DOMAIN} --version ${VERSION} --bootstrap - <<EOF
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
$(if [ "$IS_QUIC" = true ]; then
  cat <<EOT
  network:
    quicv0:
      enable: true
EOT
fi)
EOF


for i in {1..10}; do
  kubectl get pods -A
  sleep 1
done

kubectl get svc -A
kubectl get ds -A
kubectl get deployment -A

kubectl port-forward svc/octelium-ingress-dataplane 443:443 -n octelium &
sleep 3