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
	"time"

	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func (r *Runner) installSteps() []Step {
	return []Step{
		{Name: "octelium/init", Run: r.stepOctopsInit},
		{
			Name: "telemetry/collector",
			Skip: func(r *Runner) bool { return !r.Scenario.Install.OTelCollector },
			Run:  r.stepCollector,
		},
		{Name: "octelium/readiness", Run: r.stepWaitDeployments},
		{Name: "octelium/host-ingress", Run: r.stepHostIngress},
		{Name: "octelium/login", Run: r.stepLogin},
		{Name: "octelium/storage-secret", Run: r.stepStorageSecretResource},
		{
			Name: "octelium/cluster-cert",
			Skip: func(r *Runner) bool { return !r.Scenario.Install.ClusterCert },
			Run:  r.stepClusterCert,
		},
	}
}

func (r *Runner) stepOctopsInit(ctx context.Context, _ *Runner) error {
	s := r.Scenario
	o := s.Install

	authTokenPath := filepath.Join(os.TempDir(), "octelium-e2e-auth-token")
	r.State.AuthTokenPath = authTokenPath

	r.SetEnv("OCTELIUM_REGION_EXTERNAL_IP", r.State.ExternalIP)
	r.SetEnv("OCTELIUM_AUTH_TOKEN_SAVE_PATH", authTokenPath)
	r.SetEnv("OCTELIUM_SKIP_MESSAGES", "true")

	if o.EnableSPIFFECSI {
		r.SetEnv("OCTELIUM_ENABLE_SPIFFE_CSI", "true")
		if o.SPIFFECSIDriver != "" {
			r.SetEnv("OCTELIUM_SPIFFE_CSI_DRIVER", o.SPIFFECSIDriver)
		}
		if o.SPIFFETrustDomain != "" {
			r.SetEnv("OCTELIUM_SPIFFE_TRUST_DOMAIN", o.SPIFFETrustDomain)
		}
	}

	if o.IngressFrontProxy {
		r.SetEnv("OCTELIUM_INGRESS_FRONT_PROXY", "true")
	}

	for k, v := range o.Env {
		r.SetEnv(k, v)
	}

	if paths := s.Provisioner.CNIPaths(); paths.OcteliumCNIConfDir != "" {
		r.SetEnv("OCTELIUM_CNI_CONF_DIR", paths.OcteliumCNIConfDir)
	}

	versionArg := ""
	if o.Version != "" {
		versionArg = fmt.Sprintf("--version %s", o.Version)
	}

	script := fmt.Sprintf("octops version && octops init %s %s --bootstrap -",
		s.Domain, versionArg)

	return r.BashInput(ctx, script, r.bootstrapYAML())
}

func (r *Runner) bootstrapYAML() string {
	s := r.Scenario
	pg := s.Storage.Postgres
	redis := s.Storage.Redis

	var b strings.Builder
	b.WriteString("spec:\n")
	fmt.Fprintf(&b, "  primaryStorage:\n    postgresql:\n")
	fmt.Fprintf(&b, "      username: %s\n", pg.Username)
	fmt.Fprintf(&b, "      password: %q\n", r.State.PostgresPassword)
	fmt.Fprintf(&b, "      host: %s\n", pg.Host)
	fmt.Fprintf(&b, "      database: %s\n", pg.Database)
	fmt.Fprintf(&b, "      port: %d\n", pg.Port)

	fmt.Fprintf(&b, "  secondaryStorage:\n    redis:\n")
	fmt.Fprintf(&b, "      password: %q\n", r.State.RedisPassword)
	fmt.Fprintf(&b, "      host: %s\n", redis.Host)
	fmt.Fprintf(&b, "      port: %d\n", redis.Port)

	if s.Install.EnableQUICv0 || s.Install.NetworkMode != "" {
		b.WriteString("  network:\n")
		if s.Install.NetworkMode != "" {
			fmt.Fprintf(&b, "    mode: %s\n", s.Install.NetworkMode)
		}
		if s.Install.EnableQUICv0 {
			b.WriteString("    quicv0:\n      enable: true\n")
		}
	}

	return b.String()
}

func (r *Runner) stepCollector(ctx context.Context, _ *Runner) error {
	if err := r.Bash(ctx, `
helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
helm repo update open-telemetry
`); err != nil {
		return err
	}

	return r.helmInstall(ctx, vutils.K8sNS, "my-otel",
		"open-telemetry/opentelemetry-collector", nil, collectorValues)
}

func (r *Runner) stepWaitDeployments(ctx context.Context, _ *Runner) error {
	k8sC, err := r.K8sC()
	if err != nil {
		return err
	}

	timeout := r.Scenario.Install.WaitTimeout
	if timeout == 0 {
		timeout = 10 * minute
	}

	for _, name := range r.Scenario.Install.WaitDeployments {
		zap.L().Debug("Waiting for deployment readiness", zap.String("deployment", name))

		err := pollUntil(ctx, fmt.Sprintf("the deployment %s", name), timeout, 2*second,
			func(ctx context.Context) error {
				return deploymentReadiness(ctx, k8sC, vutils.K8sNS, name)
			})
		if err != nil {
			return err
		}
	}

	return nil
}

func deploymentReadiness(ctx context.Context,
	k8sC kubernetes.Interface, ns, name string) error {
	dep, err := k8sC.AppsV1().Deployments(ns).Get(ctx, name, k8smetav1.GetOptions{})
	if err != nil {
		return err
	}

	rs, err := k8sutils.GetNewReplicaSet(dep, k8sC.AppsV1())
	if err != nil {
		return err
	}
	if rs == nil {
		return errors.Errorf("The Deployment has no current ReplicaSet yet")
	}

	want := *dep.Spec.Replicas - k8sutils.MaxUnavailable(*dep)
	if rs.Status.ReadyReplicas >= want {
		return nil
	}

	return errors.Errorf("%d of %d replicas are ready. %s",
		rs.Status.ReadyReplicas, want, describePods(ctx, k8sC, dep))
}

func describePods(ctx context.Context,
	k8sC kubernetes.Interface, dep *appsv1.Deployment) string {
	sel, err := k8smetav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil {
		return fmt.Sprintf("<could not read the Deployment selector: %+v>", err)
	}

	pods, err := k8sC.CoreV1().Pods(dep.Namespace).List(ctx,
		k8smetav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return fmt.Sprintf("<could not list the pods: %+v>", err)
	}

	if len(pods.Items) == 0 {
		return "No pod has been created for this Deployment yet"
	}

	var b strings.Builder
	for i := range pods.Items {
		pod := &pods.Items[i]

		fmt.Fprintf(&b, "Pod %s is %s", pod.Name, pod.Status.Phase)

		for _, c := range pod.Status.Conditions {
			if c.Status != k8scorev1.ConditionTrue && c.Reason != "" {
				fmt.Fprintf(&b, " [%s: %s]", c.Reason, c.Message)
			}
		}

		statuses := append(append([]k8scorev1.ContainerStatus{},
			pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)

		for _, cs := range statuses {
			if cs.Ready {
				continue
			}
			switch {
			case cs.State.Waiting != nil:
				fmt.Fprintf(&b, "; the container %s is waiting: %s %s",
					cs.Name, cs.State.Waiting.Reason, cs.State.Waiting.Message)
			case cs.State.Terminated != nil:
				fmt.Fprintf(&b, "; the container %s terminated with %d: %s %s",
					cs.Name, cs.State.Terminated.ExitCode,
					cs.State.Terminated.Reason, cs.State.Terminated.Message)
			default:
				fmt.Fprintf(&b, "; the container %s is not ready yet", cs.Name)
			}
			if cs.RestartCount > 0 {
				fmt.Fprintf(&b, " (%d restarts)", cs.RestartCount)
			}
		}

		b.WriteString(". ")
	}

	return strings.TrimSpace(b.String())
}

const hostIngressPIDPath = "/tmp/octelium-e2e-host-ingress.pid"

func (r *Runner) stepHostIngress(ctx context.Context, _ *Runner) error {
	out, err := r.BashOutput(ctx, hostIngressScript(vutils.K8sNS))
	if err != nil {
		return errors.Errorf("Could not reach the Cluster ingress from the host: %+v\n%s\n%s",
			err, out, r.ingressDiagnostics(ctx))
	}

	zap.L().Debug("The Cluster ingress is reachable from the host", zap.String("out", out))

	return nil
}

func (r *Runner) stopHostIngress(ctx context.Context) error {
	return r.Bash(ctx, fmt.Sprintf(`
if [ -f %[1]s ]; then
  sudo kill "$(cat %[1]s)" 2>/dev/null || true
  sudo rm -f %[1]s
fi
`, hostIngressPIDPath))
}

func hostIngressScript(ns string) string {
	return fmt.Sprintf(`
SVC=octelium-ingress-dataplane
PORT=$(kubectl get svc -n %[1]s "$SVC" -o jsonpath='{.spec.ports[0].port}' 2>/dev/null || true)
PORT=${PORT:-443}

reachable() { timeout 3 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }

if reachable 127.0.0.1 "$PORT"; then
  echo "the ingress already answers on 127.0.0.1:$PORT"
  exit 0
fi

NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || true)
if [ -z "$NODE_IP" ]; then
  echo "could not determine the node address" >&2
  exit 1
fi

if ! reachable "$NODE_IP" "$PORT"; then
  echo "the ingress does not answer on $NODE_IP:$PORT either, so this is not a host port problem" >&2
  exit 1
fi

echo "the ingress answers on $NODE_IP:$PORT but not on 127.0.0.1:$PORT."
echo "Forwarding 127.0.0.1:$PORT to $NODE_IP:$PORT for the Cluster domain."

if ! command -v socat >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq socat
fi

if [ -f %[2]s ]; then
  sudo kill "$(cat %[2]s)" 2>/dev/null || true
  sudo rm -f %[2]s
fi

sudo sh -c "nohup socat TCP4-LISTEN:$PORT,bind=127.0.0.1,fork,reuseaddr TCP4:$NODE_IP:$PORT \
  >/dev/null 2>&1 & echo \$! > %[2]s"

for i in $(seq 1 30); do
  if reachable 127.0.0.1 "$PORT"; then
    echo "the ingress now answers on 127.0.0.1:$PORT"
    exit 0
  fi
  sleep 1
done

echo "the forwarder did not come up on 127.0.0.1:$PORT" >&2
exit 1
`, ns, hostIngressPIDPath)
}

func (r *Runner) stepLogin(ctx context.Context, _ *Runner) error {
	tkn, err := os.ReadFile(r.State.AuthTokenPath)
	if err != nil {
		return errors.Errorf("Could not read the initial auth token at %s: %+v",
			r.State.AuthTokenPath, err)
	}

	var reported bool

	return pollUntil(ctx, "initial login", 3*minute, 3*second, func(ctx context.Context) error {
		out, err := r.BashOutput(ctx, fmt.Sprintf(
			`OCTELIUM_INSECURE_TLS=true octelium login --domain %s --auth-token %s`,
			r.Scenario.Domain, shellQuote(strings.TrimSpace(string(tkn)))))
		if err == nil {
			return nil
		}

		if !reported {
			reported = true
			fmt.Fprint(os.Stdout, r.ingressDiagnostics(ctx))
		}

		return errors.Errorf("%+v: %s", err, loginError(out))
	})
}

func loginError(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "Error:") {
			return line
		}
	}

	if idx := strings.Index(out, "\nUsage:"); idx > 0 {
		return strings.TrimSpace(out[:idx])
	}

	return strings.TrimSpace(out)
}

func (r *Runner) ingressDiagnostics(ctx context.Context) string {
	out, err := r.BashOutput(ctx,
		diagScript(vutils.K8sNS, r.Scenario.Provisioner.CNIPaths().NetDir))
	if err != nil {
		return fmt.Sprintf("<could not collect the ingress diagnostics: %+v>\n%s\n", err, out)
	}

	return "The Cluster is up but its ingress is not reachable at the Cluster domain. " +
		"The host port is published by a k3s ServiceLB pod through the portmap CNI plugin, " +
		"which is iptables DNAT rather than a listening socket.\n" + out + "\n"
}

func diagScript(ns, netDir string) string {
	return fmt.Sprintf(`
SVC=octelium-ingress-dataplane
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null || true)
NODE_PORT=$(kubectl get svc -n %[1]s "$SVC" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || true)
CLUSTER_IP=$(kubectl get svc -n %[1]s "$SVC" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)

echo "--- where the ingress answers from ---"
for target in "127.0.0.1:443" "${NODE_IP}:443" "${NODE_IP}:${NODE_PORT}" "${CLUSTER_IP}:443"; do
  case "$target" in *:|:*) continue ;; esac
  printf '%%-24s ' "$target"
  curl -sk -o /dev/null -m 5 -w 'http=%%{http_code} connect=%%{time_connect}s\n' \
    "https://$target/" 2>&1 || echo "unreachable"
done

echo "--- the portmap DNAT rules for the host port ---"
RULES=$(sudo iptables -t nat -S 2>/dev/null | grep -iE 'hostport|CNI-DN' | head -n 20 || true)
if [ -n "$RULES" ]; then echo "$RULES"; else echo "no CNI hostport rules in the nat table"; fi

echo "--- route_localnet, which 127.0.0.1 to a pod IP depends on ---"
sudo sysctl net.ipv4.conf.all.route_localnet 2>&1 || true
for d in /proc/sys/net/ipv4/conf/*/route_localnet; do
  [ -r "$d" ] || continue
  printf '%%s = %%s\n' "$d" "$(sudo cat "$d" 2>/dev/null)"
done | grep -vE '/(lo|default)/' | head -n 15 || true

echo "--- the k3s ServiceLB pod that owns the host port ---"
kubectl get pods -n kube-system -o wide 2>&1 | grep -i svclb || echo "no svclb pod exists"
kubectl get ds -n kube-system 2>&1 | grep -i svclb || echo "no svclb daemonset exists"
kubectl get pod -n kube-system -l svccontroller.k3s.cattle.io/svcname="$SVC" \
  -o jsonpath='{.items[0].spec.containers[*].ports}' 2>&1 || true
echo

echo "--- the Cluster ingress Services ---"
kubectl get svc -n %[1]s -o wide 2>&1 | head -n 20

echo "--- the CNI config chain in %[2]s ---"
sudo ls -la %[2]s 2>&1
for f in %[2]s/*.conf %[2]s/*.conflist; do
  [ -f "$f" ] || continue
  echo "--- $f ---"
  sudo cat "$f" 2>&1 | head -n 40
done
`, ns, netDir)
}

func (r *Runner) stepStorageSecretResource(ctx context.Context, _ *Runner) error {
	return r.Bash(ctx, fmt.Sprintf(
		`OCTELIUM_INSECURE_TLS=true octeliumctl create secret pg --value %s`,
		shellQuote(r.State.PostgresPassword)))
}

func (r *Runner) stepClusterCert(ctx context.Context, _ *Runner) error {
	domain := r.Scenario.Domain

	sans := []string{
		domain,
		fmt.Sprintf("*.%s", domain),

		fmt.Sprintf("*.octelium.%s", domain),
		fmt.Sprintf("*.octelium-api.%s", domain),

		fmt.Sprintf("*.local.%s", domain),
		fmt.Sprintf("*.default.%s", domain),
		fmt.Sprintf("*.default.local.%s", domain),

		fmt.Sprintf("*.octelium.local.%s", domain),
		fmt.Sprintf("*.octelium-api.local.%s", domain),

		fmt.Sprintf("*.%s.%s", TestNamespace, domain),
		fmt.Sprintf("*.%s.local.%s", TestNamespace, domain),
	}

	zap.L().Debug("Setting the initial Cluster certificate",
		zap.String("domain", domain), zap.Strings("sans", sans))

	crt, err := utils_cert.GenerateSelfSignedCert(domain, sans, 4*12*30*24*time.Hour)
	if err != nil {
		return err
	}

	crtPEM, err := crt.GetCertPEM()
	if err != nil {
		return err
	}

	privPEM, err := crt.GetPrivateKeyPEM()
	if err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "octelium-e2e-cert-*")
	if err != nil {
		return err
	}

	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")

	if err := os.WriteFile(keyPath, []byte(privPEM), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, []byte(crtPEM), 0o644); err != nil {
		return err
	}

	r.State.KeyPath = keyPath
	r.State.CertPath = certPath

	if err := r.Bash(ctx, fmt.Sprintf(`
sudo cp %s /usr/local/share/ca-certificates/octelium-cluster.crt
sudo update-ca-certificates
`, certPath)); err != nil {
		return err
	}

	return r.Bash(ctx, fmt.Sprintf(`octops cert %s --key %s --cert %s --kubeconfig %s`,
		domain, keyPath, certPath, r.State.KubeconfigPath))
}

const collectorValues = `
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
`
