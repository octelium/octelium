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

	paths := s.Provisioner.CNIPaths()
	if paths.NetDir != "" {
		r.SetEnv("OCTELIUM_CNI_CONF_DIR", paths.NetDir)
	}
	if paths.MultusConfDir != "" {
		r.SetEnv(vutils.MultusConfDirEnv, paths.MultusConfDir)
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

		err := pollUntil(ctx, fmt.Sprintf("deployment %s", name), timeout, 2*second,
			func(ctx context.Context) error {
				ctx, cancel := context.WithTimeout(ctx, 30*second)
				defer cancel()
				return k8sutils.WaitReadinessDeploymentWithNS(ctx, k8sC, name, vutils.K8sNS)
			})
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *Runner) stepLogin(ctx context.Context, _ *Runner) error {
	tkn, err := os.ReadFile(r.State.AuthTokenPath)
	if err != nil {
		return errors.Errorf("Could not read the initial auth token at %s: %+v",
			r.State.AuthTokenPath, err)
	}

	return pollUntil(ctx, "initial login", 3*minute, 3*second, func(ctx context.Context) error {
		out, err := r.BashOutput(ctx, fmt.Sprintf(
			`OCTELIUM_INSECURE_TLS=true octelium login --domain %s --auth-token %s`,
			r.Scenario.Domain, shellQuote(strings.TrimSpace(string(tkn)))))
		if err != nil {
			return errors.Errorf("%+v: %s", err, out)
		}
		return nil
	})
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
