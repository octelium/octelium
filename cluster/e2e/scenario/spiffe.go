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
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	SPIRENamespace = "spire"

	SPIRERepoName = "spire"
	SPIRERepoURL  = "https://spiffe.github.io/helm-charts-hardened/"

	SPIFFECSIDriverDefault = "csi.spiffe.io"

	SPIFFETrustDomainDefault = "octelium.local"

	spireClusterName = "octelium-e2e"
)

func stepSPIRE(ctx context.Context, r *Runner) error {
	o := r.Scenario.Install

	trustDomain := o.SPIFFETrustDomain
	if trustDomain == "" {
		return errors.Errorf(
			"The scenario %s enables SPIFFE without a trust domain. The Cluster components "+
				"authorize their peers by trust domain, so it has to be set here and it has "+
				"to be the same one SPIRE issues SVIDs in",
			r.Scenario.ID)
	}

	driver := o.SPIFFECSIDriver
	if driver == "" {
		driver = SPIFFECSIDriverDefault
	}

	zap.L().Debug("Installing SPIRE",
		zap.String("trustDomain", trustDomain), zap.String("csiDriver", driver))

	if err := r.Bash(ctx, fmt.Sprintf(`
helm repo add %[1]s %[2]s
helm repo update %[1]s
`, SPIRERepoName, SPIRERepoURL)); err != nil {
		return err
	}

	if err := r.Bash(ctx, fmt.Sprintf(`
helm upgrade --install spire-crds %[1]s/spire-crds \
  --namespace %[2]s --create-namespace --wait --timeout 10m
`, SPIRERepoName, SPIRENamespace)); err != nil {
		return err
	}

	if err := r.Bash(ctx, fmt.Sprintf(`
helm upgrade --install spire %[1]s/spire \
  --namespace %[2]s --create-namespace --wait --timeout 15m \
  --set global.spire.trustDomain=%[3]s \
  --set global.spire.clusterName=%[4]s \
  --set spiffe-csi-driver.enabled=true \
  --set spiffe-csi-driver.pluginName=%[5]s
`, SPIRERepoName, SPIRENamespace, trustDomain, spireClusterName, driver)); err != nil {
		return err
	}

	if err := verifySPIFFECSIDriver(ctx, r, driver); err != nil {
		return err
	}

	return verifySPIRETrustDomain(ctx, r, trustDomain)
}

func verifySPIFFECSIDriver(ctx context.Context, r *Runner, driver string) error {
	return pollUntil(ctx, fmt.Sprintf("the CSI driver %s to register", driver),
		3*minute, 3*second, func(ctx context.Context) error {
			out, err := r.BashOutput(ctx,
				fmt.Sprintf("kubectl get csidriver %s -o name", shellQuote(driver)))
			if err != nil {
				return errors.Errorf(
					"Every Cluster component mounts a %s volume, so they all stay in "+
						"ContainerCreating until this driver exists: %+v. %s",
					driver, err, out)
			}
			return nil
		})
}

func verifySPIRETrustDomain(ctx context.Context, r *Runner, want string) error {
	out, err := r.BashOutput(ctx, fmt.Sprintf(
		"kubectl get configmaps --namespace %s -o yaml", SPIRENamespace))
	if err != nil {
		zap.L().Warn("Could not read the SPIRE ConfigMaps to verify the trust domain",
			zap.Error(err))
		return nil
	}

	got := parseSPIRETrustDomain(out)
	if got == "" {
		zap.L().Warn("Could not find the trust domain in the SPIRE server config. "+
			"Skipping the check", zap.String("want", want))
		return nil
	}

	if got != want {
		return errors.Errorf(
			"SPIRE issues SVIDs in the trust domain %q but the Cluster is being told to "+
				"authorize peers in %q. Every mTLS handshake between the components would "+
				"be rejected and the install would hang", got, want)
	}

	zap.L().Debug("SPIRE serves the expected trust domain", zap.String("trustDomain", got))

	return nil
}

func parseSPIRETrustDomain(configMaps string) string {
	for _, line := range strings.Split(configMaps, "\n") {
		_, after, ok := strings.Cut(line, "trust_domain")
		if !ok {
			continue
		}

		after = strings.TrimLeft(after, "\" \t:=")

		if idx := strings.IndexAny(after, "\","); idx >= 0 {
			after = after[:idx]
		}

		if after = strings.TrimSpace(after); after != "" {
			return after
		}
	}

	return ""
}
