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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

func (r *Runner) prepareSteps() []Step {
	return []Step{
		{Name: "storage/credentials", Run: r.stepStorageCredentials},
		{
			Name: "storage/pvc",
			Skip: func(r *Runner) bool { return r.Scenario.Storage.Postgres.PVCName == "" },
			Run:  r.stepStoragePVC,
		},
		{Name: "storage/secrets", Run: r.stepStorageSecrets},
		{
			Name: "cni/multus",
			Skip: func(r *Runner) bool { return !r.Scenario.Multus.Enabled },
			Run:  r.stepMultus,
		},
		{Name: "storage/redis", Run: r.stepRedis},
		{Name: "storage/postgres", Run: r.stepPostgres},
	}
}

func randomPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (r *Runner) stepStorageCredentials(ctx context.Context, _ *Runner) error {
	if r.State.PostgresPassword == "" {
		val, err := randomPassword()
		if err != nil {
			return err
		}
		r.State.PostgresPassword = val
	}

	if r.State.RedisPassword == "" {
		val, err := randomPassword()
		if err != nil {
			return err
		}
		r.State.RedisPassword = val
	}

	return r.SaveState()
}

func (r *Runner) stepStoragePVC(ctx context.Context, _ *Runner) error {
	pg := r.Scenario.Storage.Postgres

	size := pg.PVCSize
	if size == "" {
		size = "5Gi"
	}

	return r.BashInput(ctx, `kubectl apply -f -`, fmt.Sprintf(`
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: %s
spec:
  resources:
    requests:
      storage: %s
  accessModes:
    - ReadWriteOnce
`, pg.PVCName, size))
}

func (r *Runner) stepStorageSecrets(ctx context.Context, _ *Runner) error {
	pg := r.Scenario.Storage.Postgres
	redis := r.Scenario.Storage.Redis

	return r.Bash(ctx, fmt.Sprintf(`
kubectl create secret generic %[1]s \
  --from-literal=postgres-password=%[2]s \
  --from-literal=password=%[2]s \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic %[3]s \
  --from-literal=password=%[4]s \
  --dry-run=client -o yaml | kubectl apply -f -
`, pg.SecretName, shellQuote(r.State.PostgresPassword),
		redis.SecretName, shellQuote(r.State.RedisPassword)))
}

func (r *Runner) stepMultus(ctx context.Context, _ *Runner) error {
	m := r.Scenario.Multus
	paths := r.Scenario.Provisioner.CNIPaths()

	if paths.BinDir == "" || paths.NetDir == "" {
		return errors.Errorf(
			"The %s provisioner did not report CNI paths, which Multus needs",
			r.Scenario.Provisioner.Name())
	}

	var args []string
	args = append(args, fmt.Sprintf("--set hostCNIBinDir=%s", paths.BinDir))
	args = append(args, fmt.Sprintf("--set hostCNINetDir=%s", paths.NetDir))
	if m.ImageRepository != "" {
		args = append(args, fmt.Sprintf("--set image.repository=%s", m.ImageRepository))
	}
	if m.AllowInsecure {
		args = append(args, "--set global.security.allowInsecureImages=true")
	}
	if m.ChartVersion != "" {
		args = append(args, fmt.Sprintf("--version %s", m.ChartVersion))
	}

	return r.helmInstall(ctx, "kube-system", "octelium-multus", m.Chart, args, "")
}

func (r *Runner) stepRedis(ctx context.Context, _ *Runner) error {
	redis := r.Scenario.Storage.Redis

	args := []string{
		fmt.Sprintf("--set auth.existingSecret=%s", redis.SecretName),
		"--set auth.existingSecretPasswordKey=password",
		"--set architecture=standalone",
		"--set master.persistence.enabled=false",
		"--set standalone.persistence.enabled=false",
		"--set networkPolicy.enabled=false",
	}
	if redis.ImageRepository != "" {
		args = append(args, fmt.Sprintf("--set image.repository=%s", redis.ImageRepository))
	}
	if redis.AllowInsecure {
		args = append(args, "--set global.security.allowInsecureImages=true")
	}
	if redis.ChartVersion != "" {
		args = append(args, fmt.Sprintf("--version %s", redis.ChartVersion))
	}

	return r.helmInstall(ctx, "default", redis.ReleaseName, redis.Chart, args, "")
}

func (r *Runner) stepPostgres(ctx context.Context, _ *Runner) error {
	pg := r.Scenario.Storage.Postgres

	args := []string{
		"--wait", "--timeout 30m0s",
		fmt.Sprintf("--set global.postgresql.auth.existingSecret=%s", pg.SecretName),
		fmt.Sprintf("--set global.postgresql.auth.database=%s", pg.Database),
		fmt.Sprintf("--set global.postgresql.auth.username=%s", pg.Username),
		"--set primary.networkPolicy.enabled=false",
	}
	if pg.PVCName != "" {
		args = append(args, fmt.Sprintf("--set primary.persistence.existingClaim=%s", pg.PVCName))
	}
	if pg.ImageRepository != "" {
		args = append(args, fmt.Sprintf("--set image.repository=%s", pg.ImageRepository))
	}
	if pg.AllowInsecure {
		args = append(args, "--set global.security.allowInsecureImages=true")
	}
	if pg.ChartVersion != "" {
		args = append(args, fmt.Sprintf("--version %s", pg.ChartVersion))
	}

	return r.helmInstall(ctx, "default", pg.ReleaseName, pg.Chart, args, "")
}

func (r *Runner) helmInstall(ctx context.Context,
	ns, release, chart string, args []string, values string) error {
	if chart == "" {
		return errors.Errorf("No chart configured for the helm release %q", release)
	}

	script := fmt.Sprintf("helm upgrade --install --namespace %s %s %s %s",
		ns, release, chart, strings.Join(args, " "))

	if values != "" {
		return r.BashInput(ctx, script+" -f -", values)
	}

	return r.Bash(ctx, script)
}

func shellQuote(arg string) string {
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}
