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
	"os"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

type Step struct {
	Name string
	Run  func(ctx context.Context, r *Runner) error
	Skip func(r *Runner) bool
}

func runSteps(ctx context.Context, r *Runner, stage string, steps []Step) error {
	for _, step := range steps {
		if step.Skip != nil && step.Skip(r) {
			zap.L().Info("Skipping step",
				zap.String("stage", stage), zap.String("step", step.Name))
			continue
		}

		zap.L().Info("Step starting",
			zap.String("stage", stage), zap.String("step", step.Name))
		started := time.Now()

		if err := step.Run(ctx, r); err != nil {
			zap.L().Error("Step failed",
				zap.String("stage", stage), zap.String("step", step.Name),
				zap.Duration("duration", time.Since(started)), zap.Error(err))
			return err
		}

		zap.L().Info("Step done",
			zap.String("stage", stage), zap.String("step", step.Name),
			zap.Duration("duration", time.Since(started)))
	}

	return nil
}

func (r *Runner) Bash(ctx context.Context, script string) error {
	cmd := r.bashCmd(ctx, script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) BashInput(ctx context.Context, script string, in string) error {
	cmd := r.bashCmd(ctx, script)
	cmd.Stdin = strings.NewReader(in)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (r *Runner) BashOutput(ctx context.Context, script string) (string, error) {
	cmd := r.bashCmd(ctx, script)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (r *Runner) bashCmd(ctx context.Context, script string) *exec.Cmd {
	zap.L().Debug("Running shell snippet", zap.String("script", script))

	cmd := exec.CommandContext(ctx, "bash", "-c", "set -e\n"+script)
	cmd.Env = r.env()
	return cmd
}

func (r *Runner) env() []string {
	ret := os.Environ()
	for k, v := range r.extraEnv {
		ret = append(ret, k+"="+v)
	}
	return ret
}
