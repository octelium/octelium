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

package harness

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

func (h *H) Cmd(ctx context.Context, cmdStr string) *exec.Cmd {
	return exec.CommandContext(ctx, "bash", "-c", cmdStr)
}

func (h *H) Run(ctx context.Context, cmdStr string) error {
	cmd := h.Cmd(ctx, cmdStr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	zap.L().Debug("Running cmd", zap.String("cmd", cmdStr))
	return cmd.Run()
}

func (h *H) MustRun(t *testing.T, cmdStr string) {
	t.Helper()
	if err := h.Run(t.Context(), cmdStr); err != nil {
		t.Fatalf("Command failed: %s: %+v", cmdStr, err)
	}
}

func (h *H) MustFail(t *testing.T, cmdStr string) {
	t.Helper()
	if err := h.Run(t.Context(), cmdStr); err == nil {
		t.Fatalf("Command unexpectedly succeeded: %s", cmdStr)
	}
}

func (h *H) MustFailWithin(t *testing.T, cmdStr string, budget time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), budget)
	defer cancel()

	err := h.Run(ctx, cmdStr)

	if ctx.Err() != nil {
		t.Fatalf("Command did not exit within %s: %s", budget, cmdStr)
	}
	if err == nil {
		t.Fatalf("Command unexpectedly succeeded: %s", cmdStr)
	}
}

func (h *H) Output(ctx context.Context, cmdStr string) ([]byte, error) {
	zap.L().Debug("Running cmd", zap.String("cmd", cmdStr))
	return h.Cmd(ctx, cmdStr).CombinedOutput()
}

func (h *H) MustOutput(t *testing.T, cmdStr string) []byte {
	t.Helper()

	out, err := h.Output(t.Context(), cmdStr)
	if err != nil {
		t.Fatalf("Command failed: %s: %+v\n%s", cmdStr, err, out)
	}

	zap.L().Debug("Command out", zap.String("cmd", cmdStr), zap.String("out", string(out)))
	return out
}

func (h *H) MustOutputProto(t *testing.T, cmdStr string, msg proto.Message) {
	t.Helper()

	out := h.MustOutput(t, cmdStr)
	if err := pbutils.UnmarshalJSON(out, msg); err != nil {
		t.Fatalf("Could not parse the output of %s: %+v\n%s", cmdStr, err, out)
	}
}

func (h *H) StartBackground(t *testing.T, cmdStr string, env ...string) *exec.Cmd {
	t.Helper()

	cmd := h.Cmd(h.rootCtx, cmdStr)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	zap.L().Debug("Starting background cmd", zap.String("cmd", cmdStr))
	if err := cmd.Start(); err != nil {
		t.Fatalf("Could not start %s: %+v", cmdStr, err)
	}

	t.Cleanup(func() {
		if cmd.Process == nil || cmd.ProcessState != nil {
			return
		}
		cmd.Process.Kill()
		cmd.Wait()
	})

	return cmd
}

func (h *H) StartLogStream(ctx context.Context, selector string) error {
	cmd := h.Cmd(ctx, "kubectl logs -f -n octelium "+selector)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return errors.Errorf("Could not stream logs for %s: %+v", selector, err)
	}

	return nil
}
