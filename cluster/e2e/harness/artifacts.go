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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/common/vutils"
	"go.uber.org/zap"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const ArtifactDirEnv = "OCTELIUM_E2E_ARTIFACTS"

type ArtifactCollector struct {
	h   *H
	dir string

	mu   sync.Mutex
	done map[string]bool
}

func NewArtifactCollector(h *H, dir string) *ArtifactCollector {
	if dir == "" {
		dir = os.Getenv(ArtifactDirEnv)
	}
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "octelium-e2e", "artifacts")
	}

	return &ArtifactCollector{
		h:    h,
		dir:  dir,
		done: map[string]bool{},
	}
}

func (a *ArtifactCollector) Collect(t *testing.T) {
	a.mu.Lock()
	if a.done[t.Name()] {
		a.mu.Unlock()
		return
	}
	a.done[t.Name()] = true
	a.mu.Unlock()

	dir := filepath.Join(a.dir, a.h.Scenario.ID, sanitize(t.Name()))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		zap.L().Warn("Could not create the artifact directory", zap.Error(err))
		return
	}

	zap.L().Info("Collecting failure artifacts",
		zap.String("test", t.Name()), zap.String("dir", dir))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	for _, itm := range []struct {
		file string
		cmd  string
	}{
		{"get-all.yaml", "kubectl get all -A -o yaml"},
		{"get-pods.txt", "kubectl get pods -A -o wide"},
		{"events.txt", "kubectl get events -A --sort-by=.lastTimestamp"},
		{"nodes.yaml", "kubectl get nodes -o yaml"},
		{"octelium-services.yaml", "octeliumctl get svc -o yaml"},
		{"octelium-sessions.yaml", "octeliumctl get session -o yaml"},
		{"octelium-gateways.yaml", "octeliumctl get gw -o yaml"},
		{"octelium-policies.yaml", "octeliumctl get policy -o yaml"},
	} {
		a.capture(ctx, dir, itm.file, itm.cmd)
	}

	a.capturePods(ctx, dir)
}

func (a *ArtifactCollector) capture(ctx context.Context, dir, file, cmdStr string) {
	out, err := a.h.Output(ctx, cmdStr)
	if err != nil {
		out = append(out, []byte(fmt.Sprintf("\n\n[command failed: %+v]\n", err))...)
	}

	if err := os.WriteFile(filepath.Join(dir, file), out, 0o644); err != nil {
		zap.L().Warn("Could not write an artifact",
			zap.String("file", file), zap.Error(err))
	}
}

func (a *ArtifactCollector) capturePods(ctx context.Context, dir string) {
	podList, err := a.h.k8sC.CoreV1().Pods(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{})
	if err != nil {
		zap.L().Warn("Could not list pods for artifacts", zap.Error(err))
		return
	}

	logsDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		return
	}

	for _, pod := range podList.Items {
		a.capture(ctx, logsDir, pod.Name+".log",
			fmt.Sprintf("kubectl logs -n %s %s --all-containers --tail=2000",
				vutils.K8sNS, pod.Name))

		for _, cs := range pod.Status.ContainerStatuses {
			if cs.RestartCount == 0 {
				continue
			}
			a.capture(ctx, logsDir,
				fmt.Sprintf("%s.%s.previous.log", pod.Name, cs.Name),
				fmt.Sprintf("kubectl logs -n %s %s -c %s --previous --tail=2000",
					vutils.K8sNS, pod.Name, cs.Name))
		}

		if pod.Status.Phase != "Running" {
			a.capture(ctx, logsDir, pod.Name+".describe.txt",
				fmt.Sprintf("kubectl describe pod -n %s %s", vutils.K8sNS, pod.Name))
		}
	}
}

func sanitize(arg string) string {
	return strings.NewReplacer("/", "_", " ", "_", ":", "_").Replace(arg)
}
