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
	"slices"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	WatchIntervalEnv = "OCTELIUM_E2E_WATCH_INTERVAL"

	watchIntervalDefault = 30 * time.Second
	watchEventCount      = 12
	watchMessageMax      = 400
)

func watchInterval() time.Duration {
	val := strings.TrimSpace(os.Getenv(WatchIntervalEnv))
	if val == "" {
		return watchIntervalDefault
	}

	d, err := time.ParseDuration(val)
	if err != nil || d <= 0 {
		zap.L().Warn("Ignoring an invalid watch interval",
			zap.String("value", val), zap.String("env", WatchIntervalEnv))
		return watchIntervalDefault
	}

	return d
}

func (r *Runner) watchCluster(ctx context.Context, stage string) func() {
	interval := watchInterval()

	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		defer close(done)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		var k8sC kubernetes.Interface
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			if k8sC == nil {
				var err error
				if k8sC, err = r.newK8sC(); err != nil {
					zap.L().Debug("No cluster to watch yet",
						zap.String("stage", stage), zap.Error(err))
					continue
				}
			}

			reportCluster(ctx, k8sC, stage)
		}
	}()

	return func() {
		cancel()
		<-done
	}
}

func (r *Runner) newK8sC() (kubernetes.Interface, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", r.State.KubeconfigPath)
	if err != nil {
		return nil, err
	}
	cfg.QPS = k8sClientQPS
	cfg.Burst = k8sClientBurst

	return kubernetes.NewForConfig(cfg)
}

func reportCluster(ctx context.Context, k8sC kubernetes.Interface, stage string) {
	pods, err := k8sC.CoreV1().Pods("").List(ctx, k8smetav1.ListOptions{})
	if err != nil {
		zap.L().Debug("Could not list the pods",
			zap.String("stage", stage), zap.Error(err))
		return
	}

	var ready int
	var notReady []string
	for i := range pods.Items {
		pod := &pods.Items[i]
		if line := podNotReady(pod); line != "" {
			notReady = append(notReady, line)
		} else {
			ready++
		}
	}

	sort.Strings(notReady)

	zap.L().Info("Cluster state",
		zap.String("stage", stage),
		zap.Int("pods", len(pods.Items)),
		zap.Int("ready", ready),
		zap.Int("notReady", len(notReady)))

	if len(notReady) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString("Pods that are not ready:\n")
	b.WriteString(strings.Join(notReady, "\n"))
	b.WriteString("\n")

	if events := recentWarnings(ctx, k8sC); events != "" {
		b.WriteString("Recent warning events:\n")
		b.WriteString(events)
		b.WriteString("\n")
	}

	fmt.Fprint(os.Stdout, b.String())
}

func podNotReady(pod *k8scorev1.Pod) string {
	if pod.Status.Phase == k8scorev1.PodSucceeded {
		return ""
	}

	statuses := append(append([]k8scorev1.ContainerStatus{},
		pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)

	var total, up int
	var detail []string
	for _, cs := range statuses {
		total++
		if cs.Ready {
			up++
			continue
		}

		switch {
		case cs.State.Waiting != nil:
			detail = append(detail, fmt.Sprintf("%s waiting %s %s",
				cs.Name, cs.State.Waiting.Reason,
				strings.TrimSpace(cs.State.Waiting.Message)))
		case cs.State.Terminated != nil:
			detail = append(detail, fmt.Sprintf("%s exited %d %s",
				cs.Name, cs.State.Terminated.ExitCode, cs.State.Terminated.Reason))
		}

		if cs.RestartCount > 0 {
			detail = append(detail, fmt.Sprintf("%s restarted %d times",
				cs.Name, cs.RestartCount))
		}
	}

	if pod.Status.Phase == k8scorev1.PodRunning && total > 0 && up == total {
		return ""
	}

	for _, c := range pod.Status.Conditions {
		if c.Type == k8scorev1.PodScheduled && c.Status != k8scorev1.ConditionTrue {
			detail = append(detail, fmt.Sprintf("unscheduled %s %s",
				c.Reason, strings.TrimSpace(c.Message)))
		}
	}

	ret := fmt.Sprintf("  %s/%s %s %d/%d",
		pod.Namespace, pod.Name, pod.Status.Phase, up, total)
	if len(detail) > 0 {
		ret += " | " + strings.Join(detail, "; ")
	}

	return ret
}

func recentWarnings(ctx context.Context, k8sC kubernetes.Interface) string {
	events, err := k8sC.CoreV1().Events("").List(ctx, k8smetav1.ListOptions{
		FieldSelector: "type=Warning",
	})
	if err != nil {
		return ""
	}

	items := events.Items
	sort.Slice(items, func(i, j int) bool {
		return eventTime(&items[i]).Before(eventTime(&items[j]))
	})

	type group struct {
		reason  string
		message string
		objects []string
	}

	groups := map[string]*group{}
	var order []string

	for i := range items {
		e := &items[i]
		msg := truncate(strings.TrimSpace(e.Message), watchMessageMax)
		key := e.Reason + "\x00" + msg

		g, ok := groups[key]
		if !ok {
			g = &group{reason: e.Reason, message: msg}
			groups[key] = g
			order = append(order, key)
		}

		obj := e.InvolvedObject.Name
		if e.Namespace != "" {
			obj = e.Namespace + "/" + obj
		}
		if !slices.Contains(g.objects, obj) {
			g.objects = append(g.objects, obj)
		}
	}

	if len(order) > watchEventCount {
		order = order[len(order)-watchEventCount:]
	}

	var b strings.Builder
	for _, key := range order {
		g := groups[key]

		who := g.objects[0]
		if len(g.objects) > 1 {
			who = fmt.Sprintf("%s and %d more", who, len(g.objects)-1)
		}

		fmt.Fprintf(&b, "  %s %s: %s\n", who, g.reason, g.message)
	}

	return strings.TrimRight(b.String(), "\n")
}

func truncate(arg string, max int) string {
	if len(arg) <= max {
		return arg
	}
	return arg[:max] + "..."
}

func eventTime(e *k8scorev1.Event) time.Time {
	if !e.LastTimestamp.IsZero() {
		return e.LastTimestamp.Time
	}
	if !e.EventTime.IsZero() {
		return e.EventTime.Time
	}
	return e.CreationTimestamp.Time
}
