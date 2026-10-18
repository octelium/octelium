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
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/pkg/errors"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	RolloutAnnotation = "octelium.com/e2e-rollout-at"

	UpgradeBudget        = 20 * time.Minute
	upgradeCommandBudget = 2 * time.Minute

	installUIDAnnotation    = "octelium.com/install-uid"
	svcUpgradeUIDAnnotation = "octelium.com/svc-upgrade-uid"
	genesisSelector         = "octelium.com/component=genesis"
)

func (h *H) ServiceDeployment(service string) string {
	return k8sutils.GetSvcHostname(svcRef(service))
}

func (h *H) RolloutRestart(ctx context.Context, deployment string) error {
	patch, err := json.Marshal(map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]string{
						RolloutAnnotation: time.Now().UTC().Format(time.RFC3339Nano),
					},
				},
			},
		},
	})
	if err != nil {
		return err
	}

	_, err = h.k8sC.AppsV1().Deployments(vutils.K8sNS).Patch(ctx, deployment,
		types.StrategicMergePatchType, patch, k8smetav1.PatchOptions{})
	return err
}

func (h *H) WaitRollout(ctx context.Context, deployment string) error {
	return h.EventuallyErr(ctx, fmt.Sprintf("the rollout of the Deployment %s", deployment),
		DeploymentBudget, func(ctx context.Context) error {
			dep, err := h.k8sC.AppsV1().Deployments(vutils.K8sNS).
				Get(ctx, deployment, k8smetav1.GetOptions{})
			if err != nil {
				return err
			}
			return deploymentRolloutErr(dep)
		})
}

func deploymentRolloutErr(dep *appsv1.Deployment) error {
	want := int32(1)
	if dep.Spec.Replicas != nil {
		want = *dep.Spec.Replicas
	}

	st := dep.Status
	switch {
	case st.ObservedGeneration < dep.Generation:
		return errors.Errorf("the Deployment %s has not observed its generation %d yet",
			dep.Name, dep.Generation)
	case st.UpdatedReplicas < want:
		return errors.Errorf("%d of %d replicas of the Deployment %s are updated",
			st.UpdatedReplicas, want, dep.Name)
	case st.Replicas > st.UpdatedReplicas:
		return errors.Errorf("%d old replicas of the Deployment %s are still running",
			st.Replicas-st.UpdatedReplicas, dep.Name)
	case st.AvailableReplicas < want:
		return errors.Errorf("%d of %d replicas of the Deployment %s are available",
			st.AvailableReplicas, want, dep.Name)
	}

	return nil
}

func daemonSetRolloutErr(ds *appsv1.DaemonSet) error {
	st := ds.Status
	switch {
	case st.ObservedGeneration < ds.Generation:
		return errors.Errorf("the DaemonSet %s has not observed its generation %d yet",
			ds.Name, ds.Generation)
	case st.UpdatedNumberScheduled < st.DesiredNumberScheduled:
		return errors.Errorf("%d of %d pods of the DaemonSet %s are updated",
			st.UpdatedNumberScheduled, st.DesiredNumberScheduled, ds.Name)
	case st.NumberAvailable < st.DesiredNumberScheduled:
		return errors.Errorf("%d of %d pods of the DaemonSet %s are available",
			st.NumberAvailable, st.DesiredNumberScheduled, ds.Name)
	}

	return nil
}

type upgradeRevision struct {
	value string
	err   error
}

func templateRevision(tmpl *k8scorev1.PodTemplateSpec) (string, bool) {
	for _, key := range []string{installUIDAnnotation, svcUpgradeUIDAnnotation} {
		if val, ok := tmpl.Annotations[key]; ok {
			return val, true
		}
	}
	return "", false
}

func (h *H) upgradeRevisions(ctx context.Context) (map[string]upgradeRevision, error) {
	deps, err := h.k8sC.AppsV1().Deployments(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	dss, err := h.k8sC.AppsV1().DaemonSets(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	ret := map[string]upgradeRevision{}

	for i := range deps.Items {
		dep := &deps.Items[i]
		if val, ok := templateRevision(&dep.Spec.Template); ok {
			ret["deployment/"+dep.Name] = upgradeRevision{value: val, err: deploymentRolloutErr(dep)}
		}
	}

	for i := range dss.Items {
		ds := &dss.Items[i]
		if val, ok := templateRevision(&ds.Spec.Template); ok {
			ret["daemonset/"+ds.Name] = upgradeRevision{value: val, err: daemonSetRolloutErr(ds)}
		}
	}

	return ret, nil
}

func pendingUpgrades(before, after map[string]upgradeRevision) []string {
	var ret []string

	for key, prev := range before {
		cur, ok := after[key]
		switch {
		case !ok:
		case cur.value == prev.value:
			ret = append(ret, fmt.Sprintf("%s has not been upgraded yet", key))
		case cur.err != nil && prev.err == nil:
			ret = append(ret, cur.err.Error())
		}
	}

	sort.Strings(ret)
	return ret
}

func genesisJobErr(job *batchv1.Job) (bool, error) {
	for _, cond := range job.Status.Conditions {
		if cond.Status != k8scorev1.ConditionTrue {
			continue
		}
		switch cond.Type {
		case batchv1.JobComplete:
			return true, nil
		case batchv1.JobFailed:
			return true, errors.Errorf("the genesis Job %s failed: %s: %s",
				job.Name, cond.Reason, cond.Message)
		}
	}

	return false, nil
}

func (h *H) newGenesisJob(ctx context.Context, since time.Time) (*batchv1.Job, error) {
	jobs, err := h.k8sC.BatchV1().Jobs(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{
		LabelSelector: genesisSelector,
	})
	if err != nil {
		return nil, err
	}

	var ret *batchv1.Job
	for i := range jobs.Items {
		job := &jobs.Items[i]
		if job.CreationTimestamp.Time.Before(since.Truncate(time.Second)) {
			continue
		}
		if ret == nil || job.CreationTimestamp.After(ret.CreationTimestamp.Time) {
			ret = job
		}
	}

	if ret == nil {
		return nil, errors.Errorf("no genesis Job has been created since %s", since.Format(time.RFC3339))
	}

	return ret, nil
}

func (h *H) upgradeCommand() string {
	ret := fmt.Sprintf("octops upgrade %s", h.Domain)
	if v := h.Scenario.Install.Version; v != "" {
		ret = fmt.Sprintf("%s --version %s", ret, v)
	}
	return ret
}

func (h *H) UpgradeCluster(t *testing.T) time.Duration {
	t.Helper()

	before, err := h.upgradeRevisions(t.Context())
	if err != nil {
		t.Fatalf("Could not list the Octelium workloads before the upgrade: %+v", err)
	}

	startedAt := time.Now()

	h.MustOutputWithin(t, h.upgradeCommand(), upgradeCommandBudget)

	var jobErr error
	h.Within(t, "the genesis upgrade Job to finish", UpgradeBudget, func(ctx context.Context) error {
		job, err := h.newGenesisJob(ctx, startedAt)
		if err != nil {
			return err
		}

		done, err := genesisJobErr(job)
		if !done {
			return errors.Errorf("the genesis Job %s is still running", job.Name)
		}

		jobErr = err
		return nil
	})
	if jobErr != nil {
		t.Fatalf("%+v", jobErr)
	}

	h.Within(t, "every Octelium workload to be replaced by the upgrade", UpgradeBudget,
		func(ctx context.Context) error {
			after, err := h.upgradeRevisions(ctx)
			if err != nil {
				return err
			}

			if pending := pendingUpgrades(before, after); len(pending) > 0 {
				return errors.Errorf("%d workloads are not upgraded yet: %s",
					len(pending), strings.Join(pending, "; "))
			}

			return nil
		})

	return time.Since(startedAt)
}
