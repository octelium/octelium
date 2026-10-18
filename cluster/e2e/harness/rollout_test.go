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
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/scenario"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func testDeployment(name string, annotations map[string]string, gen int64,
	st appsv1.DeploymentStatus) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: k8smetav1.ObjectMeta{Name: name, Namespace: vutils.K8sNS, Generation: gen},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: k8smetav1.ObjectMeta{Annotations: annotations},
			},
		},
		Status: st,
	}
}

func rolledOut(gen int64) appsv1.DeploymentStatus {
	return appsv1.DeploymentStatus{
		ObservedGeneration: gen,
		Replicas:           1,
		UpdatedReplicas:    1,
		AvailableReplicas:  1,
	}
}

func TestDeploymentRolloutErr(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   appsv1.DeploymentStatus
		ok   bool
	}{
		{name: "complete", st: rolledOut(2), ok: true},
		{name: "not observed", st: rolledOut(1)},
		{name: "not updated", st: appsv1.DeploymentStatus{
			ObservedGeneration: 2, Replicas: 1, AvailableReplicas: 1}},
		{name: "old replica", st: appsv1.DeploymentStatus{
			ObservedGeneration: 2, Replicas: 2, UpdatedReplicas: 1, AvailableReplicas: 1}},
		{name: "not available", st: appsv1.DeploymentStatus{
			ObservedGeneration: 2, Replicas: 1, UpdatedReplicas: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := deploymentRolloutErr(testDeployment("octelium-octovigil", nil, 2, tc.st))
			assert.Equal(t, tc.ok, err == nil, "%+v", err)
		})
	}
}

func TestDaemonSetRolloutErr(t *testing.T) {
	ds := func(st appsv1.DaemonSetStatus) *appsv1.DaemonSet {
		return &appsv1.DaemonSet{
			ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-gwagent", Generation: 3},
			Status:     st,
		}
	}

	assert.NoError(t, daemonSetRolloutErr(ds(appsv1.DaemonSetStatus{
		ObservedGeneration: 3, DesiredNumberScheduled: 2, UpdatedNumberScheduled: 2, NumberAvailable: 2})))
	assert.Error(t, daemonSetRolloutErr(ds(appsv1.DaemonSetStatus{
		ObservedGeneration: 2, DesiredNumberScheduled: 2, UpdatedNumberScheduled: 2, NumberAvailable: 2})))
	assert.Error(t, daemonSetRolloutErr(ds(appsv1.DaemonSetStatus{
		ObservedGeneration: 3, DesiredNumberScheduled: 2, UpdatedNumberScheduled: 1, NumberAvailable: 2})))
	assert.Error(t, daemonSetRolloutErr(ds(appsv1.DaemonSetStatus{
		ObservedGeneration: 3, DesiredNumberScheduled: 2, UpdatedNumberScheduled: 2, NumberAvailable: 1})))
}

func TestRolloutRestart(t *testing.T) {
	h := &H{k8sC: fake.NewSimpleClientset(
		testDeployment("octelium-octovigil", map[string]string{installUIDAnnotation: "a"}, 1, rolledOut(1)),
	)}

	require.NoError(t, h.RolloutRestart(t.Context(), "octelium-octovigil"))

	dep, err := h.K8sDeployment(t.Context(), "octelium-octovigil")
	require.NoError(t, err)
	first := dep.Spec.Template.Annotations[RolloutAnnotation]
	assert.NotEmpty(t, first)
	assert.Equal(t, "a", dep.Spec.Template.Annotations[installUIDAnnotation])

	time.Sleep(time.Millisecond)
	require.NoError(t, h.RolloutRestart(t.Context(), "octelium-octovigil"))

	dep, err = h.K8sDeployment(t.Context(), "octelium-octovigil")
	require.NoError(t, err)
	assert.NotEqual(t, first, dep.Spec.Template.Annotations[RolloutAnnotation])

	assert.Error(t, h.RolloutRestart(t.Context(), "octelium-missing"))
}

func TestUpgradeRevisions(t *testing.T) {
	h := &H{k8sC: fake.NewSimpleClientset(
		testDeployment("octelium-octovigil", map[string]string{installUIDAnnotation: "a"}, 1, rolledOut(1)),
		testDeployment("svc-default-octelium-api", map[string]string{svcUpgradeUIDAnnotation: ""}, 1, rolledOut(0)),
		testDeployment("my-otel-opentelemetry-collector", map[string]string{"other": "x"}, 1, rolledOut(1)),
		&appsv1.DaemonSet{
			ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-gwagent", Namespace: vutils.K8sNS},
			Spec: appsv1.DaemonSetSpec{Template: k8scorev1.PodTemplateSpec{
				ObjectMeta: k8smetav1.ObjectMeta{Annotations: map[string]string{installUIDAnnotation: "b"}},
			}},
		},
	)}

	got, err := h.upgradeRevisions(t.Context())
	require.NoError(t, err)

	require.Len(t, got, 3)
	assert.Equal(t, "a", got["deployment/octelium-octovigil"].value)
	assert.NoError(t, got["deployment/octelium-octovigil"].err)
	assert.Equal(t, "", got["deployment/svc-default-octelium-api"].value)
	assert.Error(t, got["deployment/svc-default-octelium-api"].err)
	assert.Equal(t, "b", got["daemonset/octelium-gwagent"].value)
}

func TestPendingUpgrades(t *testing.T) {
	before := map[string]upgradeRevision{
		"deployment/octelium-octovigil":       {value: "a"},
		"deployment/svc-default-octelium-api": {value: ""},
		"deployment/svc-removed":              {value: "c"},
		"daemonset/octelium-gwagent":          {value: "d"},
	}

	assert.Len(t, pendingUpgrades(before, before), 4)

	after := map[string]upgradeRevision{
		"deployment/octelium-octovigil":       {value: "a2"},
		"deployment/svc-default-octelium-api": {value: "x", err: assert.AnError},
		"daemonset/octelium-gwagent":          {value: "d"},
		"deployment/svc-new":                  {value: "x"},
	}

	assert.Equal(t, []string{
		assert.AnError.Error(),
		"daemonset/octelium-gwagent has not been upgraded yet",
	}, pendingUpgrades(before, after))

	after["deployment/svc-default-octelium-api"] = upgradeRevision{value: "x"}
	after["daemonset/octelium-gwagent"] = upgradeRevision{value: "d2"}
	assert.Empty(t, pendingUpgrades(before, after))

	broken := map[string]upgradeRevision{
		"deployment/svc-broken": {value: "a", err: assert.AnError},
	}
	assert.Equal(t, []string{"deployment/svc-broken has not been upgraded yet"},
		pendingUpgrades(broken, broken))
	assert.Empty(t, pendingUpgrades(broken, map[string]upgradeRevision{
		"deployment/svc-broken": {value: "b", err: assert.AnError},
	}), "a workload that was not available before the upgrade only needs to be replaced")
}

func TestNewGenesisJob(t *testing.T) {
	since := time.Now()

	job := func(name string, createdAt time.Time, conds ...batchv1.JobCondition) *batchv1.Job {
		return &batchv1.Job{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:              name,
				Namespace:         vutils.K8sNS,
				Labels:            map[string]string{"octelium.com/component": "genesis"},
				CreationTimestamp: k8smetav1.NewTime(createdAt),
			},
			Status: batchv1.JobStatus{Conditions: conds},
		}
	}

	{
		h := &H{k8sC: fake.NewSimpleClientset(job("octelium-genesis-upgrade-old", since.Add(-time.Hour)))}
		_, err := h.newGenesisJob(t.Context(), since)
		assert.Error(t, err)
	}

	{
		h := &H{k8sC: fake.NewSimpleClientset(
			job("octelium-genesis-upgrade-old", since.Add(-time.Hour), batchv1.JobCondition{
				Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue,
			}),
			job("octelium-genesis-upgrade-new", since.Add(time.Second)),
		)}

		got, err := h.newGenesisJob(t.Context(), since)
		require.NoError(t, err)
		assert.Equal(t, "octelium-genesis-upgrade-new", got.Name)

		done, err := genesisJobErr(got)
		assert.False(t, done)
		assert.NoError(t, err)
	}

	done, err := genesisJobErr(job("complete", since, batchv1.JobCondition{
		Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue,
	}))
	assert.True(t, done)
	assert.NoError(t, err)

	done, err = genesisJobErr(job("failed", since, batchv1.JobCondition{
		Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue, Reason: "BackoffLimitExceeded",
	}))
	assert.True(t, done)
	assert.ErrorContains(t, err, "BackoffLimitExceeded")
}

func TestUpgradeCommand(t *testing.T) {
	h := &H{Domain: "example.com", Scenario: &scenario.Scenario{}}
	assert.Equal(t, "octops upgrade example.com", h.upgradeCommand())

	h.Scenario.Install.Version = "main"
	assert.Equal(t, "octops upgrade example.com --version main", h.upgradeCommand())
}
