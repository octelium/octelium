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

package suite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

func genesisSecretDigests(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT uid, resource->'data' FROM octelium_resources WHERE kind = 'Secret'`)
	require.NoError(t, err)
	defer rows.Close()
	ret := make(map[string]string)
	for rows.Next() {
		var uid string
		var data []byte
		require.NoError(t, rows.Scan(&uid, &data))
		ret[uid] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	require.NoError(t, rows.Err())
	return ret
}

func createBlockedGenesisJob(t *testing.T, h *harness.H) *batchv1.Job {
	t.Helper()
	labels := map[string]string{"octelium.com/component": "genesis"}
	jobs := h.K8sC().BatchV1().Jobs(vutils.K8sNS)
	job, err := jobs.Create(t.Context(), &batchv1.Job{
		ObjectMeta: k8smetav1.ObjectMeta{GenerateName: "genesis-blocked-e2e-", Labels: labels},
		Spec: batchv1.JobSpec{Template: k8scorev1.PodTemplateSpec{
			ObjectMeta: k8smetav1.ObjectMeta{Labels: labels},
			Spec: k8scorev1.PodSpec{
				RestartPolicy: k8scorev1.RestartPolicyNever,
				Containers: []k8scorev1.Container{{
					Name: "genesis", Image: "localhost:1/octelium/genesis:missing", ImagePullPolicy: k8scorev1.PullAlways,
				}},
			},
		}},
	}, k8smetav1.CreateOptions{})
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := jobs.Delete(ctx, job.Name, k8smetav1.DeleteOptions{
			Preconditions: &k8smetav1.Preconditions{UID: &job.UID}, PropagationPolicy: new(k8smetav1.DeletePropagationBackground),
		})
		if !k8serr.IsNotFound(err) {
			assert.NoError(t, err)
		}
	})
	h.Within(t, "the blocked genesis Job to report its image failure", 2*time.Minute, func(ctx context.Context) error {
		pods, err := h.K8sC().CoreV1().Pods(vutils.K8sNS).List(ctx, k8smetav1.ListOptions{LabelSelector: batchv1.JobNameLabel + "=" + job.Name})
		if err != nil {
			return err
		}
		for _, pod := range pods.Items {
			for _, container := range pod.Status.ContainerStatuses {
				if state := container.State.Waiting; state != nil && (state.Reason == "ErrImagePull" || state.Reason == "ImagePullBackOff") {
					return nil
				}
			}
		}
		return errors.Errorf("The Job %s has not reported an image failure yet", job.Name)
	})
	return job
}

func testGenesisInitializationReplay(t *testing.T, h *harness.H) {
	ctx := t.Context()
	c := h.K8sC()
	state, err := c.CoreV1().Secrets(vutils.K8sNS).Get(ctx, "octelium-genesis-init", k8smetav1.GetOptions{})
	if k8serr.IsNotFound(err) {
		t.Skip("This installation predates resumable genesis initialization")
	}
	require.NoError(t, err)
	require.Equal(t, "true", state.Annotations["octelium.com/genesis-init-complete"])
	namespace, err := c.CoreV1().Namespaces().Get(ctx, vutils.K8sNS, k8smetav1.GetOptions{})
	require.NoError(t, err)
	cluster, err := h.CoreC().GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
	require.NoError(t, err)
	region, err := h.CoreC().GetRegion(ctx, &metav1.GetOptions{Name: "default"})
	require.NoError(t, err)
	policy := h.CreatePolicy(t, &corev1.Policy{Metadata: &metav1.Metadata{Name: h.Name()}, Spec: &corev1.Policy_Spec{Rules: []*corev1.Policy_Spec_Rule{harness.AllowAnyRule("preserved", 0)}}})
	db, err := h.ClusterDB(ctx)
	require.NoError(t, err)
	secrets := genesisSecretDigests(t, db)
	token, err := c.CoreV1().Secrets(vutils.K8sNS).Get(ctx, "init-token", k8smetav1.GetOptions{})
	require.NoError(t, err)
	tokenDigest := sha256.Sum256(token.Data["data"])
	source, err := c.BatchV1().Jobs("default").Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
	require.NoError(t, err)

	for range 2 {
		spec := source.Spec.Template.DeepCopy()
		for _, label := range []string{batchv1.JobNameLabel, batchv1.ControllerUidLabel, "job-name", "controller-uid"} {
			delete(spec.Labels, label)
		}
		job, err := c.BatchV1().Jobs("default").Create(ctx, &batchv1.Job{
			ObjectMeta: k8smetav1.ObjectMeta{GenerateName: "genesis-replay-e2e-", Namespace: "default"},
			Spec: batchv1.JobSpec{
				BackoffLimit:            new(int32(0)),
				ActiveDeadlineSeconds:   new(int64(120)),
				TTLSecondsAfterFinished: new(int32(300)),
				Template:                *spec,
			},
		}, k8smetav1.CreateOptions{})
		require.NoError(t, err)
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := c.BatchV1().Jobs(job.Namespace).Delete(ctx, job.Name, k8smetav1.DeleteOptions{Preconditions: &k8smetav1.Preconditions{UID: &job.UID}})
			if !k8serr.IsNotFound(err) {
				assert.NoError(t, err)
			}
		})
		err = wait.PollUntilContextTimeout(ctx, time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
			current, err := c.BatchV1().Jobs(job.Namespace).Get(ctx, job.Name, k8smetav1.GetOptions{})
			if err != nil {
				return false, err
			}
			for _, condition := range current.Status.Conditions {
				if condition.Type == batchv1.JobFailed && condition.Status == "True" {
					return false, errors.Errorf("Genesis replay failed: %s", condition.Reason)
				}
			}
			return current.Status.Succeeded == 1, nil
		})
		require.NoError(t, err)
		current, err := c.CoreV1().Namespaces().Get(ctx, vutils.K8sNS, k8smetav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, namespace.UID, current.UID)
		currentCluster, err := h.CoreC().GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
		require.NoError(t, err)
		assert.Equal(t, cluster.Metadata.Uid, currentCluster.Metadata.Uid)
		assert.True(t, proto.Equal(cluster.Status.Network, currentCluster.Status.Network))
		currentRegion, err := h.CoreC().GetRegion(ctx, &metav1.GetOptions{Name: "default"})
		require.NoError(t, err)
		assert.Equal(t, region.Metadata.Uid, currentRegion.Metadata.Uid)
		assert.Equal(t, secrets, genesisSecretDigests(t, db))
		currentToken, err := c.CoreV1().Secrets(vutils.K8sNS).Get(ctx, "init-token", k8smetav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, tokenDigest, sha256.Sum256(currentToken.Data["data"]))
		currentPolicy, err := h.CoreC().GetPolicy(ctx, &metav1.GetOptions{Uid: policy.Metadata.Uid})
		require.NoError(t, err)
		assert.True(t, proto.Equal(policy.Spec, currentPolicy.Spec))
	}
}
