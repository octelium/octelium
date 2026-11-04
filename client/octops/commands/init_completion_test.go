// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package commands

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestInitCompletionE2E(t *testing.T) {
	for _, state := range []string{"legacy-success", "owned-success", "failed-after-publication", "empty-token", "wrong-initialization", "incomplete-checkpoint", "replaced-job", "deleted-job", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials", "token")
			t.Setenv("OCTELIUM_AUTH_TOKEN_SAVE_PATH", path)
			c, config := newTestKubernetes(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			started := false
			c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if !started {
					return false, nil, nil
				}
				a := action.(k8stesting.GetAction)
				switch state {
				case "deleted-job":
					return true, nil, k8serr.NewNotFound(action.GetResource().GroupResource(), a.GetName())
				case "replaced-job":
					object, err := c.Tracker().Get(action.GetResource(), action.GetNamespace(), a.GetName())
					if err != nil {
						return true, nil, err
					}
					job := object.(*batchv1.Job).DeepCopy()
					job.UID = "replacement"
					return true, job, nil
				case "cancelled":
					cancel()
					return true, nil, context.Canceled
				}
				return false, nil, nil
			})
			c.PrependReactor("update", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job)
				started = true
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
				if state == "failed-after-publication" {
					job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
				}
				token := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "init-token", Namespace: "octelium"}, Data: map[string][]byte{"data": []byte("new-admin-token")}}
				if state == "empty-token" {
					token.Data = nil
				}
				if state == "owned-success" || state == "wrong-initialization" || state == "incomplete-checkpoint" {
					token.Annotations = map[string]string{"octelium.com/genesis-init-id": "init-id"}
					checkpoint := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "octelium-genesis-init", Namespace: "octelium", Annotations: map[string]string{"octelium.com/genesis-init-complete": "true"}}, Data: map[string][]byte{"id": []byte("init-id")}}
					if state == "wrong-initialization" {
						checkpoint.Data["id"] = []byte("other-initialization")
					}
					if state == "incomplete-checkpoint" {
						checkpoint.Annotations = nil
					}
					assert.NoError(t, c.Tracker().Add(checkpoint))
				}
				assert.NoError(t, c.Tracker().Add(token))
				return false, nil, nil
			})
			output, err := executeTestCommand(t, ctx, "init", "example.com", "--bootstrap="+newTestBootstrap(t), "--kubeconfig="+config, "--kubecontext=local", "--version=1.2.3")
			if state == "legacy-success" || state == "owned-success" {
				require.NoError(t, err, output)
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, "new-admin-token", string(data))
			} else {
				require.Error(t, err)
				_, fileErr := os.Stat(path)
				assert.True(t, os.IsNotExist(fileErr))
				assert.NotContains(t, output, "new-admin-token")
				assert.NotContains(t, err.Error(), "new-admin-token")
				assert.NotContains(t, output, "Cluster installation is now complete")
				if state == "cancelled" {
					assert.ErrorIs(t, err, context.Canceled)
				}
			}
		})
	}
}
