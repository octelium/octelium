package commands

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestInitBootstrapRepairE2E(t *testing.T) {
	for _, state := range []string{"preflight-only", "checkpoint-only", "postgres-started", "redis-started", "response-lost"} {
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials", "token")
			t.Setenv("OCTELIUM_AUTH_TOKEN_SAVE_PATH", path)
			c, config := newTestKubernetes(t)
			var starts, inputWrites atomic.Int32
			c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				secret := action.(k8stesting.CreateAction).GetObject().(*corev1.Secret)
				secret.ResourceVersion = "1"
				return false, nil, nil
			})
			c.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				secret := action.(k8stesting.UpdateAction).GetObject().(*corev1.Secret)
				if secret.Name != "octelium-init" || action.GetNamespace() != "default" {
					return false, nil, nil
				}
				count := inputWrites.Add(1)
				secret.ResourceVersion = "2"
				if state == "response-lost" && count == 1 {
					assert.NoError(t, c.Tracker().Update(action.GetResource(), secret.DeepCopy(), action.GetNamespace()))
					return true, nil, k8serr.NewServiceUnavailable("response lost after bootstrap update")
				}
				return false, nil, nil
			})
			c.PrependReactor("update", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job)
				if job.Spec.Suspend != nil && *job.Spec.Suspend {
					return false, nil, nil
				}
				if starts.Add(1) == 1 {
					job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
					return false, nil, nil
				}
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: corev1.ConditionTrue}}
				token := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "init-token", Namespace: "octelium"}, Data: map[string][]byte{"data": []byte("new-admin-token")}}
				if state == "checkpoint-only" {
					object, err := c.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), "octelium", "octelium-genesis-init")
					if assert.NoError(t, err) {
						checkpoint := object.(*corev1.Secret).DeepCopy()
						checkpoint.Annotations = map[string]string{"octelium.com/genesis-init-complete": "true"}
						checkpoint.Data["id"] = []byte("new-init-id")
						assert.NoError(t, c.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), checkpoint, "octelium"))
					}
					token.Annotations = map[string]string{"octelium.com/genesis-init-id": "new-init-id"}
				}
				assert.NoError(t, c.Tracker().Add(token))
				return false, nil, nil
			})
			bootstrapPath := newTestBootstrap(t)
			contents, err := os.ReadFile(bootstrapPath)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(bootstrapPath, []byte(strings.ReplaceAll(string(contents), "host: postgres,", "host: wrong.example,")), 0600))
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			args := []string{"init", "example.com", "--bootstrap=" + bootstrapPath, "--kubeconfig=" + config, "--kubecontext=local", "--version=1.2.3"}
			output, err := executeTestCommand(t, ctx, args...)
			require.Error(t, err)
			assert.NotContains(t, output, "Cluster installation is now complete")
			_, err = os.Stat(path)
			require.True(t, os.IsNotExist(err))
			original, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", metav1.GetOptions{})
			require.NoError(t, err)
			switch state {
			case "checkpoint-only":
				require.NoError(t, c.Tracker().Add(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "octelium-genesis-init", Namespace: "octelium", UID: "previous-checkpoint"},
					Data:       map[string][]byte{"id": []byte("previous-init-id"), "version": []byte("1"), "input-hash": []byte(strings.Repeat("0", 64))},
				}))
			case "postgres-started", "redis-started":
				name := "octelium-postgres"
				if state == "redis-started" {
					name = "octelium-redis"
				}
				require.NoError(t, c.Tracker().Add(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "octelium", UID: "existing-storage"}, Data: map[string][]byte{"value": []byte("preserved")}}))
			}
			require.NoError(t, os.WriteFile(bootstrapPath, []byte(strings.ReplaceAll(string(contents), "host: postgres,", "host: corrected.example,")), 0600))
			output, err = executeTestCommand(t, ctx, args...)
			if state == "postgres-started" || state == "redis-started" {
				require.ErrorContains(t, err, "bootstrap differs")
				assert.NotContains(t, output, "new-admin-token")
				assert.Zero(t, inputWrites.Load())
				current, err := c.CoreV1().Secrets("default").Get(t.Context(), original.Name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, original, current)
				return
			}
			require.NoError(t, err, output)
			token, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "new-admin-token", string(token))
			assert.Equal(t, int32(1), inputWrites.Load())
			current, err := c.CoreV1().Secrets("default").Get(t.Context(), original.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, original.UID, current.UID)
			bootstrap := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.Unmarshal(current.Data["bootstrap"], bootstrap))
			assert.Equal(t, "corrected.example", bootstrap.Spec.PrimaryStorage.GetPostgresql().Host)
		})
	}
}
