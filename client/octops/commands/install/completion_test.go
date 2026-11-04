package install

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func completedInstallationJob() *batchv1.Job {
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: genesisJobName, Namespace: genesisNS, UID: "submitted-job"},
		Status: batchv1.JobStatus{Succeeded: 1, Conditions: []batchv1.JobCondition{{
			Type: batchv1.JobComplete, Status: corev1.ConditionTrue,
		}}},
	}
}

func legacyInitialToken() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "init-token", Namespace: octeliumNS, UID: "initial-token"},
		Data:       map[string][]byte{"data": []byte("token")},
	}
}

func completedInitializationState() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: initializationSecretName, Namespace: octeliumNS, Annotations: map[string]string{initializationCompleteKey: "true"}},
		Data:       map[string][]byte{"id": []byte("initialization")},
	}
}

func initializationPod(job *batchv1.Job) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "genesis-worker", Namespace: job.Namespace, Labels: map[string]string{"job-name": job.Name},
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: new(true)}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodPending},
	}
}

func TestInstallationJobCompletion(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*batchv1.Job)
		complete bool
		err      string
	}{
		{"complete", func(*batchv1.Job) {}, true, ""},
		{"pending", func(job *batchv1.Job) { job.Status = batchv1.JobStatus{} }, false, ""},
		{"success-counter-only", func(job *batchv1.Job) { job.Status.Conditions = nil }, false, ""},
		{"active", func(job *batchv1.Job) { job.Status.Active = 1 }, false, ""},
		{"terminating-pods", func(job *batchv1.Job) { job.Status.Terminating = new(int32(1)) }, false, ""},
		{"complete-false", func(job *batchv1.Job) { job.Status.Conditions[0].Status = corev1.ConditionFalse }, false, ""},
		{"complete-unknown", func(job *batchv1.Job) { job.Status.Conditions[0].Status = corev1.ConditionUnknown }, false, ""},
		{"pod-failure-counter", func(job *batchv1.Job) { job.Status = batchv1.JobStatus{Failed: 1} }, false, ""},
		{"failure-target", func(job *batchv1.Job) { job.Status.Conditions[0].Type = batchv1.JobFailureTarget }, false, ""},
		{"success-criteria-met", func(job *batchv1.Job) { job.Status.Conditions[0].Type = batchv1.JobSuccessCriteriaMet }, false, ""},
		{"failed", func(job *batchv1.Job) {
			job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "BackoffLimitExceeded", Message: "All retries failed"}}
		}, false, "BackoffLimitExceeded: All retries failed"},
		{"failed-after-complete", func(job *batchv1.Job) {
			job.Status.Conditions = append(job.Status.Conditions, batchv1.JobCondition{Type: batchv1.JobFailed, Status: corev1.ConditionTrue})
		}, false, "failed"},
		{"false-failure", func(job *batchv1.Job) {
			job.Status.Conditions = append(job.Status.Conditions, batchv1.JobCondition{Type: batchv1.JobFailed, Status: corev1.ConditionFalse})
		}, true, ""},
		{"replaced", func(job *batchv1.Job) { job.UID = "replacement" }, false, "replaced"},
		{"deleted", func(job *batchv1.Job) { job.DeletionTimestamp = new(metav1.Now()) }, false, "being deleted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := completedInstallationJob()
			tc.mutate(job)
			complete, err := installationJobComplete(job, completedInstallationJob())
			assert.Equal(t, tc.complete, complete)
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestInstallationResultOwnership(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*corev1.Secret, *corev1.Secret) *corev1.Secret
		err    string
	}{
		{"owned", func(_ *corev1.Secret, state *corev1.Secret) *corev1.Secret { return state }, ""},
		{"legacy", func(token, _ *corev1.Secret) *corev1.Secret { token.Annotations = nil; return nil }, ""},
		{"wrong-initialization", func(token, state *corev1.Secret) *corev1.Secret {
			token.Annotations[initializationIDKey] = "another-installation"
			return state
		}, "completed initialization"},
		{"missing-state", func(_ *corev1.Secret, _ *corev1.Secret) *corev1.Secret { return nil }, "state is missing"},
		{"missing-id", func(_ *corev1.Secret, state *corev1.Secret) *corev1.Secret { state.Data = nil; return state }, "completed initialization"},
		{"incomplete", func(_ *corev1.Secret, state *corev1.Secret) *corev1.Secret { state.Annotations = nil; return state }, "completed initialization"},
		{"unmarked-token-with-state", func(token, state *corev1.Secret) *corev1.Secret { token.Annotations = nil; return state }, "completed initialization"},
		{"empty-token", func(token, state *corev1.Secret) *corev1.Secret { token.Data["data"] = nil; return state }, "token is empty"},
		{"missing-token-data", func(token, state *corev1.Secret) *corev1.Secret { token.Data = nil; return state }, "token is empty"},
		{"whitespace-token", func(token, state *corev1.Secret) *corev1.Secret { token.Data["data"] = []byte(" \n\t"); return state }, "token is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job, token := completedInstallationJob(), legacyInitialToken()
			token.Annotations = map[string]string{initializationIDKey: "initialization"}
			state := tc.mutate(token, completedInitializationState())
			c := fake.NewSimpleClientset(job, token)
			if state != nil {
				require.NoError(t, c.Tracker().Add(state))
			}
			got, err := getInstallationResult(t.Context(), c, job)
			if tc.err == "" {
				require.NoError(t, err)
				assert.Equal(t, token, got)
			} else {
				require.ErrorContains(t, err, tc.err)
				assert.Nil(t, got)
				assert.NotContains(t, err.Error(), "another-installation")
			}
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
			}
		})
	}
}

func TestInstallationIgnoresTokenBeforeJobCompletion(t *testing.T) {
	for _, state := range []string{"pending", "running", "failed", "replaced", "deleting", "missing"} {
		t.Run(state, func(t *testing.T) {
			expected, job := completedInstallationJob(), completedInstallationJob()
			switch state {
			case "pending":
				job.Status = batchv1.JobStatus{}
			case "running":
				job.Status = batchv1.JobStatus{Active: 1}
			case "failed":
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
			case "replaced":
				job.UID = "replacement"
			case "deleting":
				job.DeletionTimestamp = new(metav1.Now())
			}
			c := fake.NewSimpleClientset(legacyInitialToken())
			if state != "missing" {
				require.NoError(t, c.Tracker().Add(job))
			}
			secret, err := getInstallationResult(t.Context(), c, expected)
			require.Error(t, err)
			assert.Nil(t, secret)
			for _, action := range c.Actions() {
				assert.NotEqual(t, "secrets", action.GetResource().Resource)
			}
		})
	}
}

func TestInstallationFailureAfterTokenPublication(t *testing.T) {
	job := completedInstallationJob()
	c := fake.NewSimpleClientset(legacyInitialToken())
	gets := 0
	c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
		gets++
		current := job.DeepCopy()
		if gets == 1 {
			current.Status = batchv1.JobStatus{Active: 1}
		} else {
			current.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "DeadlineExceeded"}}
		}
		return true, current, nil
	})
	secret, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, time.Second)
	require.ErrorContains(t, err, "DeadlineExceeded")
	assert.Nil(t, secret)
	assert.Equal(t, 2, gets)
	for _, action := range c.Actions() {
		assert.NotEqual(t, "secrets", action.GetResource().Resource)
	}
}

func TestInstallationRechecksJobBeforeAcceptingToken(t *testing.T) {
	for _, state := range []string{"replaced", "deleted", "deleting", "failed", "running", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			c := fake.NewSimpleClientset(job, legacyInitialToken())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			gets := 0
			c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				gets++
				if gets == 1 {
					return false, nil, nil
				}
				current := job.DeepCopy()
				switch state {
				case "replaced":
					current.UID = "replacement"
				case "deleted":
					return true, nil, k8serr.NewNotFound(action.GetResource().GroupResource(), job.Name)
				case "deleting":
					current.DeletionTimestamp = new(metav1.Now())
				case "failed":
					current.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue}}
				case "running":
					current.Status = batchv1.JobStatus{Active: 1}
				case "cancelled":
					cancel()
				}
				return true, current, nil
			})
			secret, err := getInstallationResult(ctx, c, job)
			require.Error(t, err)
			assert.Nil(t, secret)
			assert.Equal(t, 2, gets)
			if state == "cancelled" {
				assert.ErrorIs(t, err, context.Canceled)
			}
		})
	}
}

func TestInstallationRetriesTransientReads(t *testing.T) {
	for _, point := range []string{"job", "token", "checkpoint", "final-job"} {
		for _, failure := range []error{
			io.EOF, io.ErrUnexpectedEOF, context.DeadlineExceeded,
			k8serr.NewServiceUnavailable("API unavailable"), k8serr.NewInternalError(errors.New("storage outage")),
			k8serr.NewTooManyRequests("throttled", 1), k8serr.NewTimeoutError("timed out", 1),
			&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
		} {
			t.Run(point+"/"+failure.Error(), func(t *testing.T) {
				job, token := completedInstallationJob(), legacyInitialToken()
				token.Annotations = map[string]string{initializationIDKey: "initialization"}
				c := fake.NewSimpleClientset(job, token, completedInitializationState())
				failed, jobGets := false, 0
				c.PrependReactor("get", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
					resource, name := action.GetResource().Resource, action.(k8stesting.GetAction).GetName()
					if resource == "jobs" {
						jobGets++
					}
					match := point == "job" && resource == "jobs" || point == "final-job" && resource == "jobs" && jobGets == 2 ||
						point == "token" && name == "init-token" || point == "checkpoint" && name == initializationSecretName
					if !failed && match {
						failed = true
						return true, nil, failure
					}
					return false, nil, nil
				})
				secret, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, time.Second)
				require.NoError(t, err)
				require.True(t, failed)
				assert.Equal(t, token, secret)
				assert.GreaterOrEqual(t, jobGets, 3)
			})
		}
	}
}

func TestInstallationPermanentReadErrors(t *testing.T) {
	for _, point := range []string{"jobs", "init-token", initializationSecretName} {
		for _, failure := range []error{
			k8serr.NewForbidden(schema.GroupResource{Resource: "secrets"}, "init-token", errors.New("permission denied")),
			k8serr.NewUnauthorized("credentials expired"), errors.New("invalid API response"),
		} {
			t.Run(point+"/"+failure.Error(), func(t *testing.T) {
				job := completedInstallationJob()
				c := fake.NewSimpleClientset(job, legacyInitialToken())
				failures := 0
				c.PrependReactor("get", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if action.GetResource().Resource == point || action.(k8stesting.GetAction).GetName() == point {
						failures++
						return true, nil, failure
					}
					return false, nil, nil
				})
				secret, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, time.Second)
				require.ErrorIs(t, err, failure)
				assert.Nil(t, secret)
				assert.Equal(t, 1, failures)
			})
		}
	}
}

func TestInstallationWaitCancellationAndTimeout(t *testing.T) {
	for _, state := range []string{"cancelled-before-read", "cancelled-during-read", "api-outage", "missing-token", "pending-job"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			c := fake.NewSimpleClientset(job)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch state {
			case "cancelled-before-read":
				cancel()
			case "cancelled-during-read":
				c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
					cancel()
					return true, nil, context.Canceled
				})
			case "api-outage":
				c.PrependReactor("get", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
					return true, nil, k8serr.NewServiceUnavailable("API outage")
				})
			case "pending-job":
				job.Status = batchv1.JobStatus{}
				require.NoError(t, c.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), job, job.Namespace))
			}
			secret, err := waitForInitialToken(ctx, c, job, time.Millisecond, 30*time.Millisecond)
			assert.Nil(t, secret)
			if state == "cancelled-before-read" || state == "cancelled-during-read" {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			if state == "cancelled-before-read" {
				assert.Empty(t, c.Actions())
			}
			if state == "api-outage" {
				assert.Contains(t, err.Error(), "API outage")
			}
			assert.Contains(t, err.Error(), string(job.UID))
		})
	}
}

func TestInstallationPodDiagnosticsAndRecovery(t *testing.T) {
	for _, state := range []string{"Unschedulable", "ImagePullBackOff", "InitContainerError", "ContainerError"} {
		t.Run(state, func(t *testing.T) {
			job := completedInstallationJob()
			job.Status = batchv1.JobStatus{Failed: 1}
			pod := initializationPod(job)
			switch state {
			case "Unschedulable":
				pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: state, Message: "Insufficient memory"}}
			case "ImagePullBackOff":
				pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "genesis", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: state, Message: "Registry unavailable"}}}}
			case "InitContainerError":
				pod.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: state, ExitCode: 2}}}}
			case "ContainerError":
				pod.Status.Phase = corev1.PodFailed
				pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "genesis", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: state, ExitCode: 1, Message: "Temporary API failure"}}}}
			}
			c := fake.NewSimpleClientset(job, pod, legacyInitialToken())
			secret, err := getInstallationResult(t.Context(), c, job)
			require.ErrorIs(t, err, errInstallationPending)
			assert.Nil(t, secret)
			assert.Contains(t, err.Error(), state)
			assert.Contains(t, err.Error(), pod.Name)
			_, err = waitForInitialToken(t.Context(), c, job, time.Millisecond, 20*time.Millisecond)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			assert.Contains(t, err.Error(), state)
			finished := completedInstallationJob()
			require.NoError(t, c.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), finished, job.Namespace))
			secret, err = waitForInitialToken(t.Context(), c, job, time.Millisecond, time.Second)
			require.NoError(t, err)
			assert.Equal(t, "token", string(secret.Data["data"]))
		})
	}
}

func TestInstallationPodDiagnosticsOwnership(t *testing.T) {
	job := completedInstallationJob()
	for _, state := range []string{"different-job", "different-name", "not-controller", "not-job", "unowned"} {
		t.Run(state, func(t *testing.T) {
			pod := initializationPod(job)
			pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "unrelated", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "UnrelatedError"}}}}
			switch state {
			case "different-job":
				pod.OwnerReferences[0].UID = "previous-job"
			case "different-name":
				pod.OwnerReferences[0].Name = "other-job"
			case "not-controller":
				pod.OwnerReferences[0].Controller = new(false)
			case "not-job":
				pod.OwnerReferences[0].Kind = "Deployment"
			case "unowned":
				pod.OwnerReferences = nil
			}
			c := fake.NewSimpleClientset(pod)
			assert.NotContains(t, installationPodStatus(t.Context(), c, job), "UnrelatedError")
		})
	}
}

func TestInstallationPodReadFailureDoesNotOverrideJobResult(t *testing.T) {
	job := completedInstallationJob()
	job.Status.Conditions[0].Type = batchv1.JobFailed
	job.Status.Conditions[0].Reason = "BackoffLimitExceeded"
	c := fake.NewSimpleClientset(job)
	c.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serr.NewServiceUnavailable("Pod API outage")
	})
	_, err := waitForInitialToken(t.Context(), c, job, time.Millisecond, time.Second)
	require.ErrorContains(t, err, "BackoffLimitExceeded")
	assert.Contains(t, err.Error(), "Pod API outage")
}

func TestInstallationErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		err   error
		retry bool
	}{
		{io.EOF, true}, {io.ErrUnexpectedEOF, true}, {context.DeadlineExceeded, true},
		{&url.Error{Op: "Get", URL: "https://kubernetes", Err: io.EOF}, true},
		{syscall.ECONNRESET, true}, {syscall.ECONNREFUSED, true},
		{&net.OpError{Op: "dial", Net: "tcp", Err: syscall.EHOSTUNREACH}, true},
		{&net.DNSError{Err: "temporary DNS failure", Name: "kubernetes"}, true},
		{k8serr.NewServerTimeout(schema.GroupResource{Resource: "jobs"}, "get", 1), true},
		{k8serr.NewForbidden(schema.GroupResource{Resource: "jobs"}, genesisJobName, errors.New("denied")), false},
		{k8serr.NewUnauthorized("expired"), false}, {k8serr.NewBadRequest("invalid"), false},
		{k8serr.NewNotFound(schema.GroupResource{Resource: "jobs"}, genesisJobName), false},
		{context.Canceled, false}, {x509.UnknownAuthorityError{}, false}, {errors.New("invalid response"), false},
	} {
		t.Run(tc.err.Error(), func(t *testing.T) {
			assert.Equal(t, tc.retry, isTransientInstallationError(errors.Wrap(tc.err, "request failed")))
		})
	}
}

func TestInstallationRequiresJobIdentityAndBoundedPolling(t *testing.T) {
	for _, tc := range []struct {
		job               *batchv1.Job
		interval, timeout time.Duration
	}{
		{nil, time.Millisecond, time.Second},
		{&batchv1.Job{}, time.Millisecond, time.Second},
		{&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: genesisJobName, Namespace: genesisNS}}, time.Millisecond, time.Second},
		{&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: genesisJobName, UID: types.UID("job")}}, time.Millisecond, time.Second},
		{completedInstallationJob(), 0, time.Second},
		{completedInstallationJob(), time.Millisecond, 0},
	} {
		c := fake.NewSimpleClientset()
		secret, err := waitForInitialToken(t.Context(), c, tc.job, tc.interval, tc.timeout)
		require.Error(t, err)
		assert.Nil(t, secret)
		assert.Empty(t, c.Actions())
	}
}

func TestInitialTokenValidationPreservesLocalState(t *testing.T) {
	t.Setenv("OCTELIUM_SKIP_MESSAGES", "true")
	require.NoError(t, cliutils.OpenDB("mem"))
	db := cliutils.GetDB()
	t.Cleanup(func() { db.Close() })
	require.NoError(t, db.SetSessionToken("example.com", &authv1.SessionToken{AccessToken: "existing-session"}))
	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte("existing-token"), 0600))
	for _, token := range []*corev1.Secret{nil, {}, {Data: map[string][]byte{"data": []byte(" \n\t")}}} {
		require.Error(t, setInitialAuthToken(&Opts{ClusterDomain: "example.com", AuthTokenSavePath: path}, token))
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "existing-token", string(data))
	}
	require.Error(t, setInitialAuthToken(&Opts{ClusterDomain: "example.com", AuthTokenSavePath: t.TempDir()}, legacyInitialToken()))
	session, err := db.GetSessionToken("example.com")
	require.NoError(t, err)
	assert.Equal(t, "existing-session", session.AccessToken)
}

func TestDoInstallFailuresPreserveCredentialsAndOutput(t *testing.T) {
	for _, state := range []string{"cancelled-before-submission", "failed-job", "empty-token", "wrong-initialization", "replaced-job", "cancelled-wait", "save-failed"} {
		t.Run(state, func(t *testing.T) {
			t.Setenv("OCTELIUM_SKIP_MESSAGES", "")
			require.NoError(t, cliutils.OpenDB("mem"))
			db := cliutils.GetDB()
			t.Cleanup(func() { db.Close() })
			require.NoError(t, db.SetSessionToken("example.com", &authv1.SessionToken{AccessToken: "existing-session"}))
			path := filepath.Join(t.TempDir(), "token")
			require.NoError(t, os.WriteFile(path, []byte("existing-token"), 0600))
			output, err := os.Create(filepath.Join(t.TempDir(), "output"))
			require.NoError(t, err)
			stdout, colorOutput := os.Stdout, color.Output
			os.Stdout, color.Output = output, output
			t.Cleanup(func() { os.Stdout, color.Output = stdout, colorOutput; output.Close() })
			c := newGenesisJobClient(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if state == "cancelled-before-submission" {
				cancel()
			}
			started := false
			c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if started && state == "cancelled-wait" {
					cancel()
					return true, nil, context.Canceled
				}
				if started && state == "replaced-job" {
					job := completedInstallationJob()
					job.UID = "replacement"
					return true, job, nil
				}
				return false, nil, nil
			})
			c.PrependReactor("update", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				started = true
				job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job)
				job.Status.Conditions = completedInstallationJob().Status.Conditions
				if state == "failed-job" {
					job.Status.Conditions[0].Type = batchv1.JobFailed
				}
				token := legacyInitialToken()
				if state == "empty-token" {
					token.Data = nil
				}
				if state == "wrong-initialization" {
					token.Annotations = map[string]string{initializationIDKey: "other-initialization"}
					require.NoError(t, c.Tracker().Add(completedInitializationState()))
				}
				require.NoError(t, c.Tracker().Add(token))
				return false, nil, nil
			})
			savePath := path
			if state == "save-failed" {
				savePath = t.TempDir()
			}
			err = DoInstall(ctx, &Opts{K8sC: c, ClusterDomain: "example.com", AuthTokenSavePath: savePath})
			require.Error(t, err)
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "existing-token", string(data))
			session, err := db.GetSessionToken("example.com")
			require.NoError(t, err)
			assert.Equal(t, "existing-session", session.AccessToken)
			_, err = output.Seek(0, io.SeekStart)
			require.NoError(t, err)
			data, err = io.ReadAll(output)
			require.NoError(t, err)
			assert.NotContains(t, string(data), "Cluster installation is now complete")
			assert.NotContains(t, string(data), "--auth-token")
			if state == "cancelled-before-submission" {
				assert.Empty(t, c.Actions())
			}
		})
	}
}
