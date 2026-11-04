package install

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octops/internal/k8sretry"
	"github.com/pkg/errors"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const initializationSecretName = "octelium-genesis-init"
const initializationIDKey = "octelium.com/genesis-init-id"
const initializationCompleteKey = "octelium.com/genesis-init-complete"

var errGenesisPending = errors.New("The genesis Job has not finished")

func waitForInstallation(ctx context.Context, c kubernetes.Interface, job *batchv1.Job) (*corev1.Secret, error) {
	s := cliutils.NewSpinner(os.Stdout)
	s.SetSuffix("Waiting for Cluster installation to finish")
	s.Start()
	defer s.Stop()
	return waitForInitialToken(ctx, c, job, 2*time.Second, 8000*time.Second)
}

func waitForInitialToken(ctx context.Context, c kubernetes.Interface, job *batchv1.Job, interval, timeout time.Duration) (*corev1.Secret, error) {
	var secret *corev1.Secret
	err := waitForGenesisResult(ctx, job, interval, timeout, func(ctx context.Context) error {
		var err error
		secret, err = getInstallationResult(ctx, c, job)
		return err
	})
	if err != nil {
		return nil, err
	}
	return secret, nil
}

func WaitGenesisJob(ctx context.Context, c kubernetes.Interface, job *batchv1.Job, interval, timeout time.Duration) error {
	return waitForGenesisResult(ctx, job, interval, timeout, func(ctx context.Context) error {
		current, err := readGenesisJob(ctx, c, job)
		if err != nil {
			return err
		}
		complete, err := genesisJobComplete(current, job)
		if err != nil {
			return errors.Wrapf(err, "%s", genesisPodStatus(ctx, c, job))
		}
		if !complete {
			return errors.Wrapf(errGenesisPending, "%s", genesisPodStatus(ctx, c, job))
		}
		return ctx.Err()
	})
}

func readGenesisJob(ctx context.Context, c kubernetes.Interface, job *batchv1.Job) (*batchv1.Job, error) {
	jobs := c.BatchV1().Jobs(job.Namespace)
	current, err := jobs.Get(ctx, job.Name, metav1.GetOptions{})
	if !k8serr.IsForbidden(err) {
		return current, err
	}
	list, err := jobs.List(ctx, metav1.ListOptions{FieldSelector: "metadata.name=" + job.Name})
	if err != nil {
		return nil, err
	}
	for i := range list.Items {
		if list.Items[i].Name == job.Name && list.Items[i].Namespace == job.Namespace {
			return &list.Items[i], nil
		}
	}
	return nil, k8serr.NewNotFound(batchv1.Resource("jobs"), job.Name)
}

func waitForGenesisResult(ctx context.Context, job *batchv1.Job, interval, timeout time.Duration, check func(context.Context) error) error {
	if job == nil || job.UID == "" || job.Name == "" || job.Namespace == "" {
		return errors.Errorf("The submitted genesis Job identity is missing")
	}
	if interval <= 0 || timeout <= 0 {
		return errors.Errorf("The genesis polling interval and timeout must be positive")
	}
	var lastErr error
	err := k8sretry.Wait(ctx, interval, timeout, func(ctx context.Context) (bool, error) {
		lastErr = check(ctx)
		if errors.Is(lastErr, errGenesisPending) {
			return false, nil
		}
		return lastErr == nil, lastErr
	})
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if lastErr != nil && !errors.Is(err, lastErr) {
			err = errors.Wrapf(err, "%s", lastErr)
		}
		return errors.Wrapf(err, "Could not finish genesis Job %s/%s (%s)", job.Namespace, job.Name, job.UID)
	}
	return nil
}

func isTransientGenesisError(err error) bool {
	return k8sretry.IsTransient(err)
}

func getInstallationResult(ctx context.Context, c kubernetes.Interface, expected *batchv1.Job) (*corev1.Secret, error) {
	job, err := c.BatchV1().Jobs(expected.Namespace).Get(ctx, expected.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	complete, err := genesisJobComplete(job, expected)
	if err != nil {
		return nil, errors.Wrapf(err, "%s", genesisPodStatus(ctx, c, expected))
	}
	if !complete {
		return nil, errors.Wrapf(errGenesisPending, "%s", genesisPodStatus(ctx, c, expected))
	}
	secret, err := c.CoreV1().Secrets(octeliumNS).Get(ctx, "init-token", metav1.GetOptions{})
	if k8serr.IsNotFound(err) {
		return nil, errors.Wrap(errGenesisPending, "The completed Job's initial authentication token is not available")
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(secret.Data["data"])) == "" {
		return nil, errors.Errorf("The completed Job's initial authentication token is empty")
	}
	state, err := c.CoreV1().Secrets(octeliumNS).Get(ctx, initializationSecretName, metav1.GetOptions{})
	if k8serr.IsNotFound(err) {
		if secret.Annotations[initializationIDKey] != "" {
			return nil, errors.Errorf("The initial authentication token's initialization state is missing")
		}
	} else if err != nil {
		return nil, err
	} else if id := string(state.Data["id"]); id == "" || secret.Annotations[initializationIDKey] != id || state.Annotations[initializationCompleteKey] != "true" {
		return nil, errors.Errorf("The initial authentication token does not belong to a completed initialization")
	}
	job, err = c.BatchV1().Jobs(expected.Namespace).Get(ctx, expected.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	complete, err = genesisJobComplete(job, expected)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !complete {
		return nil, errGenesisPending
	}
	return secret, nil
}

func genesisJobComplete(job, expected *batchv1.Job) (bool, error) {
	if job.UID != expected.UID {
		return false, errors.Errorf("The submitted genesis Job was replaced")
	}
	if job.DeletionTimestamp != nil {
		return false, errors.Errorf("The submitted genesis Job is being deleted")
	}
	complete := false
	for _, condition := range job.Status.Conditions {
		if condition.Status != corev1.ConditionTrue {
			continue
		}
		switch condition.Type {
		case batchv1.JobFailed:
			return false, errors.Errorf("The genesis Job failed: %s: %s", condition.Reason, condition.Message)
		case batchv1.JobComplete:
			complete = true
		}
	}
	return complete && job.Status.Active == 0 && (job.Status.Terminating == nil || *job.Status.Terminating == 0), nil
}

func genesisPodStatus(ctx context.Context, c kubernetes.Interface, job *batchv1.Job) string {
	pods, err := c.CoreV1().Pods(job.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "job-name=" + job.Name})
	if err != nil {
		return fmt.Sprintf("Could not inspect genesis Pods: %v", err)
	}
	var states []string
	for _, pod := range pods.Items {
		owner := metav1.GetControllerOf(&pod)
		if owner == nil || owner.Kind != "Job" || owner.Name != job.Name || owner.UID != job.UID {
			continue
		}
		states = append(states, fmt.Sprintf("Pod %s: %s", pod.Name, pod.Status.Phase))
		for _, condition := range pod.Status.Conditions {
			if condition.Type == corev1.PodScheduled && condition.Status == corev1.ConditionFalse {
				states = append(states, condition.Reason+": "+condition.Message)
			}
		}
		for _, containers := range [][]corev1.ContainerStatus{pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses} {
			for _, container := range containers {
				if state := container.State.Waiting; state != nil {
					states = append(states, container.Name+": "+state.Reason+": "+state.Message)
				}
				if state := container.State.Terminated; state != nil {
					states = append(states, fmt.Sprintf("%s: %s (exit %d): %s", container.Name, state.Reason, state.ExitCode, state.Message))
				}
			}
		}
	}
	if len(states) == 0 {
		return "Waiting for the genesis Job to complete"
	}
	return strings.Join(states, "; ")
}
