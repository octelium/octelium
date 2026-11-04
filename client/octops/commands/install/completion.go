package install

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/pkg/errors"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

const initializationSecretName = "octelium-genesis-init"
const initializationIDKey = "octelium.com/genesis-init-id"
const initializationCompleteKey = "octelium.com/genesis-init-complete"

var errInstallationPending = errors.New("The Cluster installation has not finished")

func waitForInstallation(ctx context.Context, c kubernetes.Interface, job *batchv1.Job) (*corev1.Secret, error) {
	s := cliutils.NewSpinner(os.Stdout)
	s.SetSuffix("Waiting for Cluster installation to finish")
	s.Start()
	defer s.Stop()
	return waitForInitialToken(ctx, c, job, 2*time.Second, 8000*time.Second)
}

func waitForInitialToken(ctx context.Context, c kubernetes.Interface, job *batchv1.Job, interval, timeout time.Duration) (*corev1.Secret, error) {
	if job == nil || job.UID == "" || job.Name == "" || job.Namespace == "" {
		return nil, errors.Errorf("The submitted genesis Job identity is missing")
	}
	if interval <= 0 || timeout <= 0 {
		return nil, errors.Errorf("The installation polling interval and timeout must be positive")
	}
	var secret *corev1.Secret
	var lastErr error
	err := wait.PollUntilContextTimeout(ctx, interval, timeout, true, func(ctx context.Context) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		secret, lastErr = getInstallationResult(requestCtx, c, job)
		if lastErr == nil {
			return true, nil
		}
		if errors.Is(lastErr, errInstallationPending) || isTransientInstallationError(lastErr) {
			return false, nil
		}
		return false, lastErr
	})
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if lastErr != nil && !errors.Is(err, lastErr) {
			err = errors.Wrapf(err, "%s", lastErr)
		}
		return nil, errors.Wrapf(err, "Could not finish installation with genesis Job %s/%s (%s)", job.Namespace, job.Name, job.UID)
	}
	return secret, nil
}

func isTransientInstallationError(err error) bool {
	var networkError *net.OpError
	var dnsError *net.DNSError
	var timeoutError net.Error
	return k8serr.IsTimeout(err) || k8serr.IsServerTimeout(err) || k8serr.IsTooManyRequests(err) ||
		k8serr.IsServiceUnavailable(err) || k8serr.IsInternalError(err) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		utilnet.IsConnectionReset(err) || utilnet.IsConnectionRefused(err) || utilnet.IsHTTP2ConnectionLost(err) ||
		errors.As(err, &networkError) || errors.As(err, &dnsError) ||
		(errors.As(err, &timeoutError) && (timeoutError.Timeout() || timeoutError.Temporary()))
}

func getInstallationResult(ctx context.Context, c kubernetes.Interface, expected *batchv1.Job) (*corev1.Secret, error) {
	job, err := c.BatchV1().Jobs(expected.Namespace).Get(ctx, expected.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	complete, err := installationJobComplete(job, expected)
	if err != nil {
		return nil, errors.Wrapf(err, "%s", installationPodStatus(ctx, c, expected))
	}
	if !complete {
		return nil, errors.Wrapf(errInstallationPending, "%s", installationPodStatus(ctx, c, expected))
	}
	secret, err := c.CoreV1().Secrets(octeliumNS).Get(ctx, "init-token", metav1.GetOptions{})
	if k8serr.IsNotFound(err) {
		return nil, errors.Wrap(errInstallationPending, "The completed Job's initial authentication token is not available")
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
	complete, err = installationJobComplete(job, expected)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !complete {
		return nil, errInstallationPending
	}
	return secret, nil
}

func installationJobComplete(job, expected *batchv1.Job) (bool, error) {
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

func installationPodStatus(ctx context.Context, c kubernetes.Interface, job *batchv1.Job) string {
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
