package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

const genesisRequestHash = "octelium.com/genesis-request-hash"

func genesisJobFinished(job *batchv1.Job) bool {
	if job.Status.Active > 0 {
		return false
	}
	completions := int32(1)
	if job.Spec.Completions != nil {
		completions = *job.Spec.Completions
	}
	if job.Status.Succeeded > 0 && job.Status.Succeeded >= completions {
		return true
	}
	for _, condition := range job.Status.Conditions {
		if (condition.Type == batchv1.JobComplete || condition.Type == batchv1.JobFailed) && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func checkGenesisJobs(ctx context.Context, c kubernetes.Interface, own *batchv1.Job) error {
	for _, namespace := range []string{"default", octeliumNS} {
		jobs, err := c.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{LabelSelector: "octelium.com/component=genesis"})
		if err != nil {
			return err
		}
		for _, job := range jobs.Items {
			if own != nil && job.Namespace == own.Namespace && job.Name == own.Name && (own.UID == "" || job.UID == own.UID) {
				continue
			}
			if !genesisJobFinished(&job) {
				return errors.Errorf("Genesis Job %s/%s is still active. Wait for it to finish before starting another operation", job.Namespace, job.Name)
			}
		}
		pods, err := c.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "octelium.com/component=genesis"})
		if err != nil {
			return err
		}
		for _, pod := range pods.Items {
			if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
				continue
			}
			owner := metav1.GetControllerOf(&pod)
			if own != nil && pod.Namespace == own.Namespace && owner != nil && owner.Kind == "Job" && owner.Name == own.Name && (own.UID == "" || owner.UID == own.UID) {
				continue
			}
			return errors.Errorf("Genesis Pod %s/%s may still be running. Refusing to start another operation", pod.Namespace, pod.Name)
		}
	}
	return nil
}

func SubmitGenesisJob(ctx context.Context, c kubernetes.Interface, desired *batchv1.Job, prepare func(context.Context) error) error {
	_, err := submitGenesisJob(ctx, c, desired, prepare)
	return err
}

func submitGenesisJob(ctx context.Context, c kubernetes.Interface, desired *batchv1.Job, prepare func(context.Context) error) (_ *batchv1.Job, retErr error) {
	data, err := json.Marshal(desired.Spec)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	jobs := c.BatchV1().Jobs(desired.Namespace)
	if prepare == nil {
		if err := checkGenesisJobs(ctx, c, nil); err != nil {
			return nil, err
		}
		job := desired.DeepCopy()
		if job.Annotations == nil {
			job.Annotations = make(map[string]string)
		}
		job.Annotations[genesisRequestHash] = hash
		created, err := jobs.Create(ctx, job, metav1.CreateOptions{})
		if err != nil && !k8serr.IsAlreadyExists(err) {
			current, getErr := jobs.Get(ctx, job.Name, metav1.GetOptions{})
			if getErr == nil && current.DeletionTimestamp == nil && current.Annotations[genesisRequestHash] == hash && (current.Spec.Suspend == nil || !*current.Spec.Suspend) {
				return current, nil
			}
		}
		return created, err
	}
	job, err := jobs.Get(ctx, desired.Name, metav1.GetOptions{})
	createdHere := false
	defer func() {
		if retErr == nil || job == nil || !createdHere {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		current, err := jobs.Get(ctx, desired.Name, metav1.GetOptions{})
		if err == nil && current.UID == job.UID && current.Annotations[genesisRequestHash] == hash && current.Spec.Suspend != nil && *current.Spec.Suspend {
			jobs.Delete(ctx, current.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &current.UID, ResourceVersion: &current.ResourceVersion}})
		}
	}()
	if err == nil && genesisJobFinished(job) {
		if err := checkGenesisJobs(ctx, c, nil); err != nil {
			return nil, err
		}
		uid := job.UID
		err = jobs.Delete(ctx, job.Name, metav1.DeleteOptions{
			Preconditions:     &metav1.Preconditions{UID: &job.UID, ResourceVersion: &job.ResourceVersion},
			PropagationPolicy: new(metav1.DeletePropagationForeground),
		})
		if err != nil && !k8serr.IsNotFound(err) {
			return nil, err
		}
		if err := wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
			current, err := jobs.Get(ctx, desired.Name, metav1.GetOptions{})
			if k8serr.IsNotFound(err) {
				return true, nil
			}
			if err != nil {
				return false, err
			}
			if current.UID != uid {
				return false, errors.Errorf("Another genesis Job replaced the completed operation. Retry the command")
			}
			return false, nil
		}); err != nil {
			return nil, err
		}
		job, err = nil, k8serr.NewNotFound(batchv1.Resource("jobs"), desired.Name)
	}
	if k8serr.IsNotFound(err) {
		if err := checkGenesisJobs(ctx, c, desired); err != nil {
			return nil, err
		}
		job = desired.DeepCopy()
		job.Spec.Suspend = new(true)
		if job.Annotations == nil {
			job.Annotations = make(map[string]string)
		}
		job.Annotations[genesisRequestHash] = hash
		job, err = jobs.Create(ctx, job, metav1.CreateOptions{})
		createdHere = err == nil
		if err != nil {
			created, getErr := jobs.Get(ctx, desired.Name, metav1.GetOptions{})
			if getErr != nil {
				return nil, err
			}
			job, err = created, nil
		}
	}
	if err != nil {
		return nil, err
	}
	if job.Annotations[genesisRequestHash] != hash {
		return nil, errors.Errorf("Genesis Job %s/%s belongs to a different request. Wait for it to finish before retrying", job.Namespace, job.Name)
	}
	if job.Spec.Suspend == nil || !*job.Spec.Suspend {
		if prepare != nil {
			if err := prepare(ctx); err != nil {
				return nil, err
			}
		}
		return job, nil
	}
	if err := checkGenesisJobs(ctx, c, job); err != nil {
		return nil, err
	}
	if prepare != nil {
		if err := prepare(ctx); err != nil {
			return nil, err
		}
	}
	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, err := jobs.Get(ctx, job.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if current.UID != job.UID || current.Annotations[genesisRequestHash] != hash {
			return errors.Errorf("The genesis Job was replaced before it could start")
		}
		if current.Spec.Suspend == nil || !*current.Spec.Suspend {
			job = current
			return nil
		}
		if err := checkGenesisJobs(ctx, c, current); err != nil {
			return err
		}
		current.Spec.Suspend = new(false)
		started, err := jobs.Update(ctx, current, metav1.UpdateOptions{})
		if err != nil {
			started, getErr := jobs.Get(ctx, job.Name, metav1.GetOptions{})
			if getErr == nil && started.UID == job.UID && started.Annotations[genesisRequestHash] == hash &&
				(started.Spec.Suspend == nil || !*started.Spec.Suspend) {
				job = started
				return nil
			}
		}
		if err == nil {
			job = started
		}
		return err
	})
	return job, err
}
