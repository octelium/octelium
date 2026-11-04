package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/octelium/octelium/client/octops/internal/k8sretry"
	"github.com/pkg/errors"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
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
		jobs, err := k8sretry.Read(ctx, func(ctx context.Context) (*batchv1.JobList, error) {
			return c.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{LabelSelector: "octelium.com/component=genesis"})
		})
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
		pods, err := k8sretry.Read(ctx, func(ctx context.Context) (*corev1.PodList, error) {
			return c.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: "octelium.com/component=genesis"})
		})
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
	_, err := SubmitGenesisJobWithResult(ctx, c, desired, prepare)
	return err
}

func SubmitGenesisJobWithResult(ctx context.Context, c kubernetes.Interface, desired *batchv1.Job, prepare func(context.Context) error) (*batchv1.Job, error) {
	return submitGenesisJob(ctx, c, desired, prepare)
}

func submitGenesisJob(ctx context.Context, c kubernetes.Interface, desired *batchv1.Job, prepare func(context.Context) error) (_ *batchv1.Job, retErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
		if job.Name == "" {
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return jobs.Create(ctx, job, metav1.CreateOptions{})
		}
		created, err := k8sretry.Create(ctx, job,
			func(ctx context.Context) (*batchv1.Job, error) {
				return jobs.Create(ctx, job, metav1.CreateOptions{})
			},
			func(ctx context.Context) (*batchv1.Job, error) {
				return readGenesisJob(ctx, c, job)
			})
		if err != nil {
			return nil, err
		}
		if created.DeletionTimestamp != nil || created.Annotations[genesisRequestHash] != hash || (created.Spec.Suspend != nil && *created.Spec.Suspend) {
			return nil, errors.Errorf("The genesis Job does not match the submitted operation")
		}
		return created, nil
	}
	job, err := getK8sJob(ctx, c, desired.Namespace, desired.Name)
	createdHere := false
	defer func() {
		if retErr == nil || job == nil || !createdHere {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		current, err := getK8sJob(ctx, c, desired.Namespace, desired.Name)
		if err == nil && current.UID == job.UID && current.Annotations[genesisRequestHash] == hash && current.Spec.Suspend != nil && *current.Spec.Suspend {
			deleteGenesisJob(ctx, c, current, nil)
		}
	}()
	if err == nil && genesisJobFinished(job) {
		if err := checkGenesisJobs(ctx, c, nil); err != nil {
			return nil, err
		}
		uid := job.UID
		if err := deleteGenesisJob(ctx, c, job, new(metav1.DeletePropagationForeground)); err != nil {
			return nil, err
		}
		if err := k8sretry.Wait(ctx, 100*time.Millisecond, 15*time.Second, func(ctx context.Context) (bool, error) {
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
		reservation := desired.DeepCopy()
		reservation.Spec.Suspend = new(true)
		if reservation.Annotations == nil {
			reservation.Annotations = make(map[string]string)
		}
		reservation.Annotations[genesisRequestHash] = hash
		job, err = k8sretry.Create(ctx, reservation,
			func(ctx context.Context) (*batchv1.Job, error) {
				created, err := jobs.Create(ctx, reservation, metav1.CreateOptions{})
				if err == nil {
					createdHere = true
				}
				return created, err
			},
			func(ctx context.Context) (*batchv1.Job, error) {
				return jobs.Get(ctx, desired.Name, metav1.GetOptions{})
			})
	}
	if err != nil {
		return nil, err
	}
	if job.DeletionTimestamp != nil || job.Annotations[genesisRequestHash] != hash {
		return nil, errors.Errorf("Genesis Job %s/%s belongs to a different request or is being deleted. Wait for it to finish before retrying", job.Namespace, job.Name)
	}
	if job.Spec.Suspend == nil || !*job.Spec.Suspend {
		if err := prepare(ctx); err != nil {
			return nil, err
		}
		return job, nil
	}
	if err := checkGenesisJobs(ctx, c, job); err != nil {
		return nil, err
	}
	if err := prepare(ctx); err != nil {
		return nil, err
	}
	err = k8sretry.Do(ctx, func(ctx context.Context) error {
		current, err := jobs.Get(ctx, job.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if current.UID != job.UID || current.DeletionTimestamp != nil || current.Annotations[genesisRequestHash] != hash {
			return errors.Errorf("The genesis Job was replaced before it could start")
		}
		if current.Spec.Suspend == nil || !*current.Spec.Suspend {
			job = current
			return nil
		}
		if err := checkGenesisJobs(ctx, c, current); err != nil {
			return err
		}
		current = current.DeepCopy()
		current.Spec.Suspend = new(false)
		if err := ctx.Err(); err != nil {
			return err
		}
		started, err := jobs.Update(ctx, current, metav1.UpdateOptions{})
		if err == nil {
			job = started
		}
		return err
	})
	return job, err
}

func deleteGenesisJob(ctx context.Context, c kubernetes.Interface, job *batchv1.Job, propagation *metav1.DeletionPropagation) error {
	jobs := c.BatchV1().Jobs(job.Namespace)
	return k8sretry.Delete(ctx, job,
		func(ctx context.Context) (*batchv1.Job, error) {
			return jobs.Get(ctx, job.Name, metav1.GetOptions{})
		},
		func(ctx context.Context, options metav1.DeleteOptions) error {
			options.PropagationPolicy = propagation
			return jobs.Delete(ctx, job.Name, options)
		})
}
