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

package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octops/internal/k8sretry"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/types"
	"github.com/pkg/errors"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const genesisNS = "default"

const genesisJobName = "octelium-genesis"

func getGenesisRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "octelium-genesis",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"*", "*.*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
		},
	}
}

func getGenesisServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "octelium-genesis",
			Namespace: genesisNS,
		},
	}
}

func getGenesisRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "octelium-genesis",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "octelium-genesis",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "octelium-genesis",
				Namespace: genesisNS,
			},
		},
	}
}

func getGenesisJob(o *Opts, spiffe *SPIFFEOpts) *batchv1.Job {
	labels := map[string]string{
		"app":                         "octelium",
		"octelium.com/component":      "genesis",
		"octelium.com/component-type": "cluster",
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "octelium-genesis",
			Namespace: genesisNS,
			Labels:    labels,
		},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: GetGenesisPodSpec(&GenesisPodSpecOpts{
					Domain:     o.ClusterDomain,
					Cmd:        "init",
					Version:    o.Version,
					SvcAccount: "octelium-genesis",
					SPIFFE:     spiffe,
				}),
			},
		},
	}
}

type GenesisPodSpecOpts struct {
	Domain     string
	Cmd        string
	Version    string
	SvcAccount string
	Package    string
	Region     string
	SPIFFE     *SPIFFEOpts
}

func GetGenesisPodSpec(o *GenesisPodSpecOpts) corev1.PodSpec {
	pkg := o.Package
	if pkg == "" {
		pkg = "octelium"
	}
	rgn := o.Region
	if rgn == "" {
		rgn = "default"
	}

	return corev1.PodSpec{
		ServiceAccountName: o.SvcAccount,
		RestartPolicy:      corev1.RestartPolicyNever,
		Volumes: func() []corev1.Volume {
			var ret []corev1.Volume
			if o.SPIFFE != nil {
				ret = append(ret, corev1.Volume{
					Name: "spiffe-agent",
					VolumeSource: corev1.VolumeSource{
						CSI: &corev1.CSIVolumeSource{
							Driver:   o.SPIFFE.getCSIDriver(),
							ReadOnly: utils_types.BoolToPtr(true),
						},
					},
				})
			}

			return ret
		}(),

		Containers: []corev1.Container{
			{
				Name: fmt.Sprintf("%s-genesis", pkg),
				Image: func() string {
					if o.Version != "" {
						return cliutils.GetGenesisImageWithPackage(pkg, o.Version)
					}
					if ldflags.IsDev() {
						return cliutils.GetGenesisImageWithPackage(pkg, "")
					} else {
						return cliutils.GetGenesisImageWithPackage(pkg, "latest")
					}
				}(),
				ImagePullPolicy: corev1.PullAlways,
				Args:            []string{o.Cmd},
				VolumeMounts: func() []corev1.VolumeMount {
					var ret []corev1.VolumeMount
					if o.SPIFFE != nil {
						ret = append(ret, corev1.VolumeMount{
							Name:      "spiffe-agent",
							MountPath: "/run/spire/sockets",
							ReadOnly:  true,
						})
					}
					return ret
				}(),
				Env: func() []corev1.EnvVar {
					ret := []corev1.EnvVar{
						{
							Name:  "OCTELIUM_DOMAIN",
							Value: o.Domain,
						},
						{
							Name:  "OCTELIUM_REGION_NAME",
							Value: rgn,
						},
						{
							Name: "OCTELIUM_GENESIS_POD_NAME",
							ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{
								FieldPath: "metadata.name",
							}},
						},
						{
							Name: "OCTELIUM_GENESIS_POD_NAMESPACE",
							ValueFrom: &corev1.EnvVarSource{FieldRef: &corev1.ObjectFieldSelector{
								FieldPath: "metadata.namespace",
							}},
						},
					}

					if o.SPIFFE != nil {
						ret = append(ret, corev1.EnvVar{
							Name:  "OCTELIUM_ENABLE_SPIFFE_CSI",
							Value: "true",
						})

						if val := o.SPIFFE.CSIDriver; val != "" {
							ret = append(ret, corev1.EnvVar{
								Name:  "OCTELIUM_SPIFFE_CSI_DRIVER",
								Value: val,
							})
						}

						if val := o.SPIFFE.TrustDomain; val != "" {
							ret = append(ret, corev1.EnvVar{
								Name:  "OCTELIUM_SPIFFE_TRUST_DOMAIN",
								Value: val,
							})
						}
					}

					return ret
				}(),
			},
		},
	}
}

func createGenesis(ctx context.Context, o *Opts) (*batchv1.Job, error) {
	c := o.K8sC
	data := map[string][]byte{
		"bootstrap": pbutils.MarshalMust(o.Bootstrap),
		"region":    pbutils.MarshalMust(o.Region),
		"domain":    []byte(o.ClusterDomain),
	}
	source, err := getBootstrapInput(ctx, c, data)
	if err != nil {
		return nil, err
	}
	hash, err := initializationInputHash(data)
	if err != nil {
		return nil, err
	}
	job := getGenesisJob(o, spiffeFromBootstrap(o.Bootstrap))
	job, err = bindInitializationInput(ctx, c, job, hash, source.Data[initializationInputKey])
	if err != nil {
		return nil, err
	}
	prepared := false
	prepare := func(ctx context.Context) error {
		prepared = true
		if err := setClusterResources(ctx, o); err != nil {
			return err
		}
		for _, create := range []func(context.Context) error{
			func(ctx context.Context) error {
				_, err := c.CoreV1().ServiceAccounts(genesisNS).Create(ctx, getGenesisServiceAccount(), metav1.CreateOptions{})
				return err
			},
			func(ctx context.Context) error {
				_, err := c.RbacV1().ClusterRoles().Create(ctx, getGenesisRole(), metav1.CreateOptions{})
				return err
			},
			func(ctx context.Context) error {
				_, err := c.RbacV1().ClusterRoleBindings().Create(ctx, getGenesisRoleBinding(), metav1.CreateOptions{})
				return err
			},
		} {
			if err := k8sretry.Do(ctx, func(ctx context.Context) error {
				err := create(ctx)
				if k8serr.IsAlreadyExists(err) {
					return nil
				}
				return err
			}); err != nil {
				return err
			}
		}
		return nil
	}
	accepted, err := submitGenesisJob(ctx, c, job, prepare)
	if err != nil && !prepared && job.Spec.Template.Annotations[initializationInputHashKey] != "" &&
		(k8serr.IsForbidden(err) || k8serr.IsInvalid(err)) {
		currentHash, hashErr := initializationInputHash(source.Data)
		if hashErr == nil && currentHash == hash {
			job.Spec.Template.Annotations = nil
			return submitGenesisJob(ctx, c, job, prepare)
		}
	}
	return accepted, err
}

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
