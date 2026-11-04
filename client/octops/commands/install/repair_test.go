package install

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	rmetav1 "github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestRepairBootstrapAfterFailedJob(t *testing.T) {
	c, opts, _ := newRepairBootstrap(t)
	_, err := createGenesis(t.Context(), opts)
	require.NoError(t, err)
	secret, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.NoError(t, err)
	actual := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.Unmarshal(secret.Data["bootstrap"], actual))
	assert.Equal(t, "corrected.example", actual.Spec.PrimaryStorage.GetPostgresql().Host)
}

func newRepairBootstrap(t *testing.T) (*fake.Clientset, *Opts, *k8scorev1.Secret) {
	t.Helper()
	c := newGenesisJobClient(t)
	bootstrap := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: wrong.example, password: original}}, secondaryStorage: {redis: {host: localhost}}}"), bootstrap))
	opts := &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: bootstrap, Version: "1.2.3"}
	_, err := createGenesis(t.Context(), opts)
	require.NoError(t, err)
	source, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.NoError(t, err)
	source.UID, source.ResourceVersion = "input-uid", "1"
	source.Labels, source.Annotations = map[string]string{"customer": "preserved"}, map[string]string{"customer": "preserved"}
	source.Data["custom"] = []byte("preserved")
	_, err = c.CoreV1().Secrets("default").Update(t.Context(), source, metav1.UpdateOptions{})
	require.NoError(t, err)
	job, err := c.BatchV1().Jobs("default").Get(t.Context(), genesisJobName, metav1.GetOptions{})
	require.NoError(t, err)
	job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: "True"}}
	_, err = c.BatchV1().Jobs(job.Namespace).Update(t.Context(), job, metav1.UpdateOptions{})
	require.NoError(t, err)
	bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "corrected.example"
	c.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updated := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Secret).DeepCopy()
		object, err := c.Tracker().Get(action.GetResource(), action.GetNamespace(), updated.Name)
		if err != nil {
			return true, nil, err
		}
		current := object.(*k8scorev1.Secret)
		if updated.UID != current.UID || updated.ResourceVersion != current.ResourceVersion {
			return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), updated.Name, fmt.Errorf("Secret changed"))
		}
		version, err := strconv.Atoi(current.ResourceVersion)
		require.NoError(t, err)
		updated.ResourceVersion = strconv.Itoa(version + 1)
		err = c.Tracker().Update(action.GetResource(), updated, action.GetNamespace())
		return true, updated, err
	})
	return c, opts, source.DeepCopy()
}

func TestRepairBootstrapRefusesStorageAndInstalledState(t *testing.T) {
	for _, state := range []string{"octelium-postgres", "octelium-redis", "octelium-init", "init-token", "configuration", "complete", "unknown-checkpoint", "invalid-hash"} {
		t.Run(state, func(t *testing.T) {
			c, opts, original := newRepairBootstrap(t)
			switch state {
			case "configuration":
				require.NoError(t, c.Tracker().Add(&k8scorev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: installationConfigMapName, Namespace: octeliumNS}}))
			case "complete", "unknown-checkpoint", "invalid-hash":
				hash, err := initializationInputHash(original.Data)
				require.NoError(t, err)
				checkpoint := &k8scorev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "octelium-genesis-init", Namespace: octeliumNS}, Data: map[string][]byte{"version": []byte("1"), "id": []byte("previous-initialization"), "input-hash": []byte(hash)}}
				if state == "complete" {
					checkpoint.Annotations = map[string]string{"octelium.com/genesis-init-complete": "true"}
				} else if state == "unknown-checkpoint" {
					checkpoint.Data["version"] = []byte("99")
				} else {
					checkpoint.Data["input-hash"] = []byte("invalid")
				}
				require.NoError(t, c.Tracker().Add(checkpoint))
			default:
				require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: state, Namespace: octeliumNS}, Data: map[string][]byte{"key": []byte("preserved")}}))
			}
			_, err := createGenesis(t.Context(), opts)
			require.ErrorContains(t, err, "bootstrap differs")
			current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, original, current)
		})
	}
}

func TestRepairBootstrapRepeatedCorrections(t *testing.T) {
	c, opts, original := newRepairBootstrap(t)
	hash, err := initializationInputHash(original.Data)
	require.NoError(t, err)
	checkpoint := &k8scorev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "octelium-genesis-init", Namespace: octeliumNS}, Data: map[string][]byte{"version": []byte("1"), "id": []byte("previous-initialization"), "input-hash": []byte(hash)}}
	require.NoError(t, c.Tracker().Add(checkpoint))
	for _, host := range []string{"corrected.example", "corrected-again.example", "final.example"} {
		opts.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = host
		job, err := createGenesis(t.Context(), opts)
		require.NoError(t, err)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: "True"}}
		_, err = c.BatchV1().Jobs(genesisNS).Update(t.Context(), job, metav1.UpdateOptions{})
		require.NoError(t, err)
		current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, metav1.GetOptions{})
		require.NoError(t, err)
		bootstrap := &cbootstrapv1.Config{}
		require.NoError(t, pbutils.Unmarshal(current.Data["bootstrap"], bootstrap))
		assert.Equal(t, host, bootstrap.Spec.PrimaryStorage.GetPostgresql().Host)
		assert.Equal(t, original.UID, current.UID)
		assert.Equal(t, original.Labels, current.Labels)
		assert.Equal(t, original.Annotations, current.Annotations)
		assert.Equal(t, original.Data["custom"], current.Data["custom"])
		retained, err := c.CoreV1().Secrets(octeliumNS).Get(t.Context(), checkpoint.Name, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, checkpoint, retained)
	}
}

func TestRepairBootstrapRetriesAndConcurrentChanges(t *testing.T) {
	for _, point := range []string{"before", "after", "conflict", "changed-input", "replaced", "forbidden", "cancelled"} {
		t.Run(point, func(t *testing.T) {
			c, opts, original := newRepairBootstrap(t)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			writes := 0
			c.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				writes++
				if writes > 1 {
					return false, nil, nil
				}
				updated := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Secret).DeepCopy()
				assert.Equal(t, original.UID, updated.UID)
				assert.Equal(t, original.ResourceVersion, updated.ResourceVersion)
				switch point {
				case "after":
					updated.ResourceVersion = "2"
					require.NoError(t, c.Tracker().Update(action.GetResource(), updated, action.GetNamespace()))
				case "conflict", "changed-input", "replaced":
					changed := original.DeepCopy()
					changed.Annotations["concurrent"] = "preserved"
					changed.ResourceVersion = "2"
					if point == "changed-input" {
						bootstrap := proto.Clone(opts.Bootstrap).(*cbootstrapv1.Config)
						bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "another-client.example"
						changed.Data["bootstrap"] = pbutils.MarshalMust(bootstrap)
					}
					if point == "replaced" {
						changed.UID = "replacement-uid"
					}
					require.NoError(t, c.Tracker().Update(action.GetResource(), changed, action.GetNamespace()))
					return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), updated.Name, io.EOF)
				case "forbidden":
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), updated.Name, io.EOF)
				case "cancelled":
					cancel()
					return true, nil, context.Canceled
				}
				return true, nil, io.ErrUnexpectedEOF
			})
			_, err := createGenesis(ctx, opts)
			if point == "before" || point == "after" || point == "conflict" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, metav1.GetOptions{})
			require.NoError(t, err)
			if point == "after" {
				assert.Equal(t, 1, writes)
			} else if point == "before" || point == "conflict" {
				assert.Equal(t, 2, writes)
			} else {
				assert.Equal(t, 1, writes)
			}
			if point == "conflict" {
				assert.Equal(t, "preserved", current.Annotations["concurrent"])
			}
			if point == "replaced" {
				assert.Equal(t, "replacement-uid", string(current.UID))
			}
			if point == "changed-input" {
				bootstrap := &cbootstrapv1.Config{}
				require.NoError(t, pbutils.Unmarshal(current.Data["bootstrap"], bootstrap))
				assert.Equal(t, "another-client.example", bootstrap.Spec.PrimaryStorage.GetPostgresql().Host)
			}
		})
	}
}

func TestRepairBootstrapRefusesActiveOwnedPod(t *testing.T) {
	c, opts, original := newRepairBootstrap(t)
	inserted := false
	c.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		object, err := c.Tracker().Get(batchv1.SchemeGroupVersion.WithResource("jobs"), genesisNS, genesisJobName)
		if err != nil {
			return false, nil, nil
		}
		job := object.(*batchv1.Job)
		if !inserted && job.Spec.Suspend != nil && *job.Spec.Suspend {
			inserted = true
			require.NoError(t, c.Tracker().Add(&k8scorev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "custom-labels", Namespace: genesisNS, UID: "active-pod", OwnerReferences: []metav1.OwnerReference{{Kind: "Job", Name: job.Name, UID: job.UID, Controller: new(true)}}},
				Status:     k8scorev1.PodStatus{Phase: k8scorev1.PodRunning},
			}))
		}
		return false, nil, nil
	})
	_, err := createGenesis(t.Context(), opts)
	require.ErrorContains(t, err, "bootstrap differs")
	assert.True(t, inserted)
	current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, original, current)
}

func TestRepairLegacyInitializationJobCompatibility(t *testing.T) {
	for _, state := range []string{"active", "suspended", "missing-input", "changed-input", "failed"} {
		t.Run(state, func(t *testing.T) {
			c := newGenesisJobClient(t)
			bootstrap := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: postgres.example}}, secondaryStorage: {redis: {host: redis.example}}}"), bootstrap))
			opts := &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: bootstrap, Version: "1.2.3"}
			legacy, err := submitGenesisJob(t.Context(), c, getGenesisJob(opts, nil), func(ctx context.Context) error { return setClusterResources(ctx, opts) })
			require.NoError(t, err)
			if state == "suspended" || state == "missing-input" {
				legacy.Spec.Suspend = new(true)
				legacy, err = c.BatchV1().Jobs(genesisNS).Update(t.Context(), legacy, metav1.UpdateOptions{})
				require.NoError(t, err)
			}
			if state == "missing-input" {
				require.NoError(t, c.CoreV1().Secrets(genesisNS).Delete(t.Context(), "octelium-init", metav1.DeleteOptions{}))
			}
			if state == "failed" {
				legacy.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue}}
				_, err = c.BatchV1().Jobs(genesisNS).Update(t.Context(), legacy, metav1.UpdateOptions{})
				require.NoError(t, err)
			}
			if state == "changed-input" {
				opts.Bootstrap = proto.Clone(bootstrap).(*cbootstrapv1.Config)
				opts.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "changed.example"
			}
			accepted, err := createGenesis(t.Context(), opts)
			if state == "changed-input" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if state == "failed" {
				assert.NotEqual(t, legacy.UID, accepted.UID)
				assert.NotEmpty(t, accepted.Spec.Template.Annotations[initializationInputHashKey])
			} else {
				assert.Equal(t, legacy.UID, accepted.UID)
				assert.Empty(t, accepted.Spec.Template.Annotations[initializationInputHashKey])
			}
		})
	}
}

func TestRepairBootstrapStopsOnJobChange(t *testing.T) {
	for _, change := range []string{"started", "replaced"} {
		t.Run(change, func(t *testing.T) {
			c, opts, original := newRepairBootstrap(t)
			changed := false
			c.PrependReactor("get", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if changed || action.GetNamespace() != octeliumNS {
					return false, nil, nil
				}
				object, err := c.Tracker().Get(batchv1.SchemeGroupVersion.WithResource("jobs"), genesisNS, genesisJobName)
				require.NoError(t, err)
				job := object.(*batchv1.Job).DeepCopy()
				if job.Spec.Suspend != nil && *job.Spec.Suspend {
					changed = true
					if change == "started" {
						job.Spec.Suspend = new(false)
					} else {
						job.UID = "replacement-job"
					}
					job.ResourceVersion = "2"
					require.NoError(t, c.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), job, genesisNS))
				}
				return false, nil, nil
			})
			_, err := createGenesis(t.Context(), opts)
			require.Error(t, err)
			assert.True(t, changed)
			current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, original, current)
			job, err := c.BatchV1().Jobs(genesisNS).Get(t.Context(), genesisJobName, metav1.GetOptions{})
			require.NoError(t, err)
			if change == "started" {
				assert.False(t, *job.Spec.Suspend)
			} else {
				assert.Equal(t, "replacement-job", string(job.UID))
			}
		})
	}
}

func TestRepairInputHashCompatibility(t *testing.T) {
	for _, tc := range []struct{ name, hash, binding string }{
		{"region", "44642b94e6da0fa7b5e5e944c5449349ae595f3980853843c35f62812964161c", "c02a415829ae7399191ecc015fed96410e70696d2529ad2a5e7f1ee249614d97"},
		{"nil-region", "06ff4e8bba40f04f913a4f55d7b50d0a44162095cc334f17f68f34fece97c0a9", "b6fb5dbd76337d2b30299063fc3991835dfe25f151cb708446006d6e59aa04e2"},
		{"unknown", "16ec771cc69f6f92bf580c017c28f942763fbafdfa4bae41705f356f484f18cc", "2d65e18f02d1112d75ea0ee7761dbbb09623fc502cff52aeb124baa2101e0245"},
		{"empty", "3babbfe6662c6fd5437cef3d4c7e5a590ce20ab4fba62412dd3c4d2cb9f5ae50", "5920145142603dd5c2de668f49e7780a254965c718c0d2a0ec4d40621593e5f2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bootstrap := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: localhost, username: postgres, password: ' p@ss:/?& ' }}, secondaryStorage: {redis: {host: localhost, database: 7}}}"), bootstrap))
			region := &corev1.Region{Metadata: &rmetav1.Metadata{Name: "default", Labels: map[string]string{"z": "2", "a": "1"}}, Spec: &corev1.Region_Spec{}, Status: &corev1.Region_Status{}}
			if tc.name == "nil-region" {
				region = nil
			}
			if tc.name == "unknown" {
				bootstrap.ProtoReflect().SetUnknown([]byte{0xf8, 0x07, 0x01})
			}
			if tc.name == "empty" {
				bootstrap, region = &cbootstrapv1.Config{}, nil
			}
			hash, err := initializationInputHash(map[string][]byte{"bootstrap": pbutils.MarshalMust(bootstrap), "region": pbutils.MarshalMust(region), "domain": []byte("example.com")})
			require.NoError(t, err)
			assert.Equal(t, tc.hash, hash)
			assert.Equal(t, tc.binding, initializationInputBinding(hash, []byte("input-secret-uid")))
			assert.NotEqual(t, tc.binding, initializationInputBinding(hash, []byte("other-secret-uid")))
		})
	}
}

func TestRepairBindingDoesNotExposeInputHash(t *testing.T) {
	c, opts, _ := newRepairBootstrap(t)
	job, err := createGenesis(t.Context(), opts)
	require.NoError(t, err)
	source, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.NoError(t, err)
	hash, err := initializationInputHash(source.Data)
	require.NoError(t, err)
	assert.Len(t, source.Data[initializationInputKey], 32)
	assert.Equal(t, initializationInputBinding(hash, source.Data[initializationInputKey]), job.Spec.Template.Annotations[initializationInputHashKey])
	data, err := json.Marshal(job)
	require.NoError(t, err)
	assert.NotContains(t, string(data), hash)
	assert.NotContains(t, string(data), string(source.UID))
	assert.NotContains(t, string(data), "original")
}

func TestRepairConcurrentMatchingInstallations(t *testing.T) {
	c := newGenesisJobClient(t)
	bootstrap := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: postgres.example}}, secondaryStorage: {redis: {host: redis.example}}}"), bootstrap))
	opts := &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: bootstrap, Version: "1.2.3"}
	var wg sync.WaitGroup
	results := make(chan *batchv1.Job, 6)
	errors := make(chan error, 6)
	start := make(chan struct{})
	for range 6 {
		wg.Go(func() {
			<-start
			job, err := createGenesis(t.Context(), opts)
			results <- job
			errors <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	job, err := c.BatchV1().Jobs(genesisNS).Get(t.Context(), genesisJobName, metav1.GetOptions{})
	require.NoError(t, err)
	for result := range results {
		require.NotNil(t, result)
		assert.Equal(t, job.UID, result.UID)
	}
}

func TestRepairLegacyInputBindingIsOptional(t *testing.T) {
	for _, policy := range []string{"allow", "forbidden", "invalid", "immutable", "read-forbidden"} {
		t.Run(policy, func(t *testing.T) {
			c := newGenesisJobClient(t)
			bootstrap := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.UnmarshalYAML([]byte("spec: {primaryStorage: {postgresql: {host: postgres.example}}, secondaryStorage: {redis: {host: redis.example}}}"), bootstrap))
			opts := &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: bootstrap, Version: "1.2.3"}
			require.NoError(t, setClusterResources(t.Context(), opts))
			original, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), "octelium-init", metav1.GetOptions{})
			require.NoError(t, err)
			if policy == "immutable" {
				original.Immutable = new(true)
				require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), original, genesisNS))
			}
			c.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if policy == "forbidden" {
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), original.Name, io.EOF)
				}
				if policy == "invalid" {
					return true, nil, k8serr.NewInvalid(k8scorev1.SchemeGroupVersion.WithKind("Secret").GroupKind(), original.Name, field.ErrorList{field.Forbidden(field.NewPath("data", initializationInputKey), "unsupported extension")})
				}
				return false, nil, nil
			})
			if policy == "read-forbidden" {
				c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if action.(k8stesting.GetAction).GetName() == "octelium-postgres" {
						return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "octelium-postgres", io.EOF)
					}
					return false, nil, nil
				})
			}
			job, err := createGenesis(t.Context(), opts)
			require.NoError(t, err)
			current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), original.Name, metav1.GetOptions{})
			require.NoError(t, err)
			for _, key := range []string{"bootstrap", "region", "domain"} {
				assert.Equal(t, original.Data[key], current.Data[key], key)
			}
			if policy == "allow" {
				assert.Len(t, current.Data[initializationInputKey], 32)
				assert.NotEmpty(t, job.Spec.Template.Annotations[initializationInputHashKey])
			} else {
				assert.Equal(t, original, current)
				assert.Empty(t, job.Spec.Template.Annotations[initializationInputHashKey])
			}
		})
	}
}

func TestRepairInputCreationSupportsLegacyAdmission(t *testing.T) {
	c := newGenesisJobClient(t)
	rejected := 0
	c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		secret := action.(k8stesting.CreateAction).GetObject().(*k8scorev1.Secret)
		if len(secret.Data[initializationInputKey]) != 0 {
			rejected++
			return true, nil, k8serr.NewInvalid(k8scorev1.SchemeGroupVersion.WithKind("Secret").GroupKind(), secret.Name, field.ErrorList{field.Forbidden(field.NewPath("data", initializationInputKey), "unsupported extension")})
		}
		return false, nil, nil
	})
	job, err := createGenesis(t.Context(), &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: &cbootstrapv1.Config{}, Version: "1.2.3"})
	require.NoError(t, err)
	assert.Equal(t, 1, rejected)
	assert.Empty(t, job.Spec.Template.Annotations[initializationInputHashKey])
	current, err := c.CoreV1().Secrets(genesisNS).Get(t.Context(), "octelium-init", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Len(t, current.Data, 3)
}

func TestRepairJobCreationSupportsLegacyAdmission(t *testing.T) {
	c := newGenesisJobClient(t)
	rejected := 0
	c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		if job.Spec.Template.Annotations[initializationInputHashKey] != "" {
			rejected++
			return true, nil, k8serr.NewInvalid(batchv1.SchemeGroupVersion.WithKind("Job").GroupKind(), job.Name, field.ErrorList{field.Forbidden(field.NewPath("spec", "template", "metadata", "annotations"), "unsupported extension")})
		}
		return false, nil, nil
	})
	job, err := createGenesis(t.Context(), &Opts{K8sC: c, ClusterDomain: "example.com", Bootstrap: &cbootstrapv1.Config{}, Version: "1.2.3"})
	require.NoError(t, err)
	assert.Equal(t, 1, rejected)
	assert.Empty(t, job.Spec.Template.Annotations[initializationInputHashKey])
	assert.False(t, *job.Spec.Suspend)
}
