package genesis

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	rmetav1 "github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestRepairCheckpointBeforeStorage(t *testing.T) {
	c := fake.NewSimpleClientset()
	g := &Genesis{k8sC: c}
	input := newInitializationInput(t)
	first, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	checkpoint, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	checkpoint.UID, checkpoint.ResourceVersion = "checkpoint-uid", "1"
	require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), checkpoint, vutils.K8sNS))
	input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "corrected-postgres.example"
	repaired, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	assert.NotEqual(t, first.id, repaired.id)
	assert.NotEqual(t, first.inputHash, repaired.inputHash)
	assert.Equal(t, input.Domain, repaired.clusterConfig.Status.Domain)
	assert.NotEmpty(t, repaired.aesKeyName)
	current, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, repaired.id, string(current.Data["id"]))
}

func newRepairCheckpoint(t *testing.T) (*Genesis, *fake.Clientset, *LoadedClusterResource, *k8scorev1.Secret) {
	t.Helper()
	c := fake.NewSimpleClientset(&k8scorev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: vutils.K8sNS, UID: "namespace-uid"}})
	g := &Genesis{k8sC: c}
	input := newInitializationInput(t)
	_, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	checkpoint, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	checkpoint.UID, checkpoint.ResourceVersion = "checkpoint-uid", "1"
	require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), checkpoint, vutils.K8sNS))
	return g, c, input, checkpoint
}

func TestRepairCheckpointPreservesStartedInstallation(t *testing.T) {
	for _, phase := range []string{"octelium-postgres", "octelium-redis", "octelium-init", "init-token", "configuration", "complete", "namespace", "corrupt", "version", "uid", "resource-version"} {
		t.Run(phase, func(t *testing.T) {
			g, c, input, checkpoint := newRepairCheckpoint(t)
			input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "corrected.example"
			switch phase {
			case "configuration":
				require.NoError(t, c.Tracker().Add(&k8scorev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: installationConfigMapName, Namespace: vutils.K8sNS}}))
			case "complete":
				checkpoint.Annotations = map[string]string{initializationCompleteKey: "true"}
			case "namespace":
				checkpoint.Data["namespace-uid"] = []byte("previous-namespace")
			case "corrupt":
				checkpoint.Data["clusterConfig"] = []byte("invalid")
			case "version":
				previous := ldflags.GitTag
				t.Cleanup(func() { ldflags.GitTag = previous })
				ldflags.GitTag = "v987.0.0"
			case "uid":
				checkpoint.UID = ""
			case "resource-version":
				checkpoint.ResourceVersion = ""
			default:
				require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: phase, Namespace: vutils.K8sNS, UID: "preserved"}, Data: map[string][]byte{"value": []byte("preserved")}}))
			}
			require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), checkpoint, vutils.K8sNS))
			c.ClearActions()
			_, err := g.prepareInitialization(t.Context(), input)
			require.Error(t, err)
			for _, action := range c.Actions() {
				assert.Contains(t, []string{"get", "list"}, action.GetVerb())
			}
			current, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, checkpoint, current)
		})
	}
}

func TestRepairCheckpointWaitsForSuccessfulPreflight(t *testing.T) {
	for _, phase := range []string{"new", "repair", "storage-appears"} {
		t.Run(phase, func(t *testing.T) {
			g, c, input, checkpoint := newRepairCheckpoint(t)
			if phase == "new" {
				require.NoError(t, c.Tracker().Delete(k8scorev1.SchemeGroupVersion.WithResource("secrets"), vutils.K8sNS, initializationSecretName))
			}
			input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "corrected.example"
			calls := 0
			want := fmt.Errorf("storage not available")
			_, err := g.prepareInitializationWithPreflight(t.Context(), input, func(ctx context.Context, passwords *storagePasswords) error {
				calls++
				assert.NoError(t, ctx.Err())
				assert.Equal(t, "postgres", passwords.postgres)
				if phase == "storage-appears" {
					require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "octelium-postgres", Namespace: vutils.K8sNS}}))
					return nil
				}
				return want
			})
			require.Error(t, err)
			assert.Equal(t, 1, calls)
			if phase != "storage-appears" {
				assert.ErrorIs(t, err, want)
			}
			current, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, metav1.GetOptions{})
			if phase == "new" {
				assert.True(t, k8serr.IsNotFound(err))
			} else {
				require.NoError(t, err)
				assert.Equal(t, checkpoint, current)
			}
		})
	}
}

func TestRepairCheckpointDeletionSafety(t *testing.T) {
	for _, point := range []string{"before", "after", "replaced", "completed", "forbidden", "cancelled"} {
		t.Run(point, func(t *testing.T) {
			g, c, input, checkpoint := newRepairCheckpoint(t)
			input.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Host = "corrected.example"
			deletes := 0
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			c.PrependReactor("delete", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				deletes++
				deleteAction := action.(k8stesting.DeleteAction)
				require.Equal(t, initializationSecretName, deleteAction.GetName())
				preconditions := deleteAction.GetDeleteOptions().Preconditions
				require.NotNil(t, preconditions)
				assert.Equal(t, new(checkpoint.UID), preconditions.UID)
				assert.Equal(t, new(checkpoint.ResourceVersion), preconditions.ResourceVersion)
				if deletes > 1 {
					return false, nil, nil
				}
				switch point {
				case "after":
					require.NoError(t, c.Tracker().Delete(action.GetResource(), action.GetNamespace(), initializationSecretName))
				case "replaced":
					current := checkpoint.DeepCopy()
					current.UID, current.ResourceVersion = "replacement-uid", "2"
					require.NoError(t, c.Tracker().Update(action.GetResource(), current, action.GetNamespace()))
					return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), initializationSecretName, io.EOF)
				case "completed":
					current := checkpoint.DeepCopy()
					current.Annotations, current.ResourceVersion = map[string]string{initializationCompleteKey: "true"}, "2"
					require.NoError(t, c.Tracker().Update(action.GetResource(), current, action.GetNamespace()))
					return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), initializationSecretName, io.EOF)
				case "forbidden":
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), initializationSecretName, io.EOF)
				case "cancelled":
					cancel()
					return true, nil, context.Canceled
				}
				return true, nil, io.ErrUnexpectedEOF
			})
			repaired, err := g.prepareInitialization(ctx, input)
			switch point {
			case "before", "after":
				require.NoError(t, err)
				assert.NotEqual(t, string(checkpoint.Data["id"]), repaired.id)
				if point == "before" {
					assert.Equal(t, 2, deletes)
				} else {
					assert.Equal(t, 1, deletes)
				}
			default:
				require.Error(t, err)
				assert.Equal(t, 1, deletes)
				current, getErr := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, metav1.GetOptions{})
				require.NoError(t, getErr)
				if point == "replaced" {
					assert.Equal(t, "replacement-uid", string(current.UID))
				} else if point == "completed" {
					assert.Equal(t, "true", current.Annotations[initializationCompleteKey])
				} else {
					assert.Equal(t, checkpoint, current)
				}
			}
		})
	}
}

func TestRepairMatchingCheckpointSkipsNewPreflight(t *testing.T) {
	g, _, input, checkpoint := newRepairCheckpoint(t)
	result, err := g.prepareInitializationWithPreflight(t.Context(), input, func(context.Context, *storagePasswords) error {
		t.Fatal("Matching checkpoint must retain legacy replay behavior")
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, string(checkpoint.Data["id"]), result.id)
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
			hash, err := initializationInputHash(&LoadedClusterResource{Bootstrap: bootstrap, Region: region, Domain: "example.com"})
			require.NoError(t, err)
			assert.Equal(t, tc.hash, hash)
			assert.Equal(t, tc.binding, initializationInputBinding(hash, []byte("input-secret-uid")))
			assert.NotEqual(t, tc.binding, initializationInputBinding(hash, []byte("other-secret-uid")))
		})
	}
}
