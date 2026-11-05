/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package genesis

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newInitializationInput(t *testing.T) *LoadedClusterResource {
	t.Helper()
	t.Setenv("OCTELIUM_DOMAIN", "example.com")
	bs := &cbootstrapv1.Config{}
	require.NoError(t, pbutils.UnmarshalYAML([]byte(`spec:
  primaryStorage:
    postgresql: {host: localhost, username: postgres, password: postgres}
  secondaryStorage:
    redis: {host: localhost, password: secret}
`), bs))
	return &LoadedClusterResource{
		Domain:    "example.com",
		Bootstrap: bs,
		Region: &corev1.Region{
			Metadata: &metav1.Metadata{Name: "default", SystemLabels: map[string]string{"external-ips": `["192.0.2.1"]`}},
			Spec:     &corev1.Region_Spec{},
			Status:   &corev1.Region_Status{},
		},
	}
}

func TestInitializationStateReplay(t *testing.T) {
	g := &Genesis{k8sC: fakek8s.NewSimpleClientset()}
	input := newInitializationInput(t)
	original := proto.Clone(input.Region)
	first, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	assert.True(t, proto.Equal(original, input.Region))
	second, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	assert.Equal(t, first.id, second.id)
	assert.Equal(t, first.inputHash, second.inputHash)
	assert.Regexp(t, "^sys:aes256-key-[a-z0-9]{8}$", first.aesKeyName)
	assert.Equal(t, first.aesKeyName, second.aesKeyName)
	assert.True(t, proto.Equal(first.clusterConfig, second.clusterConfig))
	assert.True(t, proto.Equal(first.region, second.region))
	assert.False(t, second.complete)
	secret, err := g.k8sC.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	require.NotNil(t, secret.Immutable)
	assert.True(t, *secret.Immutable)
	for _, action := range g.k8sC.(*fakek8s.Clientset).Actions() {
		assert.NotEqual(t, "delete", action.GetVerb())
		assert.NotEqual(t, "update", action.GetVerb())
	}
	require.NoError(t, g.completeInitialization(t.Context(), first))
	require.NoError(t, g.completeInitialization(t.Context(), first))
	finished, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	assert.True(t, finished.complete)
	assert.Equal(t, first.id, finished.id)
}

func TestInitializationInputHash(t *testing.T) {
	first := newInitializationInput(t)
	second := newInitializationInput(t)
	first.Region.Metadata.Labels = map[string]string{"a": "1", "b": "2"}
	second.Region.Metadata.Labels = map[string]string{"b": "2", "a": "1"}
	left, err := initializationInputHash(first)
	require.NoError(t, err)
	right, err := initializationInputHash(second)
	require.NoError(t, err)
	assert.Equal(t, left, right)
	for _, change := range []func(*LoadedClusterResource){
		func(cr *LoadedClusterResource) { cr.Domain = "another.example" },
		func(cr *LoadedClusterResource) { cr.Region.Metadata.Name = "another" },
		func(cr *LoadedClusterResource) { cr.Bootstrap.Spec.PrimaryStorage.GetPostgresql().Database = "another" },
	} {
		cr := newInitializationInput(t)
		g := &Genesis{k8sC: fakek8s.NewSimpleClientset()}
		_, err := g.prepareInitialization(t.Context(), cr)
		require.NoError(t, err)
		change(cr)
		t.Setenv("OCTELIUM_DOMAIN", cr.Domain)
		_, err = g.prepareInitialization(t.Context(), cr)
		require.ErrorContains(t, err, "bootstrap differs")
	}
}

func TestInitializationRejectsLegacyInstallation(t *testing.T) {
	for _, name := range []string{"octelium-init", "init-token", "octelium-postgres", "octelium-redis", installationConfigMapName} {
		t.Run(name, func(t *testing.T) {
			var object runtime.Object = &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: name, Namespace: vutils.K8sNS}}
			if name == installationConfigMapName {
				object = &k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: name, Namespace: vutils.K8sNS}}
			}
			c := fakek8s.NewSimpleClientset(object)
			g := &Genesis{k8sC: c}
			_, err := g.prepareInitialization(t.Context(), newInitializationInput(t))
			require.ErrorContains(t, err, "octops upgrade")
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
			}
		})
	}
}

func TestInitializationStateFailures(t *testing.T) {
	for _, verb := range []string{"get", "create"} {
		t.Run(verb, func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
			want := k8serr.NewServiceUnavailable("temporary failure")
			c.PrependReactor(verb, "secrets", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
			g := &Genesis{k8sC: c}
			ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
			defer cancel()
			_, err := g.prepareInitialization(ctx, newInitializationInput(t))
			assert.ErrorIs(t, err, want)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
		})
	}
	for _, field := range []string{"version", "id", "input-hash", "clusterConfig", "region"} {
		t.Run(field, func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
			g := &Genesis{k8sC: c}
			input := newInitializationInput(t)
			_, err := g.prepareInitialization(t.Context(), input)
			require.NoError(t, err)
			secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
			require.NoError(t, err)
			secret.Data[field] = []byte("corrupt")
			require.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), secret, vutils.K8sNS))
			_, err = g.prepareInitialization(t.Context(), input)
			require.Error(t, err)
		})
	}
	for _, input := range []*LoadedClusterResource{nil, {}, {Bootstrap: &cbootstrapv1.Config{}}} {
		g := &Genesis{k8sC: fakek8s.NewSimpleClientset()}
		_, err := g.prepareInitialization(t.Context(), input)
		require.Error(t, err)
	}
}

func TestInitializationVersionAndIdentity(t *testing.T) {
	previous := ldflags.GitTag
	t.Cleanup(func() { ldflags.GitTag = previous })
	ldflags.GitTag = "v1.0.0"
	c := fakek8s.NewSimpleClientset()
	g := &Genesis{k8sC: c}
	input := newInitializationInput(t)
	init, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	ldflags.GitTag = "v1.0.1"
	_, err = g.prepareInitialization(t.Context(), input)
	require.ErrorContains(t, err, "version 1.0.0")
	ldflags.GitTag = "v1.0.0"
	require.NoError(t, g.completeInitialization(t.Context(), init))
	ldflags.GitTag = "v1.0.1"
	_, err = g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	wrong := *init
	wrong.id = vutils.UUIDv4()
	require.ErrorContains(t, g.completeInitialization(t.Context(), &wrong), "identity changed")
}

func TestInitializationStateCreateRace(t *testing.T) {
	input := newInitializationInput(t)
	winnerClient := fakek8s.NewSimpleClientset()
	winner := &Genesis{k8sC: winnerClient}
	state, err := winner.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	secret, err := winnerClient.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), initializationSecretName, k8smetav1.GetOptions{})
	require.NoError(t, err)
	c := fakek8s.NewSimpleClientset()
	c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		require.NoError(t, c.Tracker().Add(secret))
		return true, nil, k8serr.NewAlreadyExists(action.GetResource().GroupResource(), initializationSecretName)
	})
	g := &Genesis{k8sC: c}
	resumed, err := g.prepareInitialization(t.Context(), input)
	require.NoError(t, err)
	assert.Equal(t, state.id, resumed.id)
	assert.True(t, proto.Equal(state.clusterConfig, resumed.clusterConfig))
}

func TestInitializationCompletionConflict(t *testing.T) {
	c := fakek8s.NewSimpleClientset()
	g := &Genesis{k8sC: c}
	state, err := g.prepareInitialization(t.Context(), newInitializationInput(t))
	require.NoError(t, err)
	calls := 0
	c.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls == 1 {
			return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), initializationSecretName, io.ErrUnexpectedEOF)
		}
		return false, nil, nil
	})
	require.NoError(t, g.completeInitialization(t.Context(), state))
	assert.Equal(t, 2, calls)
}

func TestInitializationPreservesNamespace(t *testing.T) {
	for _, terminating := range []bool{false, true} {
		t.Run(fmt.Sprint(terminating), func(t *testing.T) {
			namespace := &k8scorev1.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS, UID: types.UID("existing"), Labels: map[string]string{"custom": "preserve"}}}
			if terminating {
				namespace.DeletionTimestamp = new(k8smetav1.Now())
			}
			c := fakek8s.NewSimpleClientset(namespace, &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "storage-auth", Namespace: vutils.K8sNS}, Data: map[string][]byte{"password": []byte("preserve")}})
			g := &Genesis{k8sC: c}
			err := g.setNamespace(t.Context())
			if terminating {
				require.ErrorContains(t, err, "terminating")
			} else {
				require.NoError(t, err)
			}
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
			}
			existing, err := c.CoreV1().Namespaces().Get(t.Context(), vutils.K8sNS, k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, namespace, existing)
		})
	}
}

func TestInitializationPreservesStorageSecrets(t *testing.T) {
	for _, postgres := range []bool{false, true} {
		t.Run(fmt.Sprint(postgres), func(t *testing.T) {
			c := fakek8s.NewSimpleClientset()
			g := &Genesis{k8sC: c}
			create := g.createRedisSecret
			name := "octelium-redis"
			if postgres {
				create = g.createPostgresSecret
				name = "octelium-postgres"
			}
			data := map[string][]byte{"password": []byte("original"), "host": []byte("original")}
			require.NoError(t, create(t.Context(), data))
			require.NoError(t, create(t.Context(), data))
			require.ErrorContains(t, create(t.Context(), map[string][]byte{"password": []byte("changed")}), "Refusing to replace")
			secret, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), name, k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, data, secret.Data)
			for _, action := range c.Actions() {
				assert.NotEqual(t, "update", action.GetVerb())
				assert.NotEqual(t, "delete", action.GetVerb())
			}
		})
	}
}

func TestCreateInitResource(t *testing.T) {
	for _, failure := range []string{"none", "read", "create", "response lost", "already exists"} {
		t.Run(failure, func(t *testing.T) {
			var stored *corev1.Secret
			creates := 0
			reads := 0
			get := func(context.Context, *rmetav1.GetOptions, ...grpc.CallOption) (*corev1.Secret, error) {
				reads++
				if failure == "read" {
					return nil, status.Error(codes.Unavailable, "read failed")
				}
				if stored == nil {
					return nil, status.Error(codes.NotFound, "missing")
				}
				return proto.Clone(stored).(*corev1.Secret), nil
			}
			create := func(_ context.Context, value *corev1.Secret, _ ...grpc.CallOption) (*corev1.Secret, error) {
				creates++
				if failure == "create" {
					return nil, status.Error(codes.Unavailable, "create failed")
				}
				stored = proto.Clone(value).(*corev1.Secret)
				if failure == "response lost" {
					return nil, status.Error(codes.Unavailable, "response lost")
				}
				if failure == "already exists" {
					return nil, status.Error(codes.AlreadyExists, "committed")
				}
				return proto.Clone(stored).(*corev1.Secret), nil
			}
			resource := &corev1.Secret{Metadata: &metav1.Metadata{Name: "sys:key"}, Data: &corev1.Secret_Data{Type: &corev1.Secret_Data_ValueBytes{ValueBytes: []byte("original")}}}
			_, err := createInitResource(t.Context(), resource, get, create)
			switch failure {
			case "read":
				require.Error(t, err)
				assert.Zero(t, creates)
				return
			case "create":
				require.Error(t, err)
				assert.Nil(t, stored)
				return
			case "response lost":
				require.Error(t, err)
			default:
				require.NoError(t, err)
			}
			resource.Data = &corev1.Secret_Data{Type: &corev1.Secret_Data_ValueBytes{ValueBytes: []byte("replacement")}}
			existing, err := createInitResource(t.Context(), resource, get, create)
			require.NoError(t, err)
			assert.Equal(t, "original", string(existing.Data.GetValueBytes()))
			assert.Equal(t, 1, creates)
			assert.GreaterOrEqual(t, reads, 2)
		})
	}
}

func TestInitializationTokenOwnership(t *testing.T) {
	for _, tc := range []struct {
		id, token string
		valid     bool
	}{
		{"owner", "token", true}, {"another", "token", false}, {"", "token", false}, {"owner", "", false},
	} {
		c := fakek8s.NewSimpleClientset(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "init-token", Namespace: vutils.K8sNS, Annotations: map[string]string{initializationIDKey: tc.id}}, Data: map[string][]byte{"data": []byte(tc.token)}})
		g := &Genesis{k8sC: c, initializationID: "owner"}
		_, err := g.getInitAuthenticationToken(t.Context())
		assert.Equal(t, tc.valid, err == nil)
	}
}

func TestInitializationDoesNotMutateWithoutInput(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "true"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, data := range []map[string][]byte{nil, {"bootstrap": {}}, {"bootstrap": {0xff}}} {
		objects := []runtime.Object{&k8scorev1.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: vutils.K8sNS, UID: "preserve"}}}
		if data != nil {
			objects = append(objects, &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "default"}, Data: data})
		}
		c := fakek8s.NewSimpleClientset(objects...)
		g := &Genesis{k8sC: c}
		require.Error(t, g.RunInit(t.Context(), nil))
		for _, action := range c.Actions() {
			assert.Equal(t, "get", action.GetVerb())
		}
	}
}

func TestInitializationBootstrapMoveReplay(t *testing.T) {
	for _, operation := range []string{"copy", "delete"} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/committed=%t", operation, committed), func(t *testing.T) {
				input := newInitializationInput(t)
				secret := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "default", UID: "source", ResourceVersion: "1"}, Data: map[string][]byte{"bootstrap": pbutils.MarshalMust(input.Bootstrap), "region": pbutils.MarshalMust(input.Region), "domain": []byte(input.Domain)}}
				c := fakek8s.NewSimpleClientset(secret)
				g := &Genesis{k8sC: c}
				verb := "create"
				if operation == "delete" {
					verb = "delete"
				}
				failed := false
				c.PrependReactor(verb, "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if failed {
						return false, nil, nil
					}
					failed = true
					if committed {
						if operation == "copy" {
							require.NoError(t, c.Tracker().Create(k8scorev1.SchemeGroupVersion.WithResource("secrets"), action.(k8stesting.CreateAction).GetObject(), vutils.K8sNS))
						} else {
							require.NoError(t, c.Tracker().Delete(k8scorev1.SchemeGroupVersion.WithResource("secrets"), "default", "octelium-init"))
						}
					}
					return true, nil, io.ErrUnexpectedEOF
				})
				require.NoError(t, g.moveClusterInitResources(t.Context()))
				require.NoError(t, g.moveClusterInitResources(t.Context()))
				_, err := c.CoreV1().Secrets("default").Get(t.Context(), secret.Name, k8smetav1.GetOptions{})
				assert.True(t, k8serr.IsNotFound(err))
				stored, err := c.CoreV1().Secrets(vutils.K8sNS).Get(t.Context(), secret.Name, k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, secret.Data, stored.Data)
			})
		}
	}
}

func TestInitializationBootstrapMoveRejectsDifferentInput(t *testing.T) {
	c := fakek8s.NewSimpleClientset(
		&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "default"}, Data: map[string][]byte{"domain": []byte("first.example")}},
		&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: vutils.K8sNS}, Data: map[string][]byte{"domain": []byte("other.example")}},
	)
	g := &Genesis{k8sC: c}
	require.ErrorContains(t, g.moveClusterInitResources(t.Context()), "differs")
	for _, action := range c.Actions() {
		assert.NotEqual(t, "delete", action.GetVerb())
	}
}

func TestInitializationPreservesRegisteredNodes(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "gateway", Labels: map[string]string{vutils.NodeLabelDataPlane: "", vutils.NodeLabelGatewayRegistered: "true"}}}
	c := fakek8s.NewSimpleClientset(node, readyGatewayDaemonSet())
	g := &Genesis{k8sC: c}
	require.NoError(t, g.setDataPlaneNodeTaints(t.Context()))
	updated, err := c.CoreV1().Nodes().Get(t.Context(), node.Name, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, node, updated)
	for _, action := range c.Actions() {
		assert.NotEqual(t, "update", action.GetVerb())
	}
}

func TestInitializationResetsStaleGatewayRegistration(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "gateway", Labels: map[string]string{vutils.NodeLabelDataPlane: "", vutils.NodeLabelGatewayRegistered: "true", "custom": "preserved"}}}
	c := fakek8s.NewSimpleClientset(node)
	g := &Genesis{k8sC: c}
	require.NoError(t, g.setDataPlaneNodeTaints(t.Context()))
	updated, err := c.CoreV1().Nodes().Get(t.Context(), node.Name, k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.NotContains(t, updated.Labels, vutils.NodeLabelGatewayRegistered)
	assert.Equal(t, "preserved", updated.Labels["custom"])
	require.Len(t, updated.Spec.Taints, 1)
	assert.Equal(t, vutils.NodeTaintGatewayInit, updated.Spec.Taints[0].Key)
	c.ClearActions()
	require.NoError(t, g.setDataPlaneNodeTaints(t.Context()))
	for _, action := range c.Actions() {
		assert.NotEqual(t, "update", action.GetVerb())
	}
}
