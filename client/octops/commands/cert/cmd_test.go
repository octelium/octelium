package cert

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestCreateOrUpdateCertificate(t *testing.T) {
	ctx := context.Background()
	for _, metadata := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing metadata=%t", metadata), func(t *testing.T) {
			old := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cert-cluster", Namespace: "octelium", ResourceVersion: "17"}, Data: map[string][]byte{"old": []byte("old")}}
			if metadata {
				old.Labels = map[string]string{"retained": "yes", "updated": "old"}
				old.Annotations = map[string]string{"retained": "yes", "updated": "old"}
			}
			c := fakek8s.NewSimpleClientset(old)
			want := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: old.Name, Namespace: old.Namespace, Labels: map[string]string{"updated": "new"}, Annotations: map[string]string{"updated": "new"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "owner", UID: "owner-uid"}}}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{"tls.crt": []byte("certificate"), "tls.key": []byte("key")}, StringData: map[string]string{"extra": "extra"}}
			got, err := createOrUpdate(ctx, c, want)
			require.NoError(t, err)
			assert.Equal(t, "17", got.ResourceVersion)
			assert.Equal(t, want.Data, got.Data)
			assert.Equal(t, want.StringData, got.StringData)
			assert.Equal(t, want.Type, got.Type)
			assert.Equal(t, want.OwnerReferences, got.OwnerReferences)
			assert.Equal(t, "new", got.Labels["updated"])
			assert.Equal(t, "new", got.Annotations["updated"])
			if metadata {
				assert.Equal(t, "yes", got.Labels["retained"])
				assert.Equal(t, "yes", got.Annotations["retained"])
			}
		})
	}
	c := fakek8s.NewSimpleClientset()
	want := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cert-cluster", Namespace: "octelium"}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{"tls.crt": []byte("certificate"), "tls.key": []byte("key")}}
	got, err := createOrUpdate(ctx, c, want)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestCreateOrUpdateCertificateErrors(t *testing.T) {
	for _, verb := range []string{"create", "get", "update"} {
		t.Run(verb, func(t *testing.T) {
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cert-cluster", Namespace: "octelium"}}
			c := fakek8s.NewSimpleClientset()
			if verb != "create" {
				require.NoError(t, c.Tracker().Add(secret))
			}
			c.PrependReactor(verb, "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), secret.Name, fmt.Errorf("not permitted"))
			})
			_, err := createOrUpdate(context.Background(), c, secret)
			assert.True(t, k8serr.IsForbidden(err))
			actions := c.Actions()
			assert.Equal(t, verb, actions[len(actions)-1].GetVerb())
		})
	}
}
