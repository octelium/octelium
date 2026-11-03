package install

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestDoInstallPreservesExistingInstallation(t *testing.T) {
	for _, name := range []string{"init-token", "octelium-init", installationConfigMapName, "octelium-genesis-init"} {
		t.Run(name, func(t *testing.T) {
			var object runtime.Object = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: octeliumNS, Annotations: map[string]string{"octelium.com/genesis-init-complete": "true"}},
				Data:       map[string][]byte{"data": []byte("existing-token")},
			}
			if name == installationConfigMapName {
				object = &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: octeliumNS}}
			}
			source := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "octelium-init", Namespace: "default"}, Data: map[string][]byte{"domain": []byte("original.example")}}
			c := fake.NewSimpleClientset(object, source)
			require.ErrorContains(t, DoInstall(t.Context(), &Opts{K8sC: c, ClusterDomain: "replacement.example"}), "octops upgrade")
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
			}
			stored, err := c.CoreV1().Secrets("default").Get(t.Context(), source.Name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, source.Data, stored.Data)
		})
	}
}

func TestInstallationAdmissionAllowsFreshAndIncomplete(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		t.Run(fmt.Sprint(incomplete), func(t *testing.T) {
			c := fake.NewSimpleClientset()
			if incomplete {
				require.NoError(t, c.Tracker().Add(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "octelium-genesis-init", Namespace: octeliumNS}}))
				require.NoError(t, c.Tracker().Add(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: installationConfigMapName, Namespace: octeliumNS}}))
			}
			require.NoError(t, checkExistingInstallation(t.Context(), c))
		})
	}
}

func TestInstallationAdmissionReadFailures(t *testing.T) {
	for _, resource := range []string{"secrets", "configmaps"} {
		t.Run(resource, func(t *testing.T) {
			c := fake.NewSimpleClientset()
			want := k8serr.NewServiceUnavailable("temporary outage")
			c.PrependReactor("get", resource, func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
			assert.ErrorIs(t, DoInstall(t.Context(), &Opts{K8sC: c}), want)
			for _, action := range c.Actions() {
				assert.Equal(t, "get", action.GetVerb())
			}
		})
	}
}
