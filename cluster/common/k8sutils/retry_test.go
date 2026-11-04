package k8sutils

import (
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func reconcileRetryResource(ctx context.Context, c kubernetes.Interface, object runtime.Object) (runtime.Object, error) {
	switch object := object.(type) {
	case *appsv1.Deployment:
		return CreateOrUpdateDeployment(ctx, c, object)
	case *appsv1.DaemonSet:
		return CreateOrUpdateDaemonset(ctx, c, object)
	case *corev1.Service:
		return CreateOrUpdateService(ctx, c, object)
	case *corev1.Secret:
		return CreateOrUpdateSecret(ctx, c, object)
	case *corev1.ConfigMap:
		return CreateOrUpdateConfigMap(ctx, c, object)
	case *corev1.ServiceAccount:
		return CreateOrUpdateServiceAccount(ctx, c, object)
	case *networkingv1.NetworkPolicy:
		return CreateOrUpdateNetworkPolicy(ctx, c, object)
	case *networkingv1.Ingress:
		return CreateOrUpdateIngress(ctx, c, object)
	case *rbacv1.ClusterRole:
		return CreateOrUpdateClusterRole(ctx, c, object)
	case *rbacv1.ClusterRoleBinding:
		return CreateOrUpdateClusterRoleBinding(ctx, c, object)
	default:
		panic("unexpected resource")
	}
}

func TestResourceReconciliationUncertainWrites(t *testing.T) {
	previous := defaultRetryBackoff
	defaultRetryBackoff = wait.Backoff{Steps: 5, Duration: time.Millisecond}
	t.Cleanup(func() { defaultRetryBackoff = previous })
	for _, desired := range []runtime.Object{
		&appsv1.Deployment{}, &appsv1.DaemonSet{}, &corev1.Service{}, &corev1.Secret{}, &corev1.ConfigMap{},
		&corev1.ServiceAccount{}, &networkingv1.NetworkPolicy{}, &networkingv1.Ingress{}, &rbacv1.ClusterRole{},
		&rbacv1.ClusterRoleBinding{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "role"}},
	} {
		meta := desired.(metav1.Object)
		meta.SetName("system-resource")
		meta.SetLabels(map[string]string{"revision": "new"})
		for _, stage := range []string{"create-before", "create-after", "update-before", "update-after", "readback-outage", "conflict"} {
			t.Run(fmt.Sprintf("%s/%T", stage, desired), func(t *testing.T) {
				c := fake.NewSimpleClientset()
				input := desired.DeepCopyObject()
				if stage == "update-before" || stage == "update-after" || stage == "conflict" {
					old := desired.DeepCopyObject()
					oldMeta := old.(metav1.Object)
					oldMeta.SetUID("original")
					oldMeta.SetResourceVersion("1")
					oldMeta.SetLabels(map[string]string{"revision": "old", "customer": "preserved"})
					require.NoError(t, c.Tracker().Add(old))
				}
				failed, readsFailed := false, false
				creates, updates := 0, 0
				c.PrependReactor("*", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
					switch action.GetVerb() {
					case "create":
						creates++
						if !failed && (stage == "create-before" || stage == "create-after" || stage == "readback-outage") {
							failed = true
							if stage != "create-before" {
								object := action.(k8stesting.CreateAction).GetObject().DeepCopyObject()
								object.(metav1.Object).SetUID("created")
								require.NoError(t, c.Tracker().Create(action.GetResource(), object, action.GetNamespace()))
							}
							return true, nil, io.ErrUnexpectedEOF
						}
					case "get":
						if stage == "readback-outage" && !readsFailed {
							readsFailed = true
							return true, nil, k8serr.NewServiceUnavailable("temporary readback outage")
						}
					case "update":
						updates++
						if !failed && (stage == "update-before" || stage == "update-after" || stage == "conflict") {
							failed = true
							if stage == "update-after" {
								require.NoError(t, c.Tracker().Update(action.GetResource(), action.(k8stesting.UpdateAction).GetObject(), action.GetNamespace()))
							}
							if stage == "conflict" {
								current, err := c.Tracker().Get(action.GetResource(), action.GetNamespace(), meta.GetName())
								require.NoError(t, err)
								current.(metav1.Object).GetLabels()["concurrent"] = "preserved"
								current.(metav1.Object).SetResourceVersion("2")
								require.NoError(t, c.Tracker().Update(action.GetResource(), current, action.GetNamespace()))
								return true, nil, k8serr.NewConflict(action.GetResource().GroupResource(), meta.GetName(), io.ErrUnexpectedEOF)
							}
							return true, nil, io.ErrUnexpectedEOF
						}
					}
					return false, nil, nil
				})
				result, err := reconcileRetryResource(t.Context(), c, desired)
				require.NoError(t, err)
				require.True(t, failed)
				assert.Equal(t, "new", result.(metav1.Object).GetLabels()["revision"])
				assert.Equal(t, input, desired)
				if stage == "create-after" || stage == "readback-outage" {
					assert.Equal(t, 1, creates)
					assert.Equal(t, "created", string(result.(metav1.Object).GetUID()))
				}
				if stage == "update-after" {
					assert.Equal(t, 1, updates)
				}
				if stage == "conflict" {
					assert.Equal(t, "preserved", result.(metav1.Object).GetLabels()["concurrent"])
					assert.Equal(t, "2", result.(metav1.Object).GetResourceVersion())
				}
			})
		}
	}
}

func TestReadinessTemporaryErrorsAndContext(t *testing.T) {
	previous := ldflags.TestMode
	ldflags.TestMode = "false"
	t.Cleanup(func() { ldflags.TestMode = previous })
	for _, kind := range []string{"nodes", "daemonsets", "deployments", "replicasets"} {
		t.Run(kind, func(t *testing.T) {
			dep := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "octelium", UID: "deployment"},
				Spec:       appsv1.DeploymentSpec{Replicas: new(int32(1)), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}}, Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "test"}}}},
			}
			rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "test-rs", Namespace: "octelium", Labels: map[string]string{"app": "test"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", UID: dep.UID, Name: dep.Name, Controller: new(true)}}}, Spec: appsv1.ReplicaSetSpec{Template: dep.Spec.Template}, Status: appsv1.ReplicaSetStatus{ReadyReplicas: 1}}
			c := fake.NewSimpleClientset(dep, rs,
				&appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "octelium"}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 1, NumberReady: 1}},
				&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node"}, Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}}},
			)
			failed := false
			c.PrependReactor("*", kind, func(k8stesting.Action) (bool, runtime.Object, error) {
				if !failed {
					failed = true
					return true, nil, k8serr.NewServiceUnavailable("short API outage")
				}
				return false, nil, nil
			})
			ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
			defer cancel()
			var err error
			switch kind {
			case "nodes":
				err = WaitForNodesReadiness(ctx, c)
			case "daemonsets":
				err = WaitReadinessDaemonsetWithNS(ctx, c, "test", "octelium")
			default:
				err = WaitReadinessDeploymentWithNS(ctx, c, "test", "octelium")
			}
			require.NoError(t, err)
			require.True(t, failed)
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c := fake.NewSimpleClientset()
	require.ErrorIs(t, WaitForNodesReadiness(ctx, c), context.Canceled)
	require.ErrorIs(t, WaitReadinessDaemonsetWithNS(ctx, c, "test", "octelium"), context.Canceled)
	_, err := GetNewReplicaSetWithContext(ctx, &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{}}}, c.AppsV1())
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, c.Actions())
}

func TestGeneratedResourceCreationIsNotReplayed(t *testing.T) {
	c := fake.NewSimpleClientset()
	creates := 0
	c.PrependReactor("create", "configmaps", func(k8stesting.Action) (bool, runtime.Object, error) {
		creates++
		return true, nil, io.ErrUnexpectedEOF
	})
	_, err := CreateOrUpdateConfigMap(t.Context(), c, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{GenerateName: "generated-", Namespace: "octelium"}})
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	assert.Equal(t, 1, creates)
	for _, action := range c.Actions() {
		assert.Equal(t, "create", action.GetVerb())
	}
}
