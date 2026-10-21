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

package k8sutils

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	k8scorev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestKubeConfigSelection(t *testing.T) {
	cfg := &KubeConfig{
		CurrentContext: "first",
		Contexts: []KubeConfigContext{
			{Name: "first", Context: KubeConfigContextConfig{Cluster: "cluster1", User: "user1"}},
			{Name: "second", Context: KubeConfigContextConfig{Cluster: "cluster2", User: "user2"}},
		},
		Clusters: []KubeConfigCluster{{Name: "cluster1"}, {Name: "cluster2"}},
		Users:    []KubeConfigUser{{Name: "user1"}, {Name: "user2"}},
	}
	assert.Equal(t, "first", cfg.GetContext("").Name)
	assert.Equal(t, "cluster2", cfg.GetCluster("second").Name)
	assert.Equal(t, "user2", cfg.GetUser("second").Name)
	for _, name := range []string{"missing", "invalid"} {
		assert.Nil(t, cfg.GetContext(name))
		assert.Nil(t, cfg.GetCluster(name))
		assert.Nil(t, cfg.GetUser(name))
	}
	data, err := cfg.MarshalToYAML()
	assert.Nil(t, err)
	res, err := UnmarshalKubeConfigFromYAML(data)
	assert.Nil(t, err)
	assert.Equal(t, cfg, res)
	cfg.CurrentContext = ""
	assert.Nil(t, cfg.GetContext(""))
	cfg.Clusters, cfg.Users = nil, nil
	assert.Nil(t, cfg.GetCluster("first"))
	assert.Nil(t, cfg.GetUser("first"))
	_, err = UnmarshalKubeConfigFromYAML([]byte("[invalid"))
	assert.NotNil(t, err)
}

func TestServiceHostnames(t *testing.T) {
	svc := &corev1.Service{Metadata: &metav1.Metadata{Name: "service.namespace"}}
	assert.Equal(t, "svc-service-namespace", GetSvcHostname(svc))
	assert.Equal(t, "svc-service-namespace.octelium.svc", GetSvcFQDN(svc))
	assert.Equal(t, "upstream-svc-service-namespace-default", GetSvcK8sUpstreamHostname(svc, ""))
	assert.Equal(t, "upstream-svc-service-namespace-selected.octelium.svc", GetSvcK8sUpstreamFQDN(svc, "selected"))
	t.Setenv("OCTELIUM_REGION_NAME", "region")
	node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "node", UID: "uid"}}
	name := GetGatewayName(node)
	assert.Equal(t, name, GetGatewayName(node.DeepCopy()))
	node.UID = "new-uid"
	assert.NotEqual(t, name, GetGatewayName(node))
	assert.Equal(t, k8scorev1.PullIfNotPresent, GetImagePullPolicy())
	assert.Equal(t, "csi.spiffe.io", GetSPIFFEVolume("").CSI.Driver)
	assert.Equal(t, "custom", GetSPIFFEVolume("custom").CSI.Driver)
	assert.True(t, *GetSPIFFEVolume("").CSI.ReadOnly)
	assert.True(t, GetSPIFFEVolumeMount().ReadOnly)
	assert.Equal(t, GetSPIFFEVolume("").Name, GetSPIFFEVolumeMount().Name)
	limits := GetDefaultLimits()
	assert.EqualValues(t, DefaultLimitCPUMillicores, limits.Cpu().MilliValue())
	assert.EqualValues(t, DefaultLimitMemoryMegabytes*1024*1024, limits.Memory().Value())
	assert.EqualValues(t, 1, GetResourceQuantityMust("1").Value())
}

func testCreateOrUpdateResource[T interface {
	runtime.Object
	k8smetav1.Object
}](t *testing.T, old, desired T, apply func(context.Context, kubernetes.Interface, T) (T, error), check func(T)) {
	t.Helper()
	ctx := context.Background()
	md := desired
	md.SetName("resource")
	md.SetNamespace("octelium")
	switch any(desired).(type) {
	case *rbacv1.ClusterRole, *rbacv1.ClusterRoleBinding:
		md.SetNamespace("")
	}
	md.SetLabels(map[string]string{"managed": "new"})
	md.SetAnnotations(map[string]string{"managed": "new"})
	md.SetOwnerReferences([]k8smetav1.OwnerReference{{Name: "owner", UID: "owner"}})
	client := fake.NewClientset()
	created, err := apply(ctx, client, desired)
	if !assert.Nil(t, err) {
		return
	}
	check(created)
	oldMD := old
	oldMD.SetName(md.GetName())
	oldMD.SetNamespace(md.GetNamespace())
	oldMD.SetResourceVersion("42")
	oldMD.SetLabels(map[string]string{"managed": "old", "external": "kept"})
	oldMD.SetAnnotations(map[string]string{"managed": "old", "external": "kept"})
	client = fake.NewClientset(old)
	updated, err := apply(ctx, client, desired)
	if !assert.Nil(t, err) {
		return
	}
	check(updated)
	updatedMD := updated
	assert.Equal(t, "42", updatedMD.GetResourceVersion())
	assert.Equal(t, map[string]string{"managed": "new", "external": "kept"}, updatedMD.GetLabels())
	assert.Equal(t, "new", updatedMD.GetAnnotations()["managed"])
	assert.Equal(t, "kept", updatedMD.GetAnnotations()["external"])
	assert.Equal(t, md.GetOwnerReferences(), updatedMD.GetOwnerReferences())
	assert.Equal(t, map[string]string{"managed": "new"}, md.GetLabels())
}

func TestCreateOrUpdateResources(t *testing.T) {
	t.Run("Deployment", func(t *testing.T) {
		want := &appsv1.Deployment{Spec: appsv1.DeploymentSpec{Template: k8scorev1.PodTemplateSpec{Spec: k8scorev1.PodSpec{Containers: []k8scorev1.Container{{Name: "app", Image: "new"}}}}}}
		testCreateOrUpdateResource(t, &appsv1.Deployment{}, want, CreateOrUpdateDeployment, func(got *appsv1.Deployment) { assert.Equal(t, want.Spec, got.Spec) })
	})
	t.Run("DaemonSet", func(t *testing.T) {
		want := &appsv1.DaemonSet{Spec: appsv1.DaemonSetSpec{MinReadySeconds: 12}}
		testCreateOrUpdateResource(t, &appsv1.DaemonSet{}, want, CreateOrUpdateDaemonset, func(got *appsv1.DaemonSet) { assert.Equal(t, want.Spec, got.Spec) })
	})
	t.Run("Service", func(t *testing.T) {
		want := &k8scorev1.Service{Spec: k8scorev1.ServiceSpec{Ports: []k8scorev1.ServicePort{{Port: 443}}, Selector: map[string]string{"app": "new"}, Type: k8scorev1.ServiceTypeClusterIP}}
		testCreateOrUpdateResource(t, &k8scorev1.Service{Spec: k8scorev1.ServiceSpec{ClusterIP: "10.0.0.1"}}, want, CreateOrUpdateService, func(got *k8scorev1.Service) {
			assert.Equal(t, want.Spec.Ports, got.Spec.Ports)
			assert.Equal(t, want.Spec.Selector, got.Spec.Selector)
			assert.Equal(t, want.Spec.Type, got.Spec.Type)
			if got.ResourceVersion != "" {
				assert.Equal(t, "10.0.0.1", got.Spec.ClusterIP)
			}
		})
	})
	t.Run("Secret", func(t *testing.T) {
		want := &k8scorev1.Secret{Type: k8scorev1.SecretTypeOpaque, Data: map[string][]byte{"key": []byte("new")}, StringData: map[string]string{"key2": "new"}}
		testCreateOrUpdateResource(t, &k8scorev1.Secret{}, want, CreateOrUpdateSecret, func(got *k8scorev1.Secret) {
			assert.Equal(t, want.Data, got.Data)
			assert.Equal(t, want.StringData, got.StringData)
			assert.Equal(t, want.Type, got.Type)
		})
	})
	t.Run("ConfigMap", func(t *testing.T) {
		want := &k8scorev1.ConfigMap{Data: map[string]string{"key": "new"}, BinaryData: map[string][]byte{"key2": []byte("new")}}
		testCreateOrUpdateResource(t, &k8scorev1.ConfigMap{}, want, CreateOrUpdateConfigMap, func(got *k8scorev1.ConfigMap) {
			assert.Equal(t, want.Data, got.Data)
			assert.Equal(t, want.BinaryData, got.BinaryData)
		})
	})
	t.Run("ServiceAccount", func(t *testing.T) {
		testCreateOrUpdateResource(t, &k8scorev1.ServiceAccount{Secrets: []k8scorev1.ObjectReference{{Name: "token"}}}, &k8scorev1.ServiceAccount{}, CreateOrUpdateServiceAccount, func(got *k8scorev1.ServiceAccount) {
			if got.ResourceVersion != "" {
				assert.Equal(t, []k8scorev1.ObjectReference{{Name: "token"}}, got.Secrets)
			}
		})
	})
	t.Run("NetworkPolicy", func(t *testing.T) {
		want := &networkingv1.NetworkPolicy{Spec: networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}}}
		testCreateOrUpdateResource(t, &networkingv1.NetworkPolicy{}, want, CreateOrUpdateNetworkPolicy, func(got *networkingv1.NetworkPolicy) { assert.Equal(t, want.Spec, got.Spec) })
	})
	t.Run("Ingress", func(t *testing.T) {
		want := &networkingv1.Ingress{Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{Host: "example.com"}}}}
		testCreateOrUpdateResource(t, &networkingv1.Ingress{}, want, CreateOrUpdateIngress, func(got *networkingv1.Ingress) { assert.Equal(t, want.Spec, got.Spec) })
	})
	t.Run("ClusterRole", func(t *testing.T) {
		want := &rbacv1.ClusterRole{Rules: []rbacv1.PolicyRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}}, AggregationRule: &rbacv1.AggregationRule{ClusterRoleSelectors: []k8smetav1.LabelSelector{{MatchLabels: map[string]string{"aggregate": "true"}}}}}
		testCreateOrUpdateResource(t, &rbacv1.ClusterRole{}, want, CreateOrUpdateClusterRole, func(got *rbacv1.ClusterRole) {
			assert.Equal(t, want.Rules, got.Rules)
			assert.Equal(t, want.AggregationRule, got.AggregationRule)
		})
	})
	t.Run("ClusterRoleBinding", func(t *testing.T) {
		want := &rbacv1.ClusterRoleBinding{RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "role"}, Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "service"}}}
		old := &rbacv1.ClusterRoleBinding{RoleRef: want.RoleRef}
		testCreateOrUpdateResource(t, old, want, CreateOrUpdateClusterRoleBinding, func(got *rbacv1.ClusterRoleBinding) {
			assert.Equal(t, want.Subjects, got.Subjects)
			assert.Equal(t, want.RoleRef, got.RoleRef)
		})
		old.RoleRef.Name = "old-role"
		client := fake.NewClientset(old)
		got, err := CreateOrUpdateClusterRoleBinding(context.Background(), client, want)
		assert.Nil(t, err)
		assert.Equal(t, want.RoleRef, got.RoleRef)
		assert.Equal(t, want.Subjects, got.Subjects)
	})
}

func TestRetryableCreateOrUpdate(t *testing.T) {
	previous := defaultRetryBackoff
	t.Cleanup(func() { defaultRetryBackoff = previous })
	defaultRetryBackoff = wait.Backoff{Steps: 3, Duration: time.Millisecond}
	resource := schema.GroupResource{Resource: "services"}
	transient := k8serr.NewServiceUnavailable("unavailable")
	conflict := k8serr.NewConflict(resource, "service", fmt.Errorf("conflict"))
	for _, stage := range []string{"Create", "Get", "Update", "NotFound", "Exhausted", "PermanentCreate", "PermanentGet", "PermanentUpdate"} {
		t.Run(stage, func(t *testing.T) {
			creates, gets, updates, modifies := 0, 0, 0, 0
			permanent := k8serr.NewBadRequest("invalid")
			result, err := retryableCreateOrUpdate(context.Background(),
				func(ctx context.Context) (int, error) {
					creates++
					if stage == "PermanentCreate" {
						return 0, permanent
					}
					if stage == "Exhausted" || stage == "Create" && creates == 1 {
						return 0, transient
					}
					if stage == "Create" || stage == "NotFound" && creates > 1 {
						return 42, nil
					}
					return 0, k8serr.NewAlreadyExists(resource, "service")
				},
				func(ctx context.Context) (int, error) {
					gets++
					if stage == "PermanentGet" {
						return 0, permanent
					}
					if stage == "Get" && gets == 1 {
						return 0, transient
					}
					if stage == "NotFound" {
						return 0, k8serr.NewNotFound(resource, "service")
					}
					return 41, nil
				},
				func(ctx context.Context, obj int) (int, error) {
					updates++
					assert.Equal(t, 41, obj)
					if stage == "PermanentUpdate" {
						return 0, permanent
					}
					if stage == "Update" && updates == 1 {
						return 0, conflict
					}
					return 42, nil
				}, func(obj int) { modifies++ })
			if stage == "Exhausted" {
				assert.ErrorIs(t, err, transient)
				assert.Equal(t, 3, creates)
			} else if stage == "PermanentCreate" || stage == "PermanentGet" || stage == "PermanentUpdate" {
				assert.ErrorIs(t, err, permanent)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, 42, result)
			}
			assert.Equal(t, updates, modifies)
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := retryableCreateOrUpdate(ctx, func(context.Context) (int, error) { return 0, transient }, nil, nil, nil)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestKubernetesRetryErrors(t *testing.T) {
	resource := schema.GroupResource{Resource: "services"}
	for _, err := range []error{k8serr.NewServerTimeout(resource, "get", 1), k8serr.NewTimeoutError("timeout", 1), k8serr.NewTooManyRequests("limited", 1)} {
		assert.True(t, isTransientError(err))
		assert.True(t, ShouldRetry(err))
	}
	for _, err := range []error{k8serr.NewInternalError(fmt.Errorf("failed")), k8serr.NewServiceUnavailable("unavailable")} {
		assert.True(t, isTransientError(err))
	}
	for _, err := range []error{nil, k8serr.NewBadRequest("invalid"), k8serr.NewNotFound(resource, "missing")} {
		assert.False(t, isTransientError(err))
		assert.False(t, ShouldRetry(err))
	}
	assert.True(t, ShouldRetry(k8serr.NewConflict(resource, "service", fmt.Errorf("conflict"))))
}

func TestDeploymentCalculations(t *testing.T) {
	for _, tc := range []struct {
		surge, unavailable                  intstr.IntOrString
		desired, wantSurge, wantUnavailable int32
	}{
		{intstr.FromString("25%"), intstr.FromString("25%"), 3, 1, 0},
		{intstr.FromInt32(0), intstr.FromString("1%"), 1, 0, 1},
		{intstr.FromInt32(2), intstr.FromInt32(1), 5, 2, 1},
	} {
		surge, unavailable, err := ResolveFenceposts(&tc.surge, &tc.unavailable, tc.desired)
		assert.Nil(t, err)
		assert.Equal(t, tc.wantSurge, surge)
		assert.Equal(t, tc.wantUnavailable, unavailable)
	}
	invalid := intstr.FromString("invalid")
	_, _, err := ResolveFenceposts(&invalid, nil, 1)
	assert.NotNil(t, err)
	_, _, err = ResolveFenceposts(nil, &invalid, 1)
	assert.NotNil(t, err)
	replicas := int32(3)
	maxUnavailable := intstr.FromInt32(5)
	dep := appsv1.Deployment{Spec: appsv1.DeploymentSpec{Replicas: &replicas, Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{MaxUnavailable: &maxUnavailable}}}}
	assert.EqualValues(t, 3, MaxUnavailable(dep))
	dep.Spec.Strategy.Type = appsv1.RecreateDeploymentStrategyType
	assert.Zero(t, MaxUnavailable(dep))
	dep.Spec.Strategy.Type = appsv1.RollingUpdateDeploymentStrategyType
	replicas = 0
	assert.Zero(t, MaxUnavailable(dep))
	sts := &appsv1.StatefulSet{Spec: appsv1.StatefulSetSpec{UpdateStrategy: appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType}}}
	assert.False(t, IsStatefulSetReady(sts))
	sts.Status.UpdatedReplicas = 1
	assert.False(t, IsStatefulSetReady(sts))
	sts.Status.ReadyReplicas = 1
	assert.True(t, IsStatefulSetReady(sts))
	replicas, partition := int32(3), int32(2)
	sts.Spec.Replicas = &replicas
	sts.Spec.UpdateStrategy.RollingUpdate = &appsv1.RollingUpdateStatefulSetStrategy{Partition: &partition}
	sts.Status.ReadyReplicas = 3
	assert.True(t, IsStatefulSetReady(sts))
	sts.Spec.UpdateStrategy.Type = appsv1.OnDeleteStatefulSetStrategyType
	assert.True(t, IsStatefulSetReady(sts))
}

func TestReplicaSetSelection(t *testing.T) {
	dep := &appsv1.Deployment{ObjectMeta: k8smetav1.ObjectMeta{Name: "deployment", Namespace: "namespace", UID: "deployment"}, Spec: appsv1.DeploymentSpec{
		Selector: &k8smetav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}},
		Template: k8scorev1.PodTemplateSpec{ObjectMeta: k8smetav1.ObjectMeta{Labels: map[string]string{"app": "test"}}},
	}}
	controller := true
	newRS := func(name string, createdAt time.Time, owner string) *appsv1.ReplicaSet {
		return &appsv1.ReplicaSet{ObjectMeta: k8smetav1.ObjectMeta{Name: name, Namespace: "namespace", CreationTimestamp: k8smetav1.NewTime(createdAt), Labels: map[string]string{"app": "test"}, OwnerReferences: []k8smetav1.OwnerReference{{UID: k8stypes.UID(owner), Controller: &controller}}}, Spec: appsv1.ReplicaSetSpec{Template: *dep.Spec.Template.DeepCopy()}}
	}
	first := newRS("first", time.Now().Add(-time.Hour), "deployment")
	first.OwnerReferences[0].UID = dep.UID
	second := newRS("second", first.CreationTimestamp.Time, "deployment")
	second.OwnerReferences[0].UID = dep.UID
	unowned := newRS("unowned", time.Now(), "other")
	client := fake.NewClientset(second, first, unowned)
	res, err := GetNewReplicaSet(dep, client.AppsV1())
	assert.Nil(t, err)
	assert.Equal(t, "first", res.Name)
	before := first.Spec.Template.DeepCopy()
	first.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey] = "hash"
	assert.True(t, EqualIgnoreHash(&first.Spec.Template, &dep.Spec.Template))
	assert.Equal(t, "hash", first.Spec.Template.Labels[appsv1.DefaultDeploymentUniqueLabelKey])
	first.Spec.Template.Spec.Containers = []k8scorev1.Container{{Name: "other"}}
	assert.False(t, EqualIgnoreHash(&first.Spec.Template, before))
	assert.Nil(t, FindNewReplicaSet(dep, []*appsv1.ReplicaSet{first}))
	_, err = ListReplicaSets(dep, func(string, k8smetav1.ListOptions) ([]*appsv1.ReplicaSet, error) {
		return nil, fmt.Errorf("list failed")
	})
	assert.NotNil(t, err)
}

func TestReadiness(t *testing.T) {
	previous := ldflags.TestMode
	t.Cleanup(func() { ldflags.TestMode = previous })
	ldflags.TestMode = "false"
	replicas := int32(1)
	controller := true
	dep := &appsv1.Deployment{ObjectMeta: k8smetav1.ObjectMeta{Name: "deployment", Namespace: "octelium", UID: "deployment"}, Spec: appsv1.DeploymentSpec{Replicas: &replicas, Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}, Selector: &k8smetav1.LabelSelector{MatchLabels: map[string]string{"app": "test"}}}}
	rs := &appsv1.ReplicaSet{ObjectMeta: k8smetav1.ObjectMeta{Name: "replicaset", Namespace: "octelium", Labels: map[string]string{"app": "test"}, OwnerReferences: []k8smetav1.OwnerReference{{UID: "deployment", Controller: &controller}}}, Status: appsv1.ReplicaSetStatus{ReadyReplicas: 1}}
	ds := &appsv1.DaemonSet{ObjectMeta: k8smetav1.ObjectMeta{Name: "daemonset", Namespace: "octelium"}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 2, NumberReady: 2}}
	node := &k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "node"}, Status: k8scorev1.NodeStatus{Conditions: []k8scorev1.NodeCondition{{Type: k8scorev1.NodeReady, Status: k8scorev1.ConditionTrue}}}}
	client := fake.NewClientset(dep, rs, ds, node)
	ctx := context.Background()
	assert.Nil(t, WaitReadinessDeployment(ctx, client, "deployment"))
	assert.Nil(t, WaitReadinessDaemonsetWithNS(ctx, client, "daemonset", "octelium"))
	assert.Nil(t, WaitForNodesReadiness(ctx, client))
	wantErr := k8serr.NewForbidden(schema.GroupResource{Resource: "deployments"}, "deployment", fmt.Errorf("denied"))
	client.PrependReactor("*", "*", func(action k8stesting.Action) (bool, runtime.Object, error) { return true, nil, wantErr })
	assert.ErrorIs(t, WaitReadinessDeployment(ctx, client, "deployment"), wantErr)
	assert.ErrorIs(t, WaitReadinessDaemonsetWithNS(ctx, client, "daemonset", "octelium"), wantErr)
	assert.ErrorIs(t, WaitForNodesReadiness(ctx, client), wantErr)
	ldflags.TestMode = "true"
	assert.Nil(t, WaitReadinessDeployment(ctx, client, "deployment"))
	assert.Nil(t, WaitReadinessDaemonsetWithNS(ctx, client, "daemonset", "octelium"))
	assert.Nil(t, WaitForNodesReadiness(ctx, client))
}

func TestKubeConfig(t *testing.T) {

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	validConf := `
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUMvakNDQWVhZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwcmRXSmwKY201bGRHVnpNQjRYRFRJek1ERXlNVEF5TXpVME5sb1hEVE16TURFeE9EQXlNelUwTmxvd0ZURVRNQkVHQTFVRQpBeE1LYTNWaVpYSnVaWFJsY3pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTUdZCkY1YmdqNmc2ZG9RUkE0bkNQaEoyK2NnOEcrZkFiY2NnWFZDWWw5cWFPZ29yczFMT29VTFphS0Ric2RvRTJWNUYKQmFYUHp0U2xiekVWZ1RNc2RJSGpaUU5VZU0yMlJWbWI3TmFGWGN2aUVHbjYyVU5RVHVDM0ZCVkcvWncyQU1VUwpkb2lEeXFBd1loMElRbHoydWhlb0dkSEU1dmgvRFVoQzJhK3h1Q1VFU1ZBWTRwMmdscmI4OTd5aVA5OGcxYWgyCk55MC9xYkY3NjJJMENreXVnMzRnYWtyYmZGSXJtU0ZubTdpVlN6S0NldExvaXFPakpLV2g2emlGUlBsVTY1MS8KbnJTa0dVckpwZDd5a2dsS25WQldjMXd5TlVxbDNJaC84cGtuVzhRY0UzQUpuSFlDbHJ0bndPdDRpc25GRHBtKwp2bmNlcVVRQTlQTzJBaHJCbmowQ0F3RUFBYU5aTUZjd0RnWURWUjBQQVFIL0JBUURBZ0trTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZIWEFBaTRpRGFjVVppcWJsc2x6bWdyQWZTZDZNQlVHQTFVZEVRUU8KTUF5Q0NtdDFZbVZ5Ym1WMFpYTXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRUNLL0xqSmxWcVR2WkcxTUt5Wgowck0xUVhaQm5YZHNaQjFmT3lBTVBnazJkL2libXh1emdpOXd2TWZ1SVZBekdHb1ZVY3E2dmtHODB2S3VSNjQzCnJSR3BJS0Z0VlZZNXZDN3NMUnpwNWtVTWpZN3dYUUxscFNEOTRXUkJKdTY0a0M4Wk54cFBXRFdFN1VMRTNtTnYKZjNubjF6NlQ4V2tzeSs0QnVjTCtlSU45U1ZqdWFGNkdXVjl0U1BDeDl0cks0R253alJJNUxUOElXNGtFVlZEQwp4ZjgzTnlNbEU3QlRnNVBkQ2I3bE9hczNwRlZrMExLQ09WLzBMMExINTZXdlVHUWY2dXhuSy9vRXRpUlBnUXM0ClBVNjBJWjZiYkJPMTBMN3FOaUNmdEdXR0FJRCtHYWRZZjhLNnlZL2VCd21tMFFiZkxHY3J6dFpINWJuWnNMRU8KdXNnPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    server: https://example.com:6443
  name: kubernetes
contexts:
- context:
    cluster: kubernetes
    user: kubernetes-admin
  name: kubernetes-admin@kubernetes
current-context: kubernetes-admin@kubernetes
kind: Config
preferences: {}
users:
- name: kubernetes-admin
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURJVENDQWdtZ0F3SUJBZ0lJWTVOWTJ6OVhZc0V3RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TXpBeE1qRXdNak0xTkRaYUZ3MHlOREF4TWpFd01qTTFORGxhTURReApGekFWQmdOVkJBb1REbk41YzNSbGJUcHRZWE4wWlhKek1Sa3dGd1lEVlFRREV4QnJkV0psY201bGRHVnpMV0ZrCmJXbHVNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXRlUXNJVG16M2dlc3h1ZkwKcnlBNjQyQm9TY21qNjg1eDB0LzdQbXg3OXZXMkJzWmcyZHRKOUF3K0QxVmJuRW5KaGZZcHNlZzBnZUhCVXRlKwo4czhCQVFSOU9HdEh3cWV0bVR0Qmh6MTE0WXFzMDg5RlI0SnJvWTQ0OXpwUmRRMFZrUWNhR29XU1dESzd5ZVhICjJrQUxkVm9uTS9KWktsdzBISE9hVWRPaEZaNzkveFlmc0ZhWVpOR3FjU2hjTlZ1T0MwRmE0SXc2YU8wSDRiMGMKeEI2NitmWVRYYkV3c2hGTWYya1hlZnRVeUNaRitiTEVvcUtIUUJCV09Nd2lqblpGdCtzRGk5QTYwM0k3Qk9mQwpiamdadEVZQW4zL3NsZkZHVTFLaWczQ3Z4VTVaUUFzaU8rVXlwdEtuUk8ySERheGNZOCs3TTRSdjZkcXFraDd2CjVmb1IzUUlEQVFBQm8xWXdWREFPQmdOVkhROEJBZjhFQkFNQ0JhQXdFd1lEVlIwbEJBd3dDZ1lJS3dZQkJRVUgKQXdJd0RBWURWUjBUQVFIL0JBSXdBREFmQmdOVkhTTUVHREFXZ0JSMXdBSXVJZzJuRkdZcW01YkpjNW9Ld0gwbgplakFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBZmZJL1hNcy9WVmc1R1ozbHZpQ090N2JRdjRNVER5b0VYN1ZoCm84YTUyRjNpVW1zbExwZGUxVm0rbTRMN3l6eFZRcmg5YmNBSk0yVnRXNmlOTis4RWtJQzVTeE9XTkpFWDFDZTQKaXU4THd3RGFCaFg2ZmdteEp6Z2N1cm1tNWdWT3Y0b2FBOUtndGNLb0l6STVSQWx3bS9iV2dTZ1NqUVpobU84Lwp4cVJVS1ZQenYzZHdUOWFjNkgvOEZ5bFpLTHIrRXltU0JxRWtMeVdJemsrT0tmM0pITUVtWTJIQjQvQXpqVzN4CkIzU0ZwcWwwWmtNczViYmVSUE9YeDMvV0NvZE8zbmlrYUVqU0I1am5GYmdUOUlqeUFsR1BmVzdCaFI4eE10UTkKYXhxcStrWHl6TjRMV2Jya2ZSYXVBQ3c3dnQvOEN5UTNOVDczeXpFeXh5ZlBXTEtZRUE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBdGVRc0lUbXozZ2VzeHVmTHJ5QTY0MkJvU2NtajY4NXgwdC83UG14Nzl2VzJCc1pnCjJkdEo5QXcrRDFWYm5FbkpoZllwc2VnMGdlSEJVdGUrOHM4QkFRUjlPR3RId3FldG1UdEJoejExNFlxczA4OUYKUjRKcm9ZNDQ5enBSZFEwVmtRY2FHb1dTV0RLN3llWEgya0FMZFZvbk0vSlpLbHcwSEhPYVVkT2hGWjc5L3hZZgpzRmFZWk5HcWNTaGNOVnVPQzBGYTRJdzZhTzBINGIwY3hCNjYrZllUWGJFd3NoRk1mMmtYZWZ0VXlDWkYrYkxFCm9xS0hRQkJXT013aWpuWkZ0K3NEaTlBNjAzSTdCT2ZDYmpnWnRFWUFuMy9zbGZGR1UxS2lnM0N2eFU1WlFBc2kKTytVeXB0S25STzJIRGF4Y1k4KzdNNFJ2NmRxcWtoN3Y1Zm9SM1FJREFRQUJBb0lCQUNJUFIvUXd5ZTJab2xEYwp0dGRrUWFLeU90VVdYUXVhN05WLys1d0UxSEc2TVF1enVnOFJjUmV4OHkwTDNzdTFSWGRBVVM1dlBPWFZVRTRpCitDNmZkS0NzSm9hYUVDWHpJQjdCYWRQWlBtbXRmZzlya0oyRFhvUXlEWmk5NHVMNFFFR1lBdHRVaDhMY1BTM2gKU1RzbEl3QW1rWkM0b05tOXlrUkpvV3dSSk9qWFBBV0xiMG1kU05ucWtnaVBjTEdDMUhuZkExdGM2c1hmVCtYawpiYkg1TndsUHQ2K1d2S3A3dkhnKzNySnJIcTZzVTFDSnY0Mm9CdHJ1NUNUd3ZMRWVXRmFaMzBnczZUZlMrM3JYCkozWVQrV1pXVmdWTll1Ymw0cDA2YjJ1dGVaNlhvUjFIMVJVTFZEU2xiUC83Mzh6Sk11WmVwTHJXNXF1Y0N6cEUKK0R2TG5FRUNnWUVBMnpZMW1ZRFVnd2dEb0lwdjRlOE8rSEE0RUVkSXdWeFhSaG9uL0pmc2hDL2h5My9XaGU2QQovUjRGRFFROWNPamxzZjQ1NEFqaVQvV2MvRko3WHF4a2hJSC9SYmQ2NC9HTWIvMzVIRGtBY3J4dFNGeitDRnROCmdmalR0WjAzMENhYnJUdlY2Z202WWJzNk4rbHlyLysxWmV3WmJDNEl4aG15R0h3TjBaeXpSME1DZ1lFQTFHcVoKVks2K3h4eFE5YzlUZkpkVXpiOVlIbE1xcFdIUnR2MlFDMWh4Y1NWa0I4d3lockVIL050UU5DZHZib1BuYTZsdApOWTArU1VDbXhVc0M5cE84eDhobUhKT3BhM29zMFJTUHo2Y2dvaFNPWFpEZkxPYXVQOGhkODhmcC9taVorcTdwCkVqWXA5S0pNb3FVT3RDbDZ6c0ljTmNwL1RhUUxZK1QvdGMwSTRGOENnWUFnNW1Ycy8vVGxKWkxGeVlFNU81UFgKbmFBTWNXWnQvdG5xWDRxWTBvUmc0bjdVOS83T1l4bGc0OXlHTTVpMUZYOUQwNUFFRzlFN2h2Vmt1VXhpelNUWQo3bG5Oc05mMDFnL3B6d2hRUUEzZEtvS01WY2lhb0hsbGhGN2g1eEsxWHRZR2pmQnhDN3k1Wmt3NmtBTHlmMEpPClpiejdDMzJ0bmJXcER4VlQzRnpiMlFLQmdRRExLMXFWSUw3Zyt6aUVwRlVhS2pTMnhubW1KNjMybVdWWlBaWDEKQkJjZFBjSTdveGdBdEhzTFkwbUhXT0RBTi9HMWpFd2ttSUFtMkd1cThXQllNRjYwUi8xREFBbGYvMisyVzVCaAo4VnpKS2hneGJrdklTcXdIM2NIZlZpdDladGRBYXVRS3d6dkYvU2FIdXBBaHlqcm9YOGxUdWVlaGYzSlZqY2IzClFMRm95UUtCZ1FEVVlUdjZLOVFnR1lNWXVib1VXZTJBRWV6QTVvcXo1Rm01aEFIS2tGVnp5WVcwUGJuMXR5NUoKOTAySElDRXY5NGVCWEVvS1NWZVVyT3ZMbFpXc2J1VER4aFo0Q1dFMzRUaGwvMzQ0S3VnNnJLNEFJTG81a05pLwpjWVBRTjZ2Z3hpOElQR1FncjRDQU5xd3NXcFJ6RjRMazdBTjNvSENodjRtZHprRGdVYm54bFE9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
`

	res, err := UnmarshalKubeConfigFromYAML([]byte(validConf))
	assert.Nil(t, err)

	zap.L().Debug("kubeconfig", zap.Any("val", res))

	context := res.GetContext("")
	assert.NotNil(t, context)

	assert.Equal(t, "kubernetes", res.GetCluster("").Name)
}
