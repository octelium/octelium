package components

import (
	"context"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestComponentUpgradesPreserveReplicaCounts(t *testing.T) {
	for _, count := range []int32{0, 1, 3} {
		for _, component := range []struct {
			name        string
			install     func(context.Context, *CommonOpts) error
			deployments []func(*CommonOpts) *appsv1.Deployment
		}{
			{name: "rscserver", install: CreateRscServer, deployments: []func(*CommonOpts) *appsv1.Deployment{getRscServerDeployment}},
			{name: "nocturne", install: CreateNocturne, deployments: []func(*CommonOpts) *appsv1.Deployment{getNocturneDeployment}},
			{name: "octovigil", install: CreateOctovigil, deployments: []func(*CommonOpts) *appsv1.Deployment{getOctovigilDeployment}},
			{name: "ingress", install: CreateIngress, deployments: []func(*CommonOpts) *appsv1.Deployment{getIngressDeployment, getIngressDataPlaneDeployment}},
		} {
			t.Run(fmt.Sprintf("%s/%d", component.name, count), func(t *testing.T) {
				client := fake.NewSimpleClientset()
				opts := &CommonOpts{
					K8sC:          client,
					ClusterConfig: &corev1.ClusterConfig{Metadata: &metav1.Metadata{Name: "default", Uid: "cluster-uid"}, Spec: &corev1.ClusterConfig_Spec{}, Status: &corev1.ClusterConfig_Status{Domain: "example.com"}},
					Region:        &corev1.Region{Metadata: &metav1.Metadata{Name: "default", Uid: "region-uid"}, Spec: &corev1.Region_Spec{}, Status: &corev1.Region_Status{}},
				}
				for _, get := range component.deployments {
					previous := get(opts)
					require.Nil(t, previous.Spec.Replicas)
					previous.UID = types.UID("existing-" + previous.Name)
					previous.ResourceVersion = "1"
					previous.Spec.Replicas = new(count)
					previous.Spec.Template.Spec.Containers[0].Image = "previous-release"
					require.NoError(t, client.Tracker().Add(previous))
				}
				for range 2 {
					require.NoError(t, component.install(t.Context(), opts))
					for _, get := range component.deployments {
						desired := get(opts)
						current, err := client.AppsV1().Deployments(desired.Namespace).Get(t.Context(), desired.Name, k8smetav1.GetOptions{})
						require.NoError(t, err)
						assert.Equal(t, new(count), current.Spec.Replicas)
						assert.Equal(t, types.UID("existing-"+desired.Name), current.UID)
						assert.Equal(t, desired.Spec.Template.Spec.Containers[0].Image, current.Spec.Template.Spec.Containers[0].Image)
						assert.Nil(t, desired.Spec.Replicas)
					}
				}
			})
		}
	}
}
