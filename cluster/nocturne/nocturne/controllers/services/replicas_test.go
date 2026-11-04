package svccontroller

import (
	"context"
	"fmt"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/k8sutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestServiceReplicaOwnership(t *testing.T) {
	for _, replicas := range []int32{0, 3} {
		t.Run(fmt.Sprint(replicas), func(t *testing.T) {
			t.Setenv("OCTELIUM_REGION_NAME", "default")
			svc := newTstService()
			client := fake.NewSimpleClientset()
			core := &fakeCoreC{getService: func(context.Context, *rmetav1.GetOptions) (*corev1.Service, error) {
				return proto.Clone(svc).(*corev1.Service), nil
			}}
			controller := NewController(&fakeOcteliumC{coreC: core}, client)
			require.NoError(t, controller.OnAdd(t.Context(), svc))
			deployment, err := client.AppsV1().Deployments(ns).Get(t.Context(), k8sutils.GetSvcHostname(svc), metav1.GetOptions{})
			require.NoError(t, err)
			deployment.Spec.Replicas = new(replicas)
			_, err = client.AppsV1().Deployments(ns).Update(t.Context(), deployment, metav1.UpdateOptions{})
			require.NoError(t, err)
			for range 2 {
				require.NoError(t, controller.OnUpdate(t.Context(), svc, svc))
				current, err := client.AppsV1().Deployments(ns).Get(t.Context(), deployment.Name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, new(replicas), current.Spec.Replicas)
			}
			for _, count := range []uint32{4, 1} {
				svc.Spec.Deployment = &corev1.Service_Spec_Deployment{Replicas: count}
				require.NoError(t, controller.OnUpdate(t.Context(), svc, svc))
				current, err := client.AppsV1().Deployments(ns).Get(t.Context(), deployment.Name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, new(int32(count)), current.Spec.Replicas)
			}
		})
	}
}

func TestContainerUpstreamReplicaOwnership(t *testing.T) {
	for _, replicas := range []int32{0, 3} {
		t.Run(fmt.Sprint(replicas), func(t *testing.T) {
			svc := newTstService()
			svc.Spec.Config = newTstContainerConfig("default")
			client := fake.NewSimpleClientset()
			controller := NewController(nil, client)
			owner := controller.getOwnerConfigMap(svc)
			require.NoError(t, controller.setK8sUpstream(t.Context(), svc, owner))
			deployment, err := client.AppsV1().Deployments(ns).Get(t.Context(), k8sutils.GetSvcK8sUpstreamHostname(svc, "default"), metav1.GetOptions{})
			require.NoError(t, err)
			deployment.Spec.Replicas = new(replicas)
			_, err = client.AppsV1().Deployments(ns).Update(t.Context(), deployment, metav1.UpdateOptions{})
			require.NoError(t, err)
			for range 2 {
				require.NoError(t, controller.setK8sUpstream(t.Context(), svc, owner))
				current, err := client.AppsV1().Deployments(ns).Get(t.Context(), deployment.Name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, new(replicas), current.Spec.Replicas)
			}
			for _, count := range []uint32{4, 1} {
				svc.Spec.Config.Upstream.GetContainer().Replicas = count
				require.NoError(t, controller.setK8sUpstream(t.Context(), svc, owner))
				current, err := client.AppsV1().Deployments(ns).Get(t.Context(), deployment.Name, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, new(int32(count)), current.Spec.Replicas)
			}
		})
	}
}
