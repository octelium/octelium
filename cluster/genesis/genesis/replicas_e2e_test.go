package genesis

import (
	"testing"

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/genesis/genesis/components"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestScaledClusterUpgradesPreserveReplicasE2E(t *testing.T) {
	f := newInitializationFixture(t)
	require.NoError(t, f.genesis.RunInit(t.Context(), nil))
	cc, err := f.genesis.octeliumC.CoreV1Utils().GetClusterConfig(t.Context())
	require.NoError(t, err)
	region, err := f.genesis.octeliumC.CoreC().GetRegion(t.Context(), &rmetav1.GetOptions{Name: "default"})
	require.NoError(t, err)
	require.NoError(t, components.CreateRscServer(t.Context(), &components.CommonOpts{K8sC: f.client.K8sC, ClusterConfig: cc, Region: region}))
	counts := map[string]int32{"octelium-rscserver": 3, "octelium-nocturne": 0, "octelium-octovigil": 4, "octelium-ingress": 2, "octelium-ingress-dataplane": 5}
	identities := make(map[string]types.UID)
	for name, count := range counts {
		deployment, err := f.client.K8sC.AppsV1().Deployments(vutils.K8sNS).Get(t.Context(), name, metav1.GetOptions{})
		require.NoError(t, err)
		deployment.UID = types.UID("existing-" + name)
		deployment.Spec.Replicas = new(count)
		deployment.Spec.Template.Spec.Containers[0].Image = "previous-release"
		deployment, err = f.client.K8sC.AppsV1().Deployments(vutils.K8sNS).Update(t.Context(), deployment, metav1.UpdateOptions{})
		require.NoError(t, err)
		identities[name] = deployment.UID
	}
	keys := initializationSecrets(t, f.db)
	for range 2 {
		require.NoError(t, f.genesis.RunUpgrade(t.Context(), nil))
		for name, count := range counts {
			deployment, err := f.client.K8sC.AppsV1().Deployments(vutils.K8sNS).Get(t.Context(), name, metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, new(count), deployment.Spec.Replicas, name)
			assert.Equal(t, identities[name], deployment.UID, name)
			assert.NotEqual(t, "previous-release", deployment.Spec.Template.Spec.Containers[0].Image, name)
		}
		assert.Equal(t, keys, initializationSecrets(t, f.db))
	}
	f.checkPreserved(t)
}
