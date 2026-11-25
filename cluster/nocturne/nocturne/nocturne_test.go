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

package nocturne

import (
	"testing"

	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInformerFactoriesAreNamespaced(t *testing.T) {
	client := fake.NewClientset(
		&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "cert-cluster", Namespace: vutils.K8sNS}},
		&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "vault-unseal", Namespace: "vault"}},
		&k8scorev1.Pod{ObjectMeta: k8smetav1.ObjectMeta{Name: "svc", Namespace: vutils.K8sNS}},
		&k8scorev1.Pod{ObjectMeta: k8smetav1.ObjectMeta{Name: "tenant", Namespace: "tenant"}},
		&k8scorev1.Service{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-ingress-dataplane", Namespace: vutils.K8sNS}},
		&k8scorev1.Service{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-ingress-dataplane", Namespace: "tenant"}},
		&k8scorev1.Node{ObjectMeta: k8smetav1.ObjectMeta{Name: "node"}},
	)

	kubeInformerFactory, nodeInformerFactory := newInformerFactories(client)
	secretInformer := kubeInformerFactory.Core().V1().Secrets()
	podInformer := kubeInformerFactory.Core().V1().Pods()
	serviceInformer := kubeInformerFactory.Core().V1().Services()
	nodeInformer := nodeInformerFactory.Core().V1().Nodes()
	secretInformer.Informer()
	podInformer.Informer()
	serviceInformer.Informer()
	nodeInformer.Informer()

	stopCh := make(chan struct{})
	t.Cleanup(func() {
		close(stopCh)
		kubeInformerFactory.Shutdown()
		nodeInformerFactory.Shutdown()
	})
	kubeInformerFactory.Start(stopCh)
	nodeInformerFactory.Start(stopCh)
	for _, synced := range kubeInformerFactory.WaitForCacheSync(stopCh) {
		require.True(t, synced)
	}
	for _, synced := range nodeInformerFactory.WaitForCacheSync(stopCh) {
		require.True(t, synced)
	}

	for _, action := range client.Actions() {
		switch action.GetResource().Resource {
		case "nodes":
			assert.Empty(t, action.GetNamespace())
		default:
			assert.Equal(t, vutils.K8sNS, action.GetNamespace(), "%s %s", action.GetVerb(), action.GetResource().Resource)
		}
	}

	secrets, err := secretInformer.Lister().List(labels.Everything())
	require.NoError(t, err)
	require.Len(t, secrets, 1)
	assert.Equal(t, vutils.K8sNS, secrets[0].Namespace)

	pods, err := podInformer.Lister().List(labels.Everything())
	require.NoError(t, err)
	require.Len(t, pods, 1)
	assert.Equal(t, vutils.K8sNS, pods[0].Namespace)

	services, err := serviceInformer.Lister().List(labels.Everything())
	require.NoError(t, err)
	require.Len(t, services, 1)
	assert.Equal(t, vutils.K8sNS, services[0].Namespace)

	nodes, err := nodeInformer.Lister().List(labels.Everything())
	require.NoError(t, err)
	assert.Len(t, nodes, 1)
}
