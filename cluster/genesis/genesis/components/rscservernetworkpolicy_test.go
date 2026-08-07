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

package components

import (
	"context"
	"testing"

	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/stretchr/testify/assert"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakek8s "k8s.io/client-go/kubernetes/fake"
)

func TestHasPolicyAPI(t *testing.T) {

	k8sC := fakek8s.NewSimpleClientset()
	k8sC.Resources = []*metav1.APIResourceList{
		{
			GroupVersion: "cilium.io/v2",
			APIResources: []metav1.APIResource{
				{Name: "ciliumnetworkpolicies", Kind: "CiliumNetworkPolicy"},
			},
		},
	}

	assert.True(t, hasPolicyAPI(k8sC.Discovery(), "cilium.io/v2", "CiliumNetworkPolicy"))
	assert.False(t, hasPolicyAPI(k8sC.Discovery(), "cilium.io/v2", "CiliumClusterwideNetworkPolicy"))
	assert.False(t, hasPolicyAPI(k8sC.Discovery(), "projectcalico.org/v3", "NetworkPolicy"))
}

func TestDetectCNI(t *testing.T) {

	ctx := context.Background()

	genDaemonSet := func(name, ns string) *appsv1.DaemonSet {
		return &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		}
	}

	detect := func(dss ...*appsv1.DaemonSet) string {
		var objs []runtime.Object
		for _, ds := range dss {
			objs = append(objs, ds)
		}

		ret, err := detectCNI(ctx, &CommonOpts{K8sC: fakek8s.NewSimpleClientset(objs...)})
		assert.Nil(t, err, "%+v", err)
		return ret
	}

	assert.Equal(t, "cilium", detect(genDaemonSet("cilium", "kube-system")))
	assert.Equal(t, "calico", detect(genDaemonSet("calico-node", "calico-system")))

	assert.Equal(t, "", detect(genDaemonSet("anetd", "kube-system")))

	assert.Equal(t, "", detect())

	assert.Equal(t, "", detect(
		genDaemonSet("cilium", "kube-system"),
		genDaemonSet("calico-node", "kube-system"),
	))
	assert.Equal(t, "", detect(
		genDaemonSet("calico-node", "kube-system"),
		genDaemonSet("cilium", "kube-system"),
	))
}

func TestGetRscServerCiliumNetworkPolicy(t *testing.T) {

	policy := getRscServerCiliumNetworkPolicy()

	assert.Equal(t, "octelium-rscserver", policy.Name)
	assert.Equal(t, vutils.K8sNS, policy.Namespace)

	assert.Equal(t, getComponentLabels(componentRscServer),
		policy.Spec.EndpointSelector.LabelSelector.MatchLabels)

	assert.Len(t, policy.Spec.Ingress, 1)
	ingress := policy.Spec.Ingress[0]

	assert.Contains(t, ingress.FromEntities, api.EntityHost)
	assert.Contains(t, ingress.FromEntities, api.EntityRemoteNode)

	var namespaces []string
	for _, sel := range ingress.FromEndpoints {
		assert.Equal(t, "octelium", sel.LabelSelector.MatchLabels["app"])
		namespaces = append(namespaces,
			sel.LabelSelector.MatchLabels["io.kubernetes.pod.namespace"])
	}
	assert.ElementsMatch(t, []string{vutils.K8sNS, "default"}, namespaces)

	assert.Len(t, ingress.ToPorts, 1)
	assert.Equal(t, api.PortProtocol{Port: "8080", Protocol: api.ProtoTCP},
		ingress.ToPorts[0].Ports[0])
}
