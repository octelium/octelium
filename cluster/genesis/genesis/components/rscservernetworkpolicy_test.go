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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
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

	for _, tc := range []struct {
		groupVersion, kind string
		supported          bool
	}{
		{"cilium.io/v2", "CiliumNetworkPolicy", true},
		{"cilium.io/v2", "CiliumClusterwideNetworkPolicy", false},
		{"projectcalico.org/v3", "NetworkPolicy", false},
	} {
		supported, err := hasPolicyAPI(t.Context(), k8sC.Discovery(), tc.groupVersion, tc.kind)
		require.NoError(t, err)
		assert.Equal(t, tc.supported, supported)
	}
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

func TestPolicyDiscoveryRetryHTTP(t *testing.T) {
	for _, stage := range []string{"transient", "forbidden", "stalled"} {
		t.Run(stage, func(t *testing.T) {
			var mu sync.Mutex
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				calls++
				n := calls
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				assert.Equal(t, "/apis/cilium.io/v2", r.URL.Path)
				if stage == "stalled" {
					<-r.Context().Done()
					return
				}
				if stage == "forbidden" || n == 1 {
					code, reason := http.StatusServiceUnavailable, metav1.StatusReasonServiceUnavailable
					if stage == "forbidden" {
						code, reason = http.StatusForbidden, metav1.StatusReasonForbidden
					}
					w.WriteHeader(code)
					json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: reason, Code: int32(code)})
					return
				}
				json.NewEncoder(w).Encode(&metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"}, GroupVersion: "cilium.io/v2", APIResources: []metav1.APIResource{{Name: "ciliumnetworkpolicies", Kind: "CiliumNetworkPolicy"}}})
			}))
			t.Cleanup(server.Close)
			c, err := discovery.NewDiscoveryClientForConfig(&rest.Config{Host: server.URL, QPS: -1})
			require.NoError(t, err)
			timeout := 3 * time.Second
			if stage == "stalled" {
				timeout = 80 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			supported, err := hasPolicyAPI(ctx, c, "cilium.io/v2", "CiliumNetworkPolicy")
			switch stage {
			case "transient":
				require.NoError(t, err)
				assert.True(t, supported)
			case "forbidden":
				require.True(t, k8serr.IsForbidden(err), "%v", err)
				assert.False(t, supported)
			case "stalled":
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
		})
	}
}

func TestCiliumPolicyUncertainWritesHTTP(t *testing.T) {
	for _, stage := range []string{"create-before", "create-after", "update-before", "update-after"} {
		t.Run(stage, func(t *testing.T) {
			var mu sync.Mutex
			var stored *ciliumv2.CiliumNetworkPolicy
			if stage == "update-before" || stage == "update-after" {
				stored = getRscServerCiliumNetworkPolicy()
				stored.UID, stored.ResourceVersion = "original", "1"
				stored.TypeMeta = metav1.TypeMeta{Kind: "CiliumNetworkPolicy", APIVersion: "cilium.io/v2"}
				stored.Spec.Ingress = nil
			}
			failed := false
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet {
					if stored == nil {
						w.WriteHeader(http.StatusNotFound)
						json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: metav1.StatusReasonNotFound, Code: http.StatusNotFound})
						return
					}
					json.NewEncoder(w).Encode(stored)
					return
				}
				writes++
				input := &ciliumv2.CiliumNetworkPolicy{}
				if !assert.NoError(t, json.NewDecoder(r.Body).Decode(input)) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if !failed && (stage == "create-before" || stage == "update-before") {
					failed = true
					w.WriteHeader(http.StatusServiceUnavailable)
					json.NewEncoder(w).Encode(&metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: "Failure", Reason: metav1.StatusReasonServiceUnavailable, Code: http.StatusServiceUnavailable})
					return
				}
				input.UID, input.ResourceVersion = "original", "2"
				input.TypeMeta = metav1.TypeMeta{Kind: "CiliumNetworkPolicy", APIVersion: "cilium.io/v2"}
				stored = input
				if !failed {
					failed = true
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						conn.Close()
					}
					return
				}
				json.NewEncoder(w).Encode(stored)
			}))
			t.Cleanup(server.Close)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			require.NoError(t, setNetworkPolicyCilium(ctx, &rest.Config{Host: server.URL, QPS: -1, ContentConfig: rest.ContentConfig{ContentType: "application/json"}}))
			mu.Lock()
			defer mu.Unlock()
			assert.True(t, failed)
			require.NotNil(t, stored)
			assert.NotEmpty(t, stored.Spec.Ingress)
			if stage == "create-after" || stage == "update-after" {
				assert.Equal(t, 1, writes)
			}
		})
	}
}
