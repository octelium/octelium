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

package suite

import (
	"fmt"
	"testing"

	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type k8sAccess struct {
	namespace   string
	verb        string
	group       string
	resource    string
	subresource string
	allowed     bool
}

func checkK8sAccess(t *testing.T, h *harness.H, serviceAccount string, checks []k8sAccess) {
	t.Helper()

	user := fmt.Sprintf("system:serviceaccount:%s:%s", vutils.K8sNS, serviceAccount)
	for _, itm := range checks {
		review, err := h.K8sC().AuthorizationV1().SubjectAccessReviews().Create(t.Context(), &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   user,
				Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + vutils.K8sNS, "system:authenticated"},
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   itm.namespace,
					Verb:        itm.verb,
					Group:       itm.group,
					Resource:    itm.resource,
					Subresource: itm.subresource,
				},
			},
		}, k8smetav1.CreateOptions{})
		require.NoError(t, err)
		assert.Equal(t, itm.allowed, review.Status.Allowed, "%s %s %s/%s in namespace %q",
			serviceAccount, itm.verb, itm.resource, itm.subresource, itm.namespace)
	}
}

func testKubernetesPermissions(t *testing.T, h *harness.H) {
	t.Run("NocturneRunsWithItsRuntimeServiceAccount", func(t *testing.T) {
		dep := h.MustK8sDeployment(t, "octelium-nocturne")
		assert.Equal(t, "octelium-nocturne-runtime", dep.Spec.Template.Spec.ServiceAccountName)
	})

	t.Run("NocturneRuntimeIsNamespaced", func(t *testing.T) {
		checkK8sAccess(t, h, "octelium-nocturne-runtime", []k8sAccess{
			{namespace: vutils.K8sNS, verb: "list", resource: "pods", allowed: true},
			{namespace: vutils.K8sNS, verb: "watch", resource: "secrets", allowed: true},
			{namespace: vutils.K8sNS, verb: "watch", resource: "services", allowed: true},
			{namespace: vutils.K8sNS, verb: "create", group: "apps", resource: "deployments", allowed: true},
			{namespace: vutils.K8sNS, verb: "delete", resource: "secrets", allowed: true},
			{namespace: vutils.K8sNS, verb: "update", resource: "configmaps", subresource: "finalizers", allowed: true},
			{verb: "watch", resource: "nodes", allowed: true},
			{verb: "update", resource: "nodes", allowed: true},

			{verb: "list", resource: "secrets"},
			{verb: "list", resource: "pods"},
			{namespace: "kube-system", verb: "get", resource: "secrets"},
			{namespace: "default", verb: "list", resource: "secrets"},
			{namespace: "kube-system", verb: "update", resource: "pods"},
			{namespace: vutils.K8sNS, verb: "create", resource: "pods"},
			{namespace: vutils.K8sNS, verb: "create", resource: "pods", subresource: "exec"},
			{namespace: vutils.K8sNS, verb: "create", resource: "serviceaccounts", subresource: "token"},
			{namespace: vutils.K8sNS, verb: "create", group: "batch", resource: "jobs"},
			{namespace: vutils.K8sNS, verb: "create", group: "apps", resource: "daemonsets"},
			{namespace: vutils.K8sNS, verb: "create", group: "rbac.authorization.k8s.io", resource: "rolebindings"},
			{verb: "create", group: "rbac.authorization.k8s.io", resource: "clusterrolebindings"},
			{verb: "impersonate", resource: "users"},
			{verb: "delete", resource: "nodes"},
			{verb: "update", resource: "nodes", subresource: "status"},
			{verb: "create", resource: "namespaces"},
		})
	})

	t.Run("GatewayAgentCannotUpdatePods", func(t *testing.T) {
		checkK8sAccess(t, h, "octelium-gwagent", []k8sAccess{
			{verb: "update", resource: "nodes", allowed: true},
			{verb: "update", resource: "pods"},
			{namespace: "kube-system", verb: "update", resource: "pods"},
			{verb: "list", resource: "secrets"},
		})
	})

	t.Run("GenesisInstallerIdentity", func(t *testing.T) {
		_, err := h.K8sC().CoreV1().ServiceAccounts(vutils.K8sNS).Get(t.Context(), "octelium-genesis", k8smetav1.GetOptions{})
		require.NoError(t, err)
		checkK8sAccess(t, h, "octelium-genesis", []k8sAccess{
			{verb: "create", group: "rbac.authorization.k8s.io", resource: "clusterrolebindings", allowed: true},
			{verb: "list", resource: "secrets", allowed: true},
		})
	})
}
