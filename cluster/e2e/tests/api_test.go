//go:build e2e

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

package tests

import (
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/e2e/harness"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAdminAPI(t *testing.T, h *harness.H) {
	ctx := t.Context()
	c := h.CoreC()

	t.Run("Read", func(t *testing.T) {
		_, err := c.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
		assert.Nil(t, err)

		_, err = c.GetService(ctx, &metav1.GetOptions{Name: "demo-nginx.default"})
		assert.Nil(t, err)

		itmList, err := c.ListService(ctx, &corev1.ListServiceOptions{})
		require.Nil(t, err)
		assert.True(t, len(itmList.Items) > 0)

		for _, svc := range itmList.Items {
			assert.NotNil(t, svc.Status.RegionRef)
			assert.NotNil(t, svc.Status.NamespaceRef)
			assert.True(t, len(svc.Status.Addresses) > 0)
			assert.True(t, svc.Status.Port > 0)
		}
	})

	t.Run("SystemResourcesProtected", func(t *testing.T) {
		for _, name := range []string{
			"default.octelium-api",
			"auth.octelium-api",
			"default.default",
			"dns.octelium",
			"portal.default",
		} {
			_, err := c.DeleteService(ctx, &metav1.DeleteOptions{Name: name})
			assert.True(t, grpcerr.IsUnauthorized(err),
				"deleting the system Service %s should be unauthorized, got: %+v", name, err)
		}

		for _, name := range []string{"default", "octelium", "octelium-api"} {
			_, err := c.DeleteNamespace(ctx, &metav1.DeleteOptions{Name: name})
			assert.True(t, grpcerr.IsUnauthorized(err),
				"deleting the system Namespace %s should be unauthorized, got: %+v", name, err)
		}

		_, err := c.DeleteUser(ctx, &metav1.DeleteOptions{Name: "octelium"})
		assert.True(t, grpcerr.IsUnauthorized(err),
			"deleting the system User should be unauthorized, got: %+v", err)
	})

	t.Run("DeleteInitCredential", func(t *testing.T) {
		_, err := c.DeleteCredential(ctx, &metav1.DeleteOptions{Name: "root-init"})
		assert.Nil(t, err)
	})
}
