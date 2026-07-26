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

package user

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestListNamespace(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	usrSrv, adminSrv := newFakeServers(tst.C)

	usrT, err := tstuser.NewUser(tst.C.OcteliumC, adminSrv, usrSrv, nil)
	assert.Nil(t, err, "%+v", err)

	{
		itemList, err := usrSrv.ListNamespace(usrT.Ctx(), &userv1.ListNamespaceOptions{})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "user/v1", itemList.ApiVersion)
		assert.Equal(t, "NamespaceList", itemList.Kind)
		assert.NotNil(t, itemList.ListResponseMeta)
	}

	ns, err := adminSrv.CreateNamespace(ctx, &corev1.Namespace{
		Metadata: &metav1.Metadata{
			Name:        utilrand.GetRandomStringCanonical(8),
			DisplayName: "My Namespace",
			Description: "My description",
			Labels: map[string]string{
				"key": "val",
			},
		},
		Spec: &corev1.Namespace_Spec{},
	})
	assert.Nil(t, err, "%+v", err)

	{
		itemList, err := usrSrv.ListNamespace(usrT.Ctx(), &userv1.ListNamespaceOptions{})
		assert.Nil(t, err, "%+v", err)

		var found *userv1.Namespace
		for _, itm := range itemList.Items {
			assert.NotNil(t, itm.Spec)
			assert.NotNil(t, itm.Status)
			assert.NotEmpty(t, itm.Metadata.Uid)
			assert.NotEmpty(t, itm.Metadata.Name)

			if itm.Metadata.Uid == ns.Metadata.Uid {
				found = itm
			}
		}

		assert.NotNil(t, found)
		assert.Equal(t, ns.Metadata.Name, found.Metadata.Name)
		assert.Equal(t, "My Namespace", found.Metadata.DisplayName)
		assert.Equal(t, "My description", found.Metadata.Description)
		assert.Nil(t, found.Metadata.Labels)
	}

	{
		nsList, err := tst.C.OcteliumC.CoreC().ListNamespace(ctx, nil)
		assert.Nil(t, err, "%+v", err)

		itemList, err := usrSrv.ListNamespace(usrT.Ctx(), &userv1.ListNamespaceOptions{})
		assert.Nil(t, err, "%+v", err)

		assert.True(t, len(itemList.Items) <= len(nsList.Items))
	}

	{
		_, err = adminSrv.DeleteNamespace(ctx, &metav1.DeleteOptions{Uid: ns.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)

		itemList, err := usrSrv.ListNamespace(usrT.Ctx(), &userv1.ListNamespaceOptions{})
		assert.Nil(t, err, "%+v", err)

		for _, itm := range itemList.Items {
			assert.NotEqual(t, ns.Metadata.Uid, itm.Metadata.Uid)
		}
	}
}
