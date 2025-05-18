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

package admin

import (
	"context"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

/*
func TestDeleteSystemGroups(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	systemGroups := []string{"root", "admin"}
	for _, g := range systemGroups {
		_, err := srv.DeleteGroup(ctx, &rmetav1.DeleteOptions{Name: g})
		assert.NotNilf(t, err, "system group %s deleted", g)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
	}
}*/

func TestCreateGroup(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	validGroups := []*corev1.Group{
		{
			Metadata: &metav1.Metadata{
				Name: "group-1",
			},
			Spec: &corev1.Group_Spec{},
		},
	}

	for _, grp := range validGroups {

		outGrp, err := srv.CreateGroup(ctx, grp)
		assert.Nil(t, err)

		_, err = srv.octeliumC.CoreC().GetGroup(ctx, &rmetav1.GetOptions{Uid: outGrp.Metadata.Uid})
		assert.Nil(t, err)

		assert.True(t, proto.Equal(grp.Spec, outGrp.Spec))
	}

}

func TestGroup(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	_, err = srv.CreateGroup(ctx, &corev1.Group{Metadata: &metav1.Metadata{Name: "group-1"}, Spec: &corev1.Group_Spec{}})
	assert.Nil(t, err)

	_, err = srv.CreateUser(ctx, &corev1.User{Metadata: &metav1.Metadata{Name: "usr-1"},
		Spec: &corev1.User_Spec{Type: corev1.User_Spec_WORKLOAD, Groups: []string{"group-1"}}})
	assert.Nil(t, err)

	_, err = srv.DeleteGroup(ctx, &metav1.DeleteOptions{Name: "group-1"})
	assert.NotNil(t, err)

	_, err = srv.DeleteUser(ctx, &metav1.DeleteOptions{Name: "usr-1"})
	assert.Nil(t, err)

	_, err = srv.DeleteGroup(ctx, &metav1.DeleteOptions{Name: "group-1"})
	assert.Nil(t, err)

}
