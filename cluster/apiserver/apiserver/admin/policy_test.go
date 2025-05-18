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
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
)

func TestPolicy(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	srv := newFakeServer(tst.C)

	p1, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)

	_, err = srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-2.pol-2"}, Spec: &corev1.Policy_Spec{}})
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsInvalidArg(err))

	p2, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)
	assert.Equal(t, p2.Status.ParentPolicyRef.Uid, p1.Metadata.Uid)

	p3, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-3.pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)
	assert.Equal(t, p3.Status.ParentPolicyRef.Uid, p2.Metadata.Uid)

	p4, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-4.pol-3.pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)

	p5, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-5.pol-4.pol-3.pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)

	p6, err := srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-6.pol-5.pol-4.pol-3.pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.Nil(t, err)

	_, err = srv.CreatePolicy(ctx, &corev1.Policy{Metadata: &metav1.Metadata{Name: "pol-7.pol-6.pol-5.pol-4.pol-3.pol-2.pol-1"}, Spec: &corev1.Policy_Spec{}})
	assert.NotNil(t, err)
	assert.True(t, grpcerr.IsInvalidArg(err))

	_, err = srv.DeletePolicy(ctx, &metav1.DeleteOptions{
		Name: p6.Metadata.Name,
	})
	assert.Nil(t, err)

	_, err = srv.DeletePolicy(ctx, &metav1.DeleteOptions{
		Name: p4.Metadata.Name,
	})
	assert.NotNil(t, err)

	_, err = srv.DeletePolicy(ctx, &metav1.DeleteOptions{
		Name: p5.Metadata.Name,
	})
	assert.Nil(t, err)

	_, err = srv.DeletePolicy(ctx, &metav1.DeleteOptions{
		Name: p4.Metadata.Name,
	})
	assert.Nil(t, err)
}
