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

package nodecontroller

import (
	"context"
	"testing"

	octeliumcorev1 "github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func hasGatewayInitTaint(n *corev1.Node) bool {
	for _, taint := range n.Spec.Taints {
		if taint.Key == "octelium.com/gateway-init" {
			return true
		}
	}
	return false
}

func TestUntaintNode(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	genNode := func(name string, registered bool) *corev1.Node {
		labels := map[string]string{}
		if registered {
			labels["octelium.com/gateway-registered"] = "true"
		}
		return &corev1.Node{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:   name,
				UID:    types.UID(vutils.UUIDv4()),
				Labels: labels,
			},
			Spec: corev1.NodeSpec{
				Taints: []corev1.Taint{
					{
						Key:    "octelium.com/gateway-init",
						Effect: corev1.TaintEffectNoSchedule,
					},
				},
			},
			Status: corev1.NodeStatus{},
		}
	}

	{
		node, err := fakeC.K8sC.CoreV1().Nodes().Create(ctx,
			genNode(utilrand.GetRandomStringLowercase(8), true), k8smetav1.CreateOptions{})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, hasGatewayInitTaint(node))

		err = untaintNode(ctx, fakeC.K8sC, node)
		assert.Nil(t, err, "%+v", err)

		res, err := fakeC.K8sC.CoreV1().Nodes().Get(ctx, node.Name, k8smetav1.GetOptions{})
		assert.Nil(t, err, "%+v", err)
		assert.False(t, hasGatewayInitTaint(res))
	}

	{
		node, err := fakeC.K8sC.CoreV1().Nodes().Create(ctx,
			genNode(utilrand.GetRandomStringLowercase(8), false), k8smetav1.CreateOptions{})
		assert.Nil(t, err, "%+v", err)

		err = untaintNode(ctx, fakeC.K8sC, node)
		assert.Nil(t, err, "%+v", err)

		res, err := fakeC.K8sC.CoreV1().Nodes().Get(ctx, node.Name, k8smetav1.GetOptions{})
		assert.Nil(t, err, "%+v", err)
		assert.True(t, hasGatewayInitTaint(res))
	}
}

func TestDeleteGWs(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	node := &corev1.Node{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: utilrand.GetRandomStringLowercase(8),
			UID:  types.UID(vutils.UUIDv4()),
		},
		Spec:   corev1.NodeSpec{},
		Status: corev1.NodeStatus{},
	}

	createGateway := func(nodeUID string) *octeliumcorev1.Gateway {
		gw, err := fakeC.OcteliumC.CoreC().CreateGateway(ctx, &octeliumcorev1.Gateway{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &octeliumcorev1.Gateway_Spec{},
			Status: &octeliumcorev1.Gateway_Status{
				NodeRef: &metav1.ObjectReference{
					Name: node.Name,
					Uid:  nodeUID,
				},
			},
		})
		assert.Nil(t, err, "%+v", err)
		return gw
	}

	gw := createGateway(string(node.UID))
	gwOther := createGateway(vutils.UUIDv4())

	err = deleteGWs(ctx, fakeC.OcteliumC, node)
	assert.Nil(t, err, "%+v", err)

	{
		_, err := fakeC.OcteliumC.CoreC().GetGateway(ctx, &rmetav1.GetOptions{Uid: gw.Metadata.Uid})
		assert.NotNil(t, err)
		assert.True(t, grpcerr.IsNotFound(err))
	}

	{
		res, err := fakeC.OcteliumC.CoreC().GetGateway(ctx, &rmetav1.GetOptions{Uid: gwOther.Metadata.Uid})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, gwOther.Metadata.Uid, res.Metadata.Uid)
	}
}
