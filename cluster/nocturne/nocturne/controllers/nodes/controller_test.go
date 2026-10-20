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
	"errors"
	"testing"

	octeliumcorev1 "github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	coreinformers "k8s.io/client-go/informers/core/v1"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
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

func TestTaintNode(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	genNode := func(labels map[string]string) *corev1.Node {
		return &corev1.Node{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:   utilrand.GetRandomStringLowercase(8),
				UID:    types.UID(vutils.UUIDv4()),
				Labels: labels,
			},
			Spec:   corev1.NodeSpec{},
			Status: corev1.NodeStatus{},
		}
	}

	createNode := func(node *corev1.Node) *corev1.Node {
		node, err := fakeC.K8sC.CoreV1().Nodes().Create(ctx, node, k8smetav1.CreateOptions{})
		assert.Nil(t, err, "%+v", err)
		assert.False(t, hasGatewayInitTaint(node))
		return node
	}

	runTaint := func(node *corev1.Node) *corev1.Node {
		err := taintNode(ctx, fakeC.K8sC, fakeC.OcteliumC, node)
		assert.Nil(t, err, "%+v", err)

		res, err := fakeC.K8sC.CoreV1().Nodes().Get(ctx, node.Name, k8smetav1.GetOptions{})
		assert.Nil(t, err, "%+v", err)
		return res
	}

	doTaint := func(node *corev1.Node) *corev1.Node {
		return runTaint(createNode(node))
	}

	{
		res := doTaint(genNode(map[string]string{
			vutils.NodeLabelDataPlane: "",
		}))
		assert.True(t, hasGatewayInitTaint(res))
	}

	{
		res := doTaint(genNode(map[string]string{
			vutils.NodeLabelDataPlane:    "",
			vutils.NodeLabelControlPlane: "",
		}))
		assert.False(t, hasGatewayInitTaint(res))
	}

	{
		res := doTaint(genNode(map[string]string{
			vutils.NodeLabelDataPlane:         "",
			vutils.NodeLabelGatewayRegistered: "true",
		}))
		assert.False(t, hasGatewayInitTaint(res))
	}

	{
		res := doTaint(genNode(map[string]string{
			vutils.NodeLabelControlPlane: "",
		}))
		assert.False(t, hasGatewayInitTaint(res))
	}

	{
		node := createNode(genNode(map[string]string{
			vutils.NodeLabelDataPlane: "",
		}))

		_, err := fakeC.OcteliumC.CoreC().CreateGateway(ctx, &octeliumcorev1.Gateway{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &octeliumcorev1.Gateway_Spec{},
			Status: &octeliumcorev1.Gateway_Status{
				NodeRef: &metav1.ObjectReference{
					Name: node.Name,
					Uid:  string(node.UID),
				},
			},
		})
		assert.Nil(t, err, "%+v", err)

		res := runTaint(node)
		assert.False(t, hasGatewayInitTaint(res))
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

type fakeOcteliumC struct {
	octeliumc.ClientInterface
	coreC rcorev1.ResourceServiceClient
}

func (c *fakeOcteliumC) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

type fakeCoreC struct {
	rcorev1.ResourceServiceClient
	gateways  []*octeliumcorev1.Gateway
	listErr   error
	deleteErr error
	deleted   []string
}

func (c *fakeCoreC) ListGateway(ctx context.Context,
	in *rmetav1.ListOptions, opts ...grpc.CallOption) (*octeliumcorev1.GatewayList, error) {
	return &octeliumcorev1.GatewayList{Items: c.gateways}, c.listErr
}

func (c *fakeCoreC) DeleteGateway(ctx context.Context,
	in *rmetav1.DeleteOptions, opts ...grpc.CallOption) (*rmetav1.OperationResult, error) {
	c.deleted = append(c.deleted, in.Uid)
	return nil, c.deleteErr
}

type fakeNodeInformer struct {
	coreinformers.NodeInformer
	informer *fakeInformer
}

func (i *fakeNodeInformer) Informer() cache.SharedIndexInformer {
	return i.informer
}

type fakeInformer struct {
	cache.SharedIndexInformer
	handler cache.ResourceEventHandler
}

func (i *fakeInformer) AddEventHandler(handler cache.ResourceEventHandler) (cache.ResourceEventHandlerRegistration, error) {
	i.handler = handler
	return nil, nil
}

func TestNodeEvents(t *testing.T) {
	ctx := context.Background()
	node := &corev1.Node{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: "node", UID: "node-uid", ResourceVersion: "1",
			Labels: map[string]string{vutils.NodeLabelDataPlane: ""},
		},
	}
	k8sC := fakek8s.NewSimpleClientset(node.DeepCopy())
	coreC := &fakeCoreC{}
	informer := &fakeNodeInformer{informer: &fakeInformer{}}
	NewController(k8sC, &fakeOcteliumC{coreC: coreC}, informer)
	handler := informer.informer.handler
	handler.OnAdd(node, false)
	current, err := k8sC.CoreV1().Nodes().Get(ctx, node.Name, k8smetav1.GetOptions{})
	assert.Nil(t, err)
	assert.True(t, hasGatewayInitTaint(current))

	old := current.DeepCopy()
	current.Labels[vutils.NodeLabelGatewayRegistered] = "true"
	current.ResourceVersion = "2"
	current.Spec.Taints = append(current.Spec.Taints, corev1.Taint{Key: "other", Effect: corev1.TaintEffectNoExecute})
	current, err = k8sC.CoreV1().Nodes().Update(ctx, current, k8smetav1.UpdateOptions{})
	assert.Nil(t, err)
	handler.OnUpdate(old, current)
	current, err = k8sC.CoreV1().Nodes().Get(ctx, node.Name, k8smetav1.GetOptions{})
	assert.Nil(t, err)
	assert.Equal(t, []corev1.Taint{{Key: "other", Effect: corev1.TaintEffectNoExecute}}, current.Spec.Taints)

	k8sC.ClearActions()
	handler.OnAdd("node", false)
	handler.OnUpdate("node", current)
	handler.OnUpdate(current, "node")
	handler.OnUpdate(current, current)
	handler.OnDelete("node")
	assert.Empty(t, k8sC.Actions())
	coreC.gateways = []*octeliumcorev1.Gateway{{
		Metadata: &metav1.Metadata{Uid: "gateway-uid"},
		Status:   &octeliumcorev1.Gateway_Status{NodeRef: &metav1.ObjectReference{Uid: string(node.UID)}},
	}}
	handler.OnDelete(current)
	assert.Equal(t, []string{"gateway-uid"}, coreC.deleted)

	coreC.listErr = errors.New("could not list Gateways")
	handler.OnAdd(node, false)
	handler.OnUpdate(&corev1.Node{}, node)
	handler.OnDelete(node)
}

func TestNodeErrors(t *testing.T) {
	ctx := context.Background()
	errTst := errors.New("could not update Node")
	node := &corev1.Node{ObjectMeta: k8smetav1.ObjectMeta{
		Name: "node", UID: "node-uid", Labels: map[string]string{vutils.NodeLabelDataPlane: ""},
	}}
	{
		coreC := &fakeCoreC{listErr: errTst}
		c := &fakeOcteliumC{coreC: coreC}
		assert.ErrorIs(t, taintNode(ctx, fakek8s.NewSimpleClientset(), c, node), errTst)
		assert.ErrorIs(t, deleteGWs(ctx, c, node), errTst)
	}
	for _, verb := range []string{"get", "update"} {
		t.Run(verb, func(t *testing.T) {
			k8sC := fakek8s.NewSimpleClientset(node.DeepCopy())
			k8sC.PrependReactor(verb, "nodes", func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errTst
			})
			assert.ErrorIs(t, taintNode(ctx, k8sC, &fakeOcteliumC{coreC: &fakeCoreC{}}, node), errTst)
			registered := node.DeepCopy()
			registered.Labels[vutils.NodeLabelGatewayRegistered] = "true"
			registered.Spec.Taints = []corev1.Taint{{Key: vutils.NodeTaintGatewayInit}}
			assert.Nil(t, k8sC.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), registered, ""))
			assert.ErrorIs(t, untaintNode(ctx, k8sC, registered), errTst)
			informer := &fakeNodeInformer{informer: &fakeInformer{}}
			NewController(k8sC, &fakeOcteliumC{coreC: &fakeCoreC{}}, informer)
			registered.ResourceVersion = "2"
			informer.informer.handler.OnAdd(registered, false)
			informer.informer.handler.OnUpdate(node, registered)
		})
	}
	for _, errDel := range []error{errTst, status.Error(codes.NotFound, "not found")} {
		coreC := &fakeCoreC{
			deleteErr: errDel,
			gateways: []*octeliumcorev1.Gateway{
				{Status: &octeliumcorev1.Gateway_Status{}},
				{Metadata: &metav1.Metadata{Uid: "first"}, Status: &octeliumcorev1.Gateway_Status{NodeRef: &metav1.ObjectReference{Uid: "node-uid"}}},
				{Metadata: &metav1.Metadata{Uid: "second"}, Status: &octeliumcorev1.Gateway_Status{NodeRef: &metav1.ObjectReference{Uid: "node-uid"}}},
			},
		}
		err := deleteGWs(ctx, &fakeOcteliumC{coreC: coreC}, node)
		if status.Code(errDel) == codes.NotFound {
			assert.Nil(t, err)
			assert.Equal(t, []string{"first", "second"}, coreC.deleted)
		} else {
			assert.ErrorIs(t, err, errTst)
			assert.Equal(t, []string{"first"}, coreC.deleted)
		}
	}
}

func TestNodeTaintRetries(t *testing.T) {
	ctx := context.Background()
	node := &corev1.Node{ObjectMeta: k8smetav1.ObjectMeta{
		Name: "node", UID: "node-uid", Labels: map[string]string{vutils.NodeLabelDataPlane: ""},
	}}
	k8sC := fakek8s.NewSimpleClientset(node.DeepCopy())
	var updates int
	k8sC.PrependReactor("update", "nodes", func(action k8stesting.Action) (bool, runtime.Object, error) {
		updates++
		if updates == 1 {
			return true, nil, k8serr.NewConflict(schema.GroupResource{Resource: "nodes"}, node.Name, errors.New("conflict"))
		}
		return false, nil, nil
	})
	c := &fakeOcteliumC{coreC: &fakeCoreC{}}
	assert.Nil(t, taintNode(ctx, k8sC, c, node))
	assert.Equal(t, 2, updates)
	assert.Nil(t, taintNode(ctx, k8sC, c, node))
	assert.Equal(t, 2, updates)
	current, err := k8sC.CoreV1().Nodes().Get(ctx, node.Name, k8smetav1.GetOptions{})
	assert.Nil(t, err)
	assert.Nil(t, taintNode(ctx, k8sC, c, current))
	current.Labels[vutils.NodeLabelGatewayRegistered] = "true"
	assert.Nil(t, k8sC.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), current, ""))
	updates = 0
	assert.Nil(t, untaintNode(ctx, k8sC, current))
	assert.Equal(t, 2, updates)
	assert.Nil(t, untaintNode(ctx, k8sC, current))
	assert.Equal(t, 2, updates)
	current.Spec.Taints = nil
	assert.Nil(t, untaintNode(ctx, k8sC, current))
}
