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

package cluster_config

import (
	"context"
	"errors"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestPolicyTrigger(t *testing.T) {
	ctx := context.Background()
	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	c := NewController(tst.C.OcteliumC, tst.C.K8sC)
	old, err := tst.C.OcteliumC.CoreC().GetClusterConfig(ctx, &rmetav1.GetOptions{Name: "default"})
	assert.Nil(t, err)
	assert.Nil(t, c.OnUpdate(ctx, old, old))
	_, err = tst.C.OcteliumC.CoreC().GetPolicyTrigger(ctx, &rmetav1.GetOptions{Name: "cc-global"})
	assert.Equal(t, codes.NotFound, status.Code(err))

	new := proto.Clone(old).(*corev1.ClusterConfig)
	new.Spec.Authorization = &corev1.ClusterConfig_Spec_Authorization{
		Policies: []string{"first"},
		InlinePolicies: []*corev1.InlinePolicy{
			{Name: "inline-first", Spec: &corev1.Policy_Spec{}},
		},
	}
	assert.Nil(t, c.OnUpdate(ctx, new, old))
	pt, err := tst.C.OcteliumC.CoreC().GetPolicyTrigger(ctx, &rmetav1.GetOptions{Name: "cc-global"})
	assert.Nil(t, err)
	assert.Equal(t, []string{"first"}, pt.Status.Policies)
	assert.True(t, proto.Equal(new.Spec.Authorization.InlinePolicies[0], pt.Status.InlinePolicies[0]))
	assert.True(t, pt.Status.PreCondition.GetMatchAny())
	assert.True(t, proto.Equal(umetav1.GetObjectReference(new), pt.Status.OwnerRef))
	uid := pt.Metadata.Uid

	old = proto.Clone(new).(*corev1.ClusterConfig)
	new.Spec.Authorization.Policies = []string{"second", "third"}
	new.Spec.Authorization.InlinePolicies = []*corev1.InlinePolicy{{Name: "inline-second", Spec: &corev1.Policy_Spec{}}}
	assert.Nil(t, c.OnUpdate(ctx, new, old))
	pt, err = tst.C.OcteliumC.CoreC().GetPolicyTrigger(ctx, &rmetav1.GetOptions{Name: "cc-global"})
	assert.Nil(t, err)
	assert.Equal(t, uid, pt.Metadata.Uid)
	assert.Equal(t, []string{"second", "third"}, pt.Status.Policies)
	assert.True(t, proto.Equal(new.Spec.Authorization.InlinePolicies[0], pt.Status.InlinePolicies[0]))
	assert.True(t, pt.Status.PreCondition.GetMatchAny())

	old = proto.Clone(new).(*corev1.ClusterConfig)
	new.Spec.Authorization = nil
	assert.Nil(t, c.OnUpdate(ctx, new, old))
	pt, err = tst.C.OcteliumC.CoreC().GetPolicyTrigger(ctx, &rmetav1.GetOptions{Name: "cc-global"})
	assert.Nil(t, err)
	assert.Empty(t, pt.Status.Policies)
	assert.Empty(t, pt.Status.InlinePolicies)
	assert.Equal(t, uid, pt.Metadata.Uid)

	_, err = tst.C.OcteliumC.CoreC().DeletePolicyTrigger(ctx, &rmetav1.DeleteOptions{Uid: uid})
	assert.Nil(t, err)
	assert.Nil(t, c.OnUpdate(ctx, new, old))
	pt, err = tst.C.OcteliumC.CoreC().GetPolicyTrigger(ctx, &rmetav1.GetOptions{Name: "cc-global"})
	assert.Nil(t, err)
	assert.Empty(t, pt.Status.Policies)
	assert.Empty(t, pt.Status.InlinePolicies)
	assert.True(t, pt.Status.PreCondition.GetMatchAny())
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
	getErr    error
	createErr error
	updateErr error
}

func (c *fakeCoreC) GetPolicyTrigger(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.PolicyTrigger, error) {
	return &corev1.PolicyTrigger{Status: &corev1.PolicyTrigger_Status{}}, c.getErr
}

func (c *fakeCoreC) CreatePolicyTrigger(ctx context.Context,
	in *corev1.PolicyTrigger, opts ...grpc.CallOption) (*corev1.PolicyTrigger, error) {
	return in, c.createErr
}

func (c *fakeCoreC) UpdatePolicyTrigger(ctx context.Context,
	in *corev1.PolicyTrigger, opts ...grpc.CallOption) (*corev1.PolicyTrigger, error) {
	return in, c.updateErr
}

func TestPolicyTriggerErrors(t *testing.T) {
	errTst := errors.New("could not reconcile PolicyTrigger")
	old := &corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{}}
	new := &corev1.ClusterConfig{
		Metadata: &metav1.Metadata{Name: "default", Uid: "cluster-uid"},
		Spec: &corev1.ClusterConfig_Spec{
			Authorization: &corev1.ClusterConfig_Spec_Authorization{Policies: []string{"policy"}},
		},
	}
	for _, coreC := range []*fakeCoreC{
		{getErr: errTst},
		{getErr: status.Error(codes.NotFound, "not found"), createErr: errTst},
		{updateErr: errTst},
	} {
		c := NewController(&fakeOcteliumC{coreC: coreC}, nil)
		assert.ErrorIs(t, c.OnUpdate(context.Background(), new, old), errTst)
	}
}
