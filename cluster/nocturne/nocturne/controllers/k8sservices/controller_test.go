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

package k8sservicescontroller

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
)

func TestDoHandle(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err, "%+v", err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	os.Setenv("OCTELIUM_REGION_NAME", "default")
	defer os.Unsetenv("OCTELIUM_REGION_NAME")

	genSvc := func() *k8scorev1.Service {
		return &k8scorev1.Service{
			ObjectMeta: k8smetav1.ObjectMeta{
				Name:      "octelium-ingress-dataplane",
				Namespace: vutils.K8sNS,
			},
			Spec: k8scorev1.ServiceSpec{},
			Status: k8scorev1.ServiceStatus{
				LoadBalancer: k8scorev1.LoadBalancerStatus{
					Ingress: []k8scorev1.LoadBalancerIngress{
						{IP: "1.2.3.4"},
						{IP: "5.6.7.8"},
					},
				},
			},
		}
	}

	{
		svc := genSvc()
		err = doHandle(ctx, fakeC.OcteliumC, fakeC.K8sC, svc)
		assert.Nil(t, err, "%+v", err)

		region, err := fakeC.OcteliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
			Name: vutils.GetMyRegionName(),
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, []string{"1.2.3.4", "5.6.7.8"}, region.Status.IngressAddresses)
	}

	{
		svc := genSvc()
		err = doHandle(ctx, fakeC.OcteliumC, fakeC.K8sC, svc)
		assert.Nil(t, err, "%+v", err)

		region, err := fakeC.OcteliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
			Name: vutils.GetMyRegionName(),
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, []string{"1.2.3.4", "5.6.7.8"}, region.Status.IngressAddresses)
	}

	{
		svc := genSvc()
		svc.Spec.ExternalIPs = []string{"9.9.9.9"}
		err = doHandle(ctx, fakeC.OcteliumC, fakeC.K8sC, svc)
		assert.Nil(t, err, "%+v", err)

		region, err := fakeC.OcteliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
			Name: vutils.GetMyRegionName(),
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, []string{"9.9.9.9"}, region.Status.IngressAddresses)
	}

	{
		svc := genSvc()
		svc.Name = "some-other-service"
		err = doHandle(ctx, fakeC.OcteliumC, fakeC.K8sC, svc)
		assert.Nil(t, err, "%+v", err)

		region, err := fakeC.OcteliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
			Name: vutils.GetMyRegionName(),
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, []string{"9.9.9.9"}, region.Status.IngressAddresses)
	}

	{
		svc := genSvc()
		svc.Namespace = "not-octelium"
		err = doHandle(ctx, fakeC.OcteliumC, fakeC.K8sC, svc)
		assert.Nil(t, err, "%+v", err)

		region, err := fakeC.OcteliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
			Name: vutils.GetMyRegionName(),
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, []string{"9.9.9.9"}, region.Status.IngressAddresses)
	}
}

func TestDoGetIPs(t *testing.T) {

	{
		svc := &k8scorev1.Service{
			Spec: k8scorev1.ServiceSpec{
				ExternalIPs: []string{"1.1.1.1", "2.2.2.2"},
			},
			Status: k8scorev1.ServiceStatus{
				LoadBalancer: k8scorev1.LoadBalancerStatus{
					Ingress: []k8scorev1.LoadBalancerIngress{
						{IP: "9.9.9.9"},
					},
				},
			},
		}
		assert.Equal(t, []string{"1.1.1.1", "2.2.2.2"}, doGetIPs(svc))
	}

	{
		svc := &k8scorev1.Service{
			Spec: k8scorev1.ServiceSpec{},
			Status: k8scorev1.ServiceStatus{
				LoadBalancer: k8scorev1.LoadBalancerStatus{
					Ingress: []k8scorev1.LoadBalancerIngress{
						{IP: "3.3.3.3"},
						{IP: "4.4.4.4"},
					},
				},
			},
		}
		assert.Equal(t, []string{"3.3.3.3", "4.4.4.4"}, doGetIPs(svc))
	}

	{
		svc := &k8scorev1.Service{
			Spec:   k8scorev1.ServiceSpec{},
			Status: k8scorev1.ServiceStatus{},
		}
		assert.Nil(t, doGetIPs(svc))
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
	region    *corev1.Region
	getErr    error
	updateErr error
	gets      int
	updates   int
}

func (c *fakeCoreC) GetRegion(ctx context.Context,
	in *rmetav1.GetOptions, opts ...grpc.CallOption) (*corev1.Region, error) {
	c.gets++
	return c.region, c.getErr
}

func (c *fakeCoreC) UpdateRegion(ctx context.Context,
	in *corev1.Region, opts ...grpc.CallOption) (*corev1.Region, error) {
	c.updates++
	c.region = in
	return in, c.updateErr
}

type fakeServiceInformer struct {
	coreinformers.ServiceInformer
	informer *fakeInformer
}

func (i *fakeServiceInformer) Informer() cache.SharedIndexInformer {
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

func TestServiceEvents(t *testing.T) {
	coreC := &fakeCoreC{region: &corev1.Region{}}
	informer := &fakeServiceInformer{informer: &fakeInformer{}}
	NewController(nil, &fakeOcteliumC{coreC: coreC}, informer)
	handler := informer.informer.handler
	svc := &k8scorev1.Service{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: "octelium-ingress-dataplane", Namespace: vutils.K8sNS, ResourceVersion: "1",
		},
		Spec: k8scorev1.ServiceSpec{ExternalIPs: []string{"192.0.2.1", "2001:db8::1"}},
	}
	handler.OnAdd(svc, false)
	assert.Equal(t, svc.Spec.ExternalIPs, coreC.region.Status.IngressAddresses)
	assert.Equal(t, 1, coreC.updates)
	handler.OnAdd(svc, false)
	assert.Equal(t, 1, coreC.updates)
	old := svc.DeepCopy()
	svc.ResourceVersion = "2"
	svc.Spec.ExternalIPs = []string{"192.0.2.2"}
	handler.OnUpdate(old, svc)
	assert.Equal(t, []string{"192.0.2.2"}, coreC.region.Status.IngressAddresses)
	assert.Equal(t, 2, coreC.updates)
	gets := coreC.gets
	handler.OnAdd("service", false)
	handler.OnUpdate("service", svc)
	handler.OnUpdate(svc, "service")
	handler.OnUpdate(svc, svc)
	assert.Equal(t, gets, coreC.gets)
	coreC.getErr = errors.New("could not get Region")
	handler.OnAdd(svc, false)
	handler.OnUpdate(old, svc)
	assert.Equal(t, gets+2, coreC.gets)
}

func TestRegionIngressErrors(t *testing.T) {
	errTst := errors.New("could not reconcile Region")
	svc := &k8scorev1.Service{
		ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-ingress-dataplane", Namespace: vutils.K8sNS},
		Spec:       k8scorev1.ServiceSpec{ExternalIPs: []string{"192.0.2.1"}},
	}
	for _, coreC := range []*fakeCoreC{
		{getErr: errTst},
		{region: &corev1.Region{}, updateErr: errTst},
	} {
		assert.ErrorIs(t, doHandle(context.Background(), &fakeOcteliumC{coreC: coreC}, nil, svc), errTst)
	}

	coreC := &fakeCoreC{region: &corev1.Region{Status: &corev1.Region_Status{IngressAddresses: []string{"192.0.2.1"}}}}
	svc.Spec.ExternalIPs = []string{}
	assert.Nil(t, doHandle(context.Background(), &fakeOcteliumC{coreC: coreC}, nil, svc))
	assert.Empty(t, coreC.region.Status.IngressAddresses)
}
