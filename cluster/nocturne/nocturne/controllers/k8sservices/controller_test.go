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
	"os"
	"testing"

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/stretchr/testify/assert"
	k8scorev1 "k8s.io/api/core/v1"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
