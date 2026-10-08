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

package resources

import (
	"context"
	"testing"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/stretchr/testify/assert"
)

func TestGetClusters(t *testing.T) {

	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	usr := tests.GenUser(nil)

	doCreateSvc := func() *corev1.Service {
		svc := tests.GenService("default")
		svc.Spec.IsPublic = true
		svc.Spec.Mode = corev1.Service_Spec_HTTP
		svc, err = adminSrv.CreateService(ctx, svc)
		assert.Nil(t, err, "%+v", err)
		ret, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		return ret
	}

	usr, err = adminSrv.CreateUser(ctx, usr)
	assert.Nil(t, err)

	var svcList []*corev1.Service

	apiSrvSvc, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{
		Name: "api.octelium",
	})
	assert.Nil(t, err)

	svcList = append(svcList, apiSrvSvc)

	_, err = GetClusters("example.com", nil)
	assert.Nil(t, err)
	//os.Setenv("OCTELIUM_REHION_NAME", "default")
	_, err = GetClusters("example.com", svcList)
	assert.Nil(t, err)

	for i := 0; i < 100; i++ {
		svcList = append(svcList, doCreateSvc())
	}

	_, err = GetClusters("example.com", svcList)
	assert.Nil(t, err)
	_, err = GetClusters("example.com", svcList)
	assert.Nil(t, err)
}

func TestGetClustersCircuitBreakers(t *testing.T) {
	apiSvc := newAPIServerService("default.octelium-api", "/octelium.api.main.core, /octelium.api.main.user")
	svc := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: "svc1.default",
		},
		Spec: &corev1.Service_Spec{
			Port:     8080,
			IsPublic: true,
			Mode:     corev1.Service_Spec_HTTP,
		},
		Status: &corev1.Service_Status{
			NamespaceRef: &metav1.ObjectReference{Name: "default"},
		},
	}

	resources, err := GetClusters("example.com", []*corev1.Service{apiSvc, svc})
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 3, len(resources))

	clusters := make(map[string]*clusterv3.Cluster)
	for _, rsc := range resources {
		clstr := rsc.(*clusterv3.Cluster)
		assert.Nil(t, clstr.ValidateAll())
		clusters[clstr.Name] = clstr
	}

	assertThresholds := func(thresholds *clusterv3.CircuitBreakers_Thresholds,
		priority core.RoutingPriority, maxRequests uint32) {
		assert.Equal(t, priority, thresholds.Priority)
		assert.Equal(t, maxRequests, thresholds.MaxRequests.GetValue())
		assert.Equal(t, maxRequests, thresholds.MaxPendingRequests.GetValue())
		assert.Equal(t, maxRequests, thresholds.MaxConnections.GetValue())
		assert.Equal(t, uint32(3), thresholds.MaxRetries.GetValue())
	}

	{
		clstr := clusters[getClusterNameFromService(apiSvc)]
		assert.NotNil(t, clstr)
		assert.Equal(t, 2, len(clstr.CircuitBreakers.Thresholds))
		assertThresholds(clstr.CircuitBreakers.Thresholds[0], core.RoutingPriority_DEFAULT, maxRequestsDefault)
		assertThresholds(clstr.CircuitBreakers.Thresholds[1], core.RoutingPriority_HIGH, maxRequestsAPIServerConnect)
	}

	{
		clstr := clusters[getClusterNameFromService(svc)]
		assert.NotNil(t, clstr)
		assert.Equal(t, 1, len(clstr.CircuitBreakers.Thresholds))
		assertThresholds(clstr.CircuitBreakers.Thresholds[0], core.RoutingPriority_DEFAULT, maxRequestsDefault)
	}

	{
		clstr := clusters[healthCheckCluster]
		assert.NotNil(t, clstr)
		assert.Equal(t, 1, len(clstr.CircuitBreakers.Thresholds))
		assertThresholds(clstr.CircuitBreakers.Thresholds[0], core.RoutingPriority_DEFAULT, maxRequestsDefault)
	}
}
