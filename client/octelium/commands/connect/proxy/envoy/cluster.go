// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build serveenvoy

package envoy

/*
import (
	"fmt"

	"github.com/asaskevich/govalidator"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"google.golang.org/protobuf/types/known/durationpb"

	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	pb "github.com/octelium/octelium/apis/main/userv1"
)

type cluster struct {
	svc *pb.HostedService
	id  string
}

func (s *Server) getClusters() ([]types.Resource, error) {
	ret := []types.Resource{}
	for _, l := range s.services {

		if l.Upstream == nil {
			continue
		}

		cl := cluster{
			svc: l,
			id:  fmt.Sprintf("%s-%s", l.Namespace, l.Name),
		}

		cluster, err := cl.GetCluster()
		if err != nil {
			return nil, err
		}
		ret = append(ret, cluster)

	}

	return ret, nil
}

func (c *cluster) GetCluster() (*clusterv3.Cluster, error) {

	loadAssignments, err := c.getClusterLoadAssignment()
	if err != nil {
		return nil, err
	}

	cluster := &clusterv3.Cluster{

		Name:           c.id,
		ConnectTimeout: &durationpb.Duration{Seconds: 15},
		LbPolicy:       clusterv3.Cluster_ROUND_ROBIN,
		ClusterDiscoveryType: &clusterv3.Cluster_Type{
			Type: c.getClusterDiscoveryType(),
		},

		LoadAssignment: loadAssignments,
	}

	return cluster, nil
}

func (c *cluster) getClusterDiscoveryType() clusterv3.Cluster_DiscoveryType {
	if govalidator.IsIP(c.svc.Upstream.Host) {
		return clusterv3.Cluster_STATIC
	}
	return clusterv3.Cluster_LOGICAL_DNS
}

func (c *cluster) getClusterLoadAssignment() (*endpoint.ClusterLoadAssignment, error) {
	endpoints, err := c.getEndpoints()
	if err != nil {
		return nil, err
	}
	ret := &endpoint.ClusterLoadAssignment{
		ClusterName: c.id,
		Endpoints:   []*endpoint.LocalityLbEndpoints{endpoints},
	}

	return ret, nil
}

func (c *cluster) getEndpoints() (*endpoint.LocalityLbEndpoints, error) {
	return c.getEndpointsBackend()
}

func (c *cluster) getEndpointsBackend() (*endpoint.LocalityLbEndpoints, error) {
	ret := &endpoint.LocalityLbEndpoints{
		LbEndpoints: []*endpoint.LbEndpoint{},
	}

	proto := ProtocolTCP

	if c.svc.L4Type == pb.HostedService_UDP {
		proto = ProtocolUDP
	}

	ret.LbEndpoints = append(ret.LbEndpoints, &endpoint.LbEndpoint{
		HostIdentifier: &endpoint.LbEndpoint_Endpoint{
			Endpoint: &endpoint.Endpoint{

				Address: getAddress(c.svc.Upstream.Host, uint32(c.svc.Upstream.Port), proto),
			},
		},
	})

	return ret, nil
}
*/
