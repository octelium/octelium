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
	"context"
	"fmt"
	"net"
	"sync"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"go.uber.org/zap"

	utils_rand "github.com/octelium/octelium/pkg/utils/random"
	"github.com/octelium/octelium/pkg/xdscb"

	types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	xds "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	pb "github.com/octelium/octelium/apis/main/userv1"
	"google.golang.org/grpc"

	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
)

const IsEnabled = true

type hasher struct{}

func (hasher) ID(node *core.Node) string {
	if node == nil {
		return "unknown"
	}
	return node.Id
}

type logger struct{}

func (logger logger) Infof(format string, args ...interface{}) {
	zap.S().Infof(format, args...)
}

func (logger logger) Debugf(format string, args ...interface{}) {
	zap.S().Debugf(format, args...)
}

func (logger logger) Warnf(format string, args ...interface{}) {
	zap.S().Warnf(format, args...)
}

func (logger logger) Errorf(format string, args ...interface{}) {
	zap.S().Errorf(format, args...)
}

type Server struct {
	grpcServer    *grpc.Server
	listener      net.Listener
	xdsServer     xds.Server
	snapshotCache cache.SnapshotCache

	sync.Mutex

	services []*pb.HostedService

	ipv4Supported bool
	ipv6Supported bool
}

func NewServer(ipv4Supported bool, ipv6Supported bool) (*Server, error) {

	server := &Server{
		ipv4Supported: ipv4Supported,
		ipv6Supported: ipv6Supported,
	}
	l, err := net.Listen("tcp", "127.0.0.1:44444")
	if err != nil {
		return nil, err
	}

	server.listener = l

	server.snapshotCache = cache.NewSnapshotCache(true, hasher{}, logger{})

	server.xdsServer = xds.NewServer(context.Background(), server.snapshotCache, xdscb.NewCallback())

	server.grpcServer = grpc.NewServer()

	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(server.grpcServer, server.xdsServer)
	endpointservice.RegisterEndpointDiscoveryServiceServer(server.grpcServer, server.xdsServer)
	clusterservice.RegisterClusterDiscoveryServiceServer(server.grpcServer, server.xdsServer)
	routeservice.RegisterRouteDiscoveryServiceServer(server.grpcServer, server.xdsServer)
	listenerservice.RegisterListenerDiscoveryServiceServer(server.grpcServer, server.xdsServer)

	return server, nil
}

func (s *Server) Run() error {
	zap.S().Debugf("Starting envoy xDS")
	return s.grpcServer.Serve(s.listener)
}

func (s *Server) Close() {
	s.grpcServer.Stop()
}

func (s *Server) AddService(svc *pb.HostedService) error {
	zap.S().Debugf("Envoy controller adding service: %+v", svc)

	for _, itm := range s.services {
		if itm.Name == svc.Name && itm.Namespace == svc.Namespace {
			zap.S().Debugf("Service %s already exists. Updating instead of adding", svc.Name)
			return s.UpdateService(svc)
		}
	}

	s.services = append(s.services, svc)

	return s.doSnapshot()
}

func (s *Server) UpdateService(svc *pb.HostedService) error {

	found := false
	for i := range s.services {
		if s.services[i].Name == svc.Name && s.services[i].Namespace == svc.Namespace {
			s.services[i] = svc
			found = true
			break
		}
	}

	if !found {
		s.services = append(s.services, svc)
	}

	return s.doSnapshot()
}

func (s *Server) DeleteService(name, namespace string) error {

	zap.S().Debugf("Envoy controller deleting Service: %s/%s", namespace, name)

	for i := len(s.services) - 1; i >= 0; i-- {
		if s.services[i].Name == name && s.services[i].Namespace == namespace {
			s.services = append(s.services[:i], s.services[i+1:]...)
		}
	}

	return s.doSnapshot()
}

func (s *Server) doSnapshot() error {

	rscListeners, err := s.getListeners()
	if err != nil {
		return err
	}

	rscClusters, err := s.getClusters()
	if err != nil {
		return err
	}

	zap.S().Debugf("Applying snapshot for:\n listeners: %+q\n\nclusters: %+q\n", rscListeners, rscClusters)

	snap, err := cache.NewSnapshot(fmt.Sprintf("octelium-%s", utilrand.GetRandomStringLowercase(10)),
		map[string][]types.Resource{
			resource.ClusterType:  rscClusters,
			resource.ListenerType: rscListeners,
		})
	if err != nil {
		return err
	}

	err = s.snapshotCache.SetSnapshot(context.Background(), "octelium", snap)
	if err != nil {
		return err
	}

	return nil
}
*/
