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

package envoy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"go.uber.org/zap"

	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/ingress/ingress/envoy/resources"
	"github.com/octelium/octelium/cluster/ingress/ingress/xdscb"
	"github.com/octelium/octelium/pkg/utils/utilrand"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	xds "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"google.golang.org/grpc"

	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoverygrpc "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointservice "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routeservice "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
)

type hasher struct{}

func (hasher) ID(node *core.Node) string {
	if node == nil {
		return "unknown"
	}
	return node.Id
}

type logger struct{}

func (logger logger) Infof(format string, args ...any) {
	// log.Infof(format, args...)
}

func (logger logger) Debugf(format string, args ...any) {
	// log.Debugf(format, args...)
}

func (logger logger) Warnf(format string, args ...any) {
	zap.S().Warnf(format, args...)
}

func (logger logger) Errorf(format string, args ...any) {
	zap.S().Warnf(format, args...)
}

type Server struct {
	grpcServer    *grpc.Server
	listener      net.Listener
	xdsServer     xds.Server
	snapshotCache cache.SnapshotCache

	sync.Mutex

	domain    string
	octeliumC octeliumc.ClientInterface

	hasFrontProxy bool

	triggerCh chan struct{}
}

type Opts struct {
	HasFrontProxy bool
}

func NewServer(domain string, octeliumC octeliumc.ClientInterface, o *Opts) (*Server, error) {

	if o == nil {
		o = &Opts{}
	}

	server := &Server{
		domain:        domain,
		octeliumC:     octeliumC,
		hasFrontProxy: o.HasFrontProxy,
		triggerCh:     make(chan struct{}, 1),
	}

	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		return nil, err
	}
	server.listener = l

	server.snapshotCache = cache.NewSnapshotCache(true, hasher{}, logger{})

	server.xdsServer = xds.NewServer(context.Background(), server.snapshotCache, xdscb.NewCallback())

	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions, grpc.MaxConcurrentStreams(1000000))
	server.grpcServer = grpc.NewServer(grpcOptions...)

	discoverygrpc.RegisterAggregatedDiscoveryServiceServer(server.grpcServer, server.xdsServer)
	endpointservice.RegisterEndpointDiscoveryServiceServer(server.grpcServer, server.xdsServer)
	clusterservice.RegisterClusterDiscoveryServiceServer(server.grpcServer, server.xdsServer)
	routeservice.RegisterRouteDiscoveryServiceServer(server.grpcServer, server.xdsServer)
	listenerservice.RegisterListenerDiscoveryServiceServer(server.grpcServer, server.xdsServer)

	return server, nil
}

func (s *Server) startDebouncer(ctx context.Context) {
	const debounceInterval = 300 * time.Millisecond
	var timer *time.Timer
	var timerCh <-chan time.Time

	zap.L().Debug("Starting startDebouncer loop")

	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return

		case <-s.triggerCh:
			if timer == nil {
				timer = time.NewTimer(debounceInterval)
				timerCh = timer.C
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(debounceInterval)
			}

		case <-timerCh:
			snapshotCtx, cancel := context.WithTimeout(ctx, 30*time.Second)

			if err := s.doSnapshot(snapshotCtx); err != nil {
				zap.L().Error("Failed to perform Envoy snapshot", zap.Error(err))
			}

			cancel()

			timer = nil
			timerCh = nil
		}
	}
}
func (s *Server) DoSnapshot(_ context.Context) error {
	select {
	case s.triggerCh <- struct{}{}:
	default:
	}

	return nil
}

func (s *Server) Run(ctx context.Context) error {
	zap.L().Debug("Starting the Envoy server")
	if s.hasFrontProxy {
		zap.L().Info("Front proxy mode is enabled")
	}

	if err := s.doSnapshot(ctx); err != nil {
		return err
	}

	go s.startDebouncer(ctx)

	go func() {
		if err := s.grpcServer.Serve(s.listener); err != nil {
			zap.L().Info("gRPC sever exited...", zap.Error(err))
		}
	}()

	return nil
}

func (s *Server) Close() error {
	return s.listener.Close()
}

func (s *Server) doSnapshot(ctx context.Context) error {
	s.Lock()
	defer s.Unlock()

	zap.L().Info("Starting a new Envoy snapshot")

	rgn, err := s.octeliumC.CoreC().GetRegion(ctx, &rmetav1.GetOptions{
		Name: vutils.GetMyRegionName(),
	})
	if err != nil {
		return err
	}

	svcList, err := s.octeliumC.CoreC().ListService(ctx, &rmetav1.ListOptions{
		Filters: []*rmetav1.ListOptions_Filter{
			urscsrv.FilterFieldBooleanTrue("spec.isPublic"),
			urscsrv.FilterFieldEQValStr("status.regionRef.uid", rgn.Metadata.Uid),
		},
	})
	if err != nil {
		return err
	}

	crtList, err := s.octeliumC.CoreC().ListSecret(ctx, &rmetav1.ListOptions{
		SystemLabels: map[string]string{
			"octelium-cert": "true",
		},
	})
	if err != nil {
		return err
	}

	cc, err := s.octeliumC.CoreV1Utils().GetClusterConfig(ctx)
	if err != nil {
		return err
	}

	rscListeners, err := resources.GetListeners(ctx, &resources.GetListenersReq{
		Domain:        s.domain,
		ClusterConfig: cc,
		ServiceList:   svcList.Items,
		CertList:      crtList.Items,
		HasFrontProxy: s.hasFrontProxy,
	})
	if err != nil {
		return err
	}

	rscClusters, err := resources.GetClusters(s.domain, svcList.Items)
	if err != nil {
		return err
	}

	snap, err := cache.NewSnapshot(fmt.Sprintf("octelium-%s", utilrand.GetRandomStringLowercase(10)),
		map[string][]types.Resource{
			resource.ClusterType:  rscClusters,
			resource.ListenerType: rscListeners,
		})
	if err != nil {
		return err
	}

	if err := s.snapshotCache.SetSnapshot(ctx, "octelium-ingress", snap); err != nil {
		return err
	}

	return nil
}
