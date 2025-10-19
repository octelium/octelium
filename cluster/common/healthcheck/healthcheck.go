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

package healthcheck

import (
	"context"
	"fmt"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type Server struct {
	grpc_health_v1.UnimplementedHealthServer
}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) Check(ctx context.Context, in *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	// zap.L().Debug("Responding to health check request")
	return &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	}, nil
}

func (s *Server) Watch(*grpc_health_v1.HealthCheckRequest, grpc_health_v1.Health_WatchServer) error {
	return nil
}

func Run(port int) {
	go func() {
		if err := doRun(fmt.Sprintf(":%d", port)); err != nil {
			zap.L().Warn("healthCheck server error", zap.Error(err))
		}
	}()
}

func RunWithAddr(addr string) {
	go func() {
		if err := doRun(addr); err != nil {
			zap.L().Warn("healthCheck server error", zap.Error(err))
		}
	}()
}

func doRun(addr string) error {
	grpcSrv := grpc.NewServer(
		grpc.MaxConcurrentStreams(1000000),
	)

	grpc_health_v1.RegisterHealthServer(grpcSrv, NewServer())

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		zap.L().Warn("Could not listen to port for gRPC healthCheck service", zap.Error(err))
		return err
	}

	zap.L().Debug("Running healthCheck gRPC service", zap.String("addr", addr))

	err = grpcSrv.Serve(lis)
	zap.L().Debug("healthCheck gRPC service exited", zap.Error(err))

	return nil
}
