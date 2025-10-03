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

package apiserver

import (
	"context"
	"net"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/user"
	"github.com/octelium/octelium/cluster/common/commoninit"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/userctx"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/common/watchers"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	gwcontroller "github.com/octelium/octelium/cluster/apiserver/apiserver/controllers/gateways"
	svccontroller "github.com/octelium/octelium/cluster/apiserver/apiserver/controllers/services"
	sesscontroller "github.com/octelium/octelium/cluster/apiserver/apiserver/controllers/sessions"
)

func Run(ctx context.Context) error {

	zap.L().Debug("Starting octelium API server...")

	octeliumC, err := octeliumc.NewClient(ctx)
	if err != nil {
		return err
	}

	if err := commoninit.Run(ctx, nil); err != nil {
		return err
	}

	lis, err := net.Listen("tcp", vutils.ManagedServiceAddr)
	if err != nil {
		return err
	}

	srv := admin.NewServer(&admin.Opts{
		OcteliumC: octeliumC,
	})
	usrSrv := user.NewServer(octeliumC)

	gwCtl := gwcontroller.NewController(octeliumC, usrSrv.ConnServer())
	svcCtl := svccontroller.NewController(octeliumC, usrSrv.ConnServer())
	sessCtl := sesscontroller.NewController(octeliumC, usrSrv.ConnServer())

	{
		watcher := watchers.NewCoreV1(octeliumC)
		if err := watcher.Service(ctx, nil, svcCtl.OnAdd, svcCtl.OnUpdate, svcCtl.OnDelete); err != nil {
			return err
		}

		if err := watcher.Session(ctx, nil, sessCtl.OnAdd, sessCtl.OnUpdate, sessCtl.OnDelete); err != nil {
			return err
		}
	}

	{
		if err := watchers.NewCoreV1(octeliumC).
			Gateway(ctx, nil, gwCtl.OnAdd, gwCtl.OnUpdate, gwCtl.OnDelete); err != nil {
			return err
		}
	}

	zap.L().Debug("starting gRPC server....")

	mdlwr, err := userctx.New(ctx, octeliumC)
	if err != nil {
		return err
	}

	s := grpc.NewServer(
		grpc.StreamInterceptor(
			grpc_middleware.ChainStreamServer(mdlwr.StreamServerInterceptor())),
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(mdlwr.UnaryServerInterceptor())),
	)
	corev1.RegisterMainServiceServer(s, srv)
	userv1.RegisterMainServiceServer(s, usrSrv)

	go func() {
		zap.L().Debug("running gRPC server.")
		if err := s.Serve(lis); err != nil {
			zap.L().Info("gRPC server closed", zap.Error(err))
		}
	}()

	healthcheck.Run(vutils.HealthCheckPortManagedService)
	zap.L().Info("API Server is now running")
	<-ctx.Done()
	zap.L().Debug("Shutting down gRPC server")
	s.Stop()

	return nil
}
