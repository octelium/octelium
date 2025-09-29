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

package rscserver

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/go-redis/redis/v8"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	_ "github.com/lib/pq"
	"github.com/octelium/octelium/apis/cluster/csecretmanv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/apis/rsc/rratelimitv1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/healthcheck"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type Server struct {
	db *sql.DB

	redisC  *redis.Client
	grpcSrv *grpc.Server

	opts          *Opts
	commonMetrics *commonMetrics

	secretmanC       csecretmanv1.MainServiceClient
	hasSecretManager bool
}

func NewServer(ctx context.Context, o *Opts) (*Server, error) {

	db, err := postgresutils.NewDB()
	if err != nil {
		return nil, errors.Errorf("Could not create a db client: %+v", err)
	}

	{
		_, err := db.Exec("SELECT current_database();")
		if err != nil {
			return nil, errors.Errorf("Could not check Postgres with SELECT current_database(): %+v", err)
		}
	}

	redisC := redisutils.NewClient()

	if err := postgresutils.Migrate(ctx, db); err != nil {
		return nil, errors.Errorf("Could not migrate database: %+v", err)
	}

	if o == nil {
		o = &Opts{}
	}

	if o.NewResourceObject == nil {
		o.NewResourceObject = vutils.NewResourceObject
	}

	if o.NewResourceObjectList == nil {
		o.NewResourceObjectList = vutils.NewResourceObjectList
	}

	commonMetrics, err := newCommonMetrics(ctx)
	if err != nil {
		return nil, err
	}

	ret := &Server{
		db:            db,
		redisC:        redisC,
		opts:          o,
		commonMetrics: commonMetrics,
	}

	/*
		if os.Getenv("OCTELIUM_USE_SECRETMAN") == "true" {
			ret.hasSecretManager = true
			addr := os.Getenv("OCTELIUM_SECRETMAN_ADDR")
			retryCodes := []codes.Code{
				codes.Unavailable,
				codes.ResourceExhausted,
				codes.Unknown,
				codes.Aborted,
				codes.DataLoss,
				codes.Internal,
				codes.DeadlineExceeded,
			}

			unaryMiddlewares := []grpc.UnaryClientInterceptor{
				grpc_retry.UnaryClientInterceptor(
					grpc_retry.WithMax(32),
					grpc_retry.WithBackoff(grpc_retry.BackoffLinear(1000*time.Millisecond)),
					grpc_retry.WithCodes(retryCodes...)),
			}

			zap.L().Info("Using secretManager", zap.String("address", addr))

			grpcConn, err := grpc.NewClient(
				addr, grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithUnaryInterceptor(grpc_middleware.ChainUnaryClient(unaryMiddlewares...)),
			)
			if err != nil {
				return nil, err
			}

			ret.secretmanC = csecretmanv1.NewMainServiceClient(grpcConn)
		}
	*/

	return ret, nil
}

type ObjectList struct {
	Items []umetav1.ResourceObjectI
}

type Opts struct {
	RegisterResourceFn func(s grpc.ServiceRegistrar) error

	PostGet func(ctx context.Context,
		req umetav1.ResourceObjectI, api, version, kind string) error

	PreCreate func(ctx context.Context,
		req umetav1.ResourceObjectI, api, version, kind string) error
	PostCreate func(ctx context.Context,
		req umetav1.ResourceObjectI, api, version, kind string) error

	PreUpdate func(ctx context.Context,
		new, old umetav1.ResourceObjectI, api, version, kind string) error
	PostUpdate func(ctx context.Context,
		new, old umetav1.ResourceObjectI, api, version, kind string) error

	PreDelete func(ctx context.Context,
		req umetav1.ResourceObjectI, api, version, kind string) error
	PostDelete func(ctx context.Context,
		req umetav1.ResourceObjectI, api, version, kind string) error

	PostList func(ctx context.Context,
		req *ObjectList, api, version, kind string) error

	NewResourceObject func(api string, version string, kind string) (umetav1.ResourceObjectI, error)

	// NewResourceWatchEvent func(api, version, kind string) (metav1.ObjectI, error)

	NewResourceObjectList func(api string, version string, kind string) (protoreflect.ProtoMessage, error)
}

func (s *Server) GetDB() *sql.DB {
	return s.db
}

func (s *Server) GetRedisC() *redis.Client {
	return s.redisC
}

func (s *Server) Run(ctx context.Context) error {
	if err := s.setSecretManager(ctx); err != nil {
		zap.L().Warn("Could not setSecretManager", zap.Error(err))
	}

	if err := func() error {
		for range 100 {
			err := s.redisC.Ping(ctx).Err()
			if err == nil {
				zap.L().Debug("Successfully ping'ed Redis server")
				return nil
			}
			zap.L().Warn("Could not ping redis. Trying again", zap.Error(err))
			time.Sleep(3 * time.Second)
		}
		return errors.Errorf("Could not ping redis")
	}(); err != nil {
		return err
	}

	s.grpcSrv = grpc.NewServer(
		grpc.MaxConcurrentStreams(1000000),
		grpc.StreamInterceptor(
			grpc_middleware.ChainStreamServer(s.handleStreamRequest)),
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(s.handleUnaryRequest)),
	)

	grpc_health_v1.RegisterHealthServer(s.grpcSrv, healthcheck.NewServer())

	{
		cacheSrv := &srvCache{
			redisC: s.redisC,
		}
		rcachev1.RegisterMainServiceServer(s.grpcSrv, cacheSrv)
	}

	{
		rateLimitSrv := &srvRateLimit{
			redisC: s.redisC,
		}
		rratelimitv1.RegisterMainServiceServer(s.grpcSrv, rateLimitSrv)
	}

	if s.opts.RegisterResourceFn != nil {
		zap.L().Debug("Running RegisterResourceFn")
		if err := s.opts.RegisterResourceFn(s.grpcSrv); err != nil {
			return err
		}
	} else {
		zap.L().Debug("Registering default gRPC servers")
		rcorev1.RegisterResourceServiceServer(s.grpcSrv, &struct {
			rcorev1.UnimplementedResourceServiceServer
		}{})
	}

	port := func() int {
		if ldflags.IsTest() {
			p, _ := strconv.Atoi(os.Getenv("OCTELIUM_TEST_RSCSERVER_PORT"))
			return p
		} else {
			return 8080
		}
	}()

	if err := vutils.WaitUntilPortIsAvailable(port); err != nil {
		return err
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}

	go func() {
		s.grpcSrv.Serve(lis)
	}()

	return nil
}

func (s *Server) Stop() {
	s.grpcSrv.Stop()
	s.redisC.Close()
}

func (s *Server) getClusterConfig(ctx context.Context) (*corev1.ClusterConfig, error) {
	ccI, err := s.doGet(ctx, &rmetav1.GetOptions{
		Name: "default",
	}, ucorev1.API, ucorev1.Version, ucorev1.KindClusterConfig)
	if err != nil {
		return nil, err
	}

	cc, ok := ccI.(*corev1.ClusterConfig)
	if !ok {
		return nil, grpcutils.Internal("Invalid ClusterConfig")
	}

	return cc, nil
}

func (s *Server) setSecretManager(ctx context.Context) error {

	cc, err := s.getClusterConfig(ctx)
	if err != nil {
		zap.L().Warn("Could not getClusterConfig. Skipping using secretManager...", zap.Error(err))
		return nil
	}

	if cc.Status == nil || cc.Status.SecretManager == nil || cc.Status.SecretManager.Address == "" {
		zap.L().Debug("secretManager config is not set")
		return nil
	}

	s.hasSecretManager = true
	addr := cc.Status.SecretManager.Address
	retryCodes := []codes.Code{
		codes.Unavailable,
		codes.ResourceExhausted,
		codes.Unknown,
		codes.Aborted,
		codes.DataLoss,
		codes.Internal,
		codes.DeadlineExceeded,
	}

	unaryMiddlewares := []grpc.UnaryClientInterceptor{
		grpc_retry.UnaryClientInterceptor(
			grpc_retry.WithMax(32),
			grpc_retry.WithBackoff(grpc_retry.BackoffLinear(1000*time.Millisecond)),
			grpc_retry.WithCodes(retryCodes...)),
	}

	zap.L().Info("Using secretManager", zap.String("address", addr))

	opts := []grpc.DialOption{
		grpc.WithUnaryInterceptor(grpc_middleware.ChainUnaryClient(unaryMiddlewares...)),
	}

	if cc.Status.SecretManager.Tls == nil {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	grpcConn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return err
	}

	s.secretmanC = csecretmanv1.NewMainServiceClient(grpcConn)

	return nil
}
