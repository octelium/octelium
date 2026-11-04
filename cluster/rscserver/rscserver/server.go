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
	"sync"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	_ "github.com/lib/pq"
	"github.com/octelium/octelium/apis/cluster/csecretmanv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rlockv1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/apis/rsc/rpubsubv1"
	"github.com/octelium/octelium/apis/rsc/rratelimitv1"
	"github.com/octelium/octelium/apis/rsc/rvectorv1"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/cluster/common/postgresutils"
	"github.com/octelium/octelium/cluster/common/redisutils"
	"github.com/octelium/octelium/cluster/common/spiffec"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type Server struct {
	db *sql.DB

	redisC  *redis.Client
	grpcSrv *grpc.Server

	eventHub *eventHub

	pubSubSrv *srvPubSub

	opts          *Opts
	commonMetrics *commonMetrics

	secretmanC       csecretmanv1.MainServiceClient
	hasSecretManager bool
}

type startupDialer struct {
	ctx      context.Context
	mu       sync.Mutex
	finished bool
	stops    []func() bool
}

func (d *startupDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	if !d.finished {
		d.stops = append(d.stops, context.AfterFunc(d.ctx, func() {
			d.mu.Lock()
			defer d.mu.Unlock()
			if !d.finished {
				conn.Close()
			}
		}))
	}
	d.mu.Unlock()
	return conn, nil
}

func (d *startupDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *startupDialer) DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialContext(ctx, network, address)
}

func (d *startupDialer) finish() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.finished = true
	for _, stop := range d.stops {
		stop()
	}
	d.stops = nil
	d.ctx = nil
}

func NewServer(ctx context.Context, o *Opts) (_ *Server, retErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dialer := &startupDialer{ctx: ctx}
	defer dialer.finish()
	db, err := postgresutils.NewDBWithDialer(dialer)
	if err != nil {
		return nil, errors.Errorf("Could not create a db client: %+v", err)
	}
	defer func() {
		if retErr != nil {
			db.Close()
		}
	}()
	connection, err := db.Conn(ctx)
	if err == nil {
		err = connection.Close()
	}
	dialer.finish()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, errors.Wrap(err, "Could not connect to Postgres")
	}

	{
		_, err := db.ExecContext(ctx, "SELECT current_database();")
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			return nil, errors.Wrap(err, "Could not check Postgres with SELECT current_database()")
		}
	}

	redisC := redisutils.NewClient()
	defer func() {
		if retErr != nil {
			redisC.Close()
		}
	}()

	if err := postgresutils.Migrate(ctx, db); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.Wrap(err, "Could not migrate database")
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ret := &Server{
		db:            db,
		redisC:        redisC,
		eventHub:      newEventHub(redisC),
		opts:          o,
		commonMetrics: commonMetrics,
	}

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
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.setSecretManager(ctx); err != nil {
		zap.L().Warn("Could not setSecretManager", zap.Error(err))
	}

	if err := func() error {
		for range 100 {
			if err := ctx.Err(); err != nil {
				return err
			}
			err := s.redisC.Ping(ctx).Err()
			if err == nil {
				zap.L().Debug("Successfully ping'ed Redis server")
				return ctx.Err()
			}
			zap.L().Warn("Could not ping redis. Trying again", zap.Error(err))
			timer := time.NewTimer(3 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return errors.Errorf("Could not ping redis")
	}(); err != nil {
		return err
	}

	cred, err := spiffec.GetGRPCServerCred(ctx, nil)
	if err != nil {
		return err
	}

	s.grpcSrv = grpc.NewServer(
		cred,
		grpc.ReadBufferSize(32*1024),
		grpc.MaxConcurrentStreams(1000000),
		grpc.ChainStreamInterceptor(s.handleStreamRequest),
		grpc.ChainUnaryInterceptor(s.handleUnaryRequest),
	)

	// grpc_health_v1.RegisterHealthServer(s.grpcSrv, healthcheck.NewServer())

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

	{
		lockSrv := &srvLock{
			redisC: s.redisC,
		}
		rlockv1.RegisterMainServiceServer(s.grpcSrv, lockSrv)
	}

	{
		vectorSrv := newSrvVector(ctx, s.redisC)
		rvectorv1.RegisterMainServiceServer(s.grpcSrv, vectorSrv)
	}

	{
		s.pubSubSrv = newSrvPubSub(s.redisC)
		rpubsubv1.RegisterMainServiceServer(s.grpcSrv, s.pubSubSrv)
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

	if err := vutils.WaitUntilPortIsAvailableContext(ctx, port); err != nil {
		return err
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		lis.Close()
		return err
	}

	if err := s.eventHub.Start(ctx); err != nil {
		lis.Close()
		return err
	}
	if err := ctx.Err(); err != nil {
		lis.Close()
		return err
	}

	go func() {
		s.grpcSrv.Serve(lis)
	}()

	return nil
}

func (s *Server) Stop() {
	s.eventHub.Stop()

	if s.grpcSrv != nil {
		s.grpcSrv.Stop()
	}

	if s.pubSubSrv != nil {
		s.pubSubSrv.close()
	}

	if s.redisC != nil {
		s.redisC.Close()
	}

	if s.db != nil {
		s.db.Close()
	}
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
		grpc.WithChainUnaryInterceptor(unaryMiddlewares...),
	}

	cred, err := spiffec.GetGRPCClientCred(ctx, nil)
	if err != nil {
		return err
	}

	opts = append(opts, cred)

	grpcConn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return err
	}

	s.secretmanC = csecretmanv1.NewMainServiceClient(grpcConn)

	return nil
}
