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

package octeliumc

import (
	"context"
	"fmt"
	"os"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/rsc/rcachev1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/apis/rsc/rratelimitv1"
	"github.com/octelium/octelium/cluster/common/components"
	"github.com/octelium/octelium/cluster/common/octeliumc/middlewares"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	coreC           rcorev1.ResourceServiceClient
	cacheC          rcachev1.MainServiceClient
	rateLimitC      rratelimitv1.MainServiceClient
	clusterV1UtilsC *clusterV1UtilsC
}

type CoreV1Utils interface {
	GetClusterConfig(ctx context.Context) (*corev1.ClusterConfig, error)
}

func DefaultAddr() string {
	return fmt.Sprintf("%s.octelium.svc:8080", components.OcteliumComponent(components.RscServer))
}

func DefaultDialOpts(ctx context.Context) ([]grpc.DialOption, error) {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(grpc_middleware.ChainUnaryClient(middlewares.GetUnaryInterceptors()...)),
		grpc.WithStreamInterceptor(grpc_middleware.ChainStreamClient(middlewares.GetStreamInterceptors()...)),
	}, nil
}

func NewClient(ctx context.Context) (*Client, error) {

	var host string

	if ldflags.IsTest() {
		host = fmt.Sprintf("localhost:%s", os.Getenv("OCTELIUM_TEST_RSCSERVER_PORT"))
	} else {
		host = DefaultAddr()
	}

	opts, err := DefaultDialOpts(ctx)
	if err != nil {
		return nil, err
	}

	grpcConn, err := grpc.NewClient(host, opts...)
	if err != nil {
		return nil, err
	}

	ret := &Client{
		coreC:           rcorev1.NewResourceServiceClient(grpcConn),
		cacheC:          rcachev1.NewMainServiceClient(grpcConn),
		rateLimitC:      rratelimitv1.NewMainServiceClient(grpcConn),
		clusterV1UtilsC: &clusterV1UtilsC{},
	}

	ret.clusterV1UtilsC.c = ret.coreC

	return ret, nil
}

func (c *Client) CoreC() rcorev1.ResourceServiceClient {
	return c.coreC
}

func (c *Client) CacheC() rcachev1.MainServiceClient {
	return c.cacheC
}

func (c *Client) RateLimitC() rratelimitv1.MainServiceClient {
	return c.rateLimitC
}

func (c *Client) CoreV1Utils() CoreV1Utils {
	return c.clusterV1UtilsC
}

type ClientInterface interface {
	CoreC() rcorev1.ResourceServiceClient
	CoreV1Utils() CoreV1Utils
	CacheC() rcachev1.MainServiceClient
	RateLimitC() rratelimitv1.MainServiceClient
}

type clusterV1UtilsC struct {
	c rcorev1.ResourceServiceClient
}

func (c *clusterV1UtilsC) GetClusterConfig(ctx context.Context) (*corev1.ClusterConfig, error) {
	return c.c.GetClusterConfig(ctx, &rmetav1.GetOptions{
		Name: "default",
	})
}
