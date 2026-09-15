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

package modes

import (
	"context"
	"runtime/debug"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"go.uber.org/zap"
)

func Recover(fns ...func(any)) {
	if err := recover(); err != nil {
		zap.L().Error("Recovered from Vigil connection panic",
			zap.Any("error", err),
			zap.ByteString("stack", debug.Stack()))
		for _, fn := range fns {
			fn(err)
		}
	}
}

type Server interface {
	Run(ctx context.Context) error
	Close() error
	SetClusterCertificate(crt *corev1.Secret) error
}

type Opts struct {
	OcteliumC  octeliumc.ClientInterface
	OctovigilC *octovigilc.Client
	VCache     *vcache.Cache
	SecretMan  *secretman.SecretManager
	LBManager  *loadbalancer.LBManager

	PostAuthorize func(ctx context.Context, req *PostAuthorizeRequest) (*PostAuthorizeResponse, error)
	GetUpstream   func(ctx context.Context, opts *Opts, reqCtx *corev1.RequestContext) (*loadbalancer.Upstream, error)
}

type PostAuthorizeRequest struct {
	Request *coctovigilv1.DownstreamRequest
	Resp    *coctovigilv1.AuthenticateAndAuthorizeResponse
}

type PostAuthorizeResponse struct {
	IsAuthorized bool
}
