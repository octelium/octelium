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

package octovigilc

import (
	"context"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/octovigilc"
	"github.com/octelium/octelium/cluster/octovigil/octovigil"
	"github.com/octelium/octelium/cluster/octovigil/octovigil/acache"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type Client struct {
	embeddedSrv *octovigil.Server
	isEmbedded  bool
	vCache      *vcache.Cache
	svcUID      string

	remoteC octovigilc.ClientInterface
}

type Opts struct {
	OcteliumC octeliumc.ClientInterface
	VCache    *vcache.Cache
}

func NewClient(ctx context.Context, opts *Opts) (*Client, error) {

	if opts == nil {
		return nil, errors.Errorf("Nil opts")
	}

	if opts.VCache == nil {
		return nil, errors.Errorf("Nil vCache")
	}

	if ldflags.IsTest() {
		if opts.OcteliumC == nil {
			return nil, errors.Errorf("Nil octeliumC")
		}

		zap.L().Debug("Creating an internal Octovigil client")
		srv, err := octovigil.New(ctx, opts.OcteliumC)
		if err != nil {
			return nil, err
		}
		return &Client{
			isEmbedded:  true,
			embeddedSrv: srv,
			vCache:      opts.VCache,
			svcUID:      opts.VCache.GetService().Metadata.Uid,
		}, nil
	}

	zap.L().Debug("Creating a new Octovigil client to a remote server")

	client, err := octovigilc.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	return &Client{
		vCache:  opts.VCache,
		svcUID:  opts.VCache.GetService().Metadata.Uid,
		remoteC: client,
	}, nil

}

func (c *Client) AuthenticateAndAuthorize(ctx context.Context, req *AuthenticateAndAuthorizeRequest) (*coctovigilv1.AuthenticateAndAuthorizeResponse, error) {
	if c.isEmbedded {
		return c.embeddedSrv.AuthenticateAndAuthorize(ctx, &coctovigilv1.DoAuthenticateAndAuthorizeRequest{
			Service: c.vCache.GetService(),
			Request: req.Request,
		})
	} else {
		// zap.L().Debug("Starting a remote AuthenticateAndAuthorize")
		return c.remoteC.InternalC().AuthenticateAndAuthorize(ctx, &coctovigilv1.AuthenticateAndAuthorizeRequest{
			ServiceUID: c.svcUID,
			Request:    req.Request,
		})
	}
}

func (c *Client) Authorize(ctx context.Context, req *coctovigilv1.AuthorizeRequest) (*coctovigilv1.AuthorizeResponse, error) {
	if c.isEmbedded {
		di, err := c.embeddedSrv.GetCache().GetDownstreamInfoBySessionIdentifier(req.SessionUID)
		if err != nil {
			return nil, err
		}

		reqCtx := &corev1.RequestContext{
			Service: c.vCache.GetService(),
			Session: di.Session,
			User:    di.User,
			Groups:  di.Groups,
			Device:  di.Device,
			Request: req.Request,
		}

		reqCtx.Namespace, _ = c.embeddedSrv.GetCache().GetNamespace(reqCtx.Service.Status.NamespaceRef.Uid)

		return c.embeddedSrv.DoAuthorize(ctx, reqCtx)
	} else {
		// zap.L().Debug("Starting a remote Authorize")
		return c.remoteC.InternalC().Authorize(ctx, &coctovigilv1.AuthorizeRequest{
			ServiceUID: c.svcUID,
			SessionUID: req.SessionUID,
			Request:    req.Request,
		})
	}
}

type AuthenticateAndAuthorizeRequest struct {
	Request *coctovigilv1.DownstreamRequest
}

func (c *Client) GetCache() *acache.Cache {
	if c.isEmbedded {
		return c.embeddedSrv.GetCache()
	}
	return nil
}
