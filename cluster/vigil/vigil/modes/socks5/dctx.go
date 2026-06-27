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

package socks5

import (
	"context"
	"io"
	"net"
	"time"

	gosocks5 "github.com/things-go/go-socks5"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
)

type dctx struct {
	id      string
	sessUID string

	conn             net.Conn
	downstreamWriter io.Writer
	downstreamReader io.Reader

	req    *gosocks5.Request
	target *target

	proxy     *proxy
	createdAt time.Time

	svcConfig *corev1.Service_Spec_Config
	authResp  *coctovigilv1.AuthenticateAndAuthorizeResponse

	upstreamSession *corev1.Session

	upstreamHost string
	upstreamPort int
}

func newDctx(
	ctx context.Context,
	conn net.Conn,
	downstreamWriter io.Writer,
	downstreamReader io.Reader,
	target *target,
	authResp *coctovigilv1.AuthenticateAndAuthorizeResponse,
	svcConfig *corev1.Service_Spec_Config,
	upstreamSession *corev1.Session,
) *dctx {
	return &dctx{
		id:               vutils.GenerateLogID(),
		sessUID:          authResp.RequestContext.Session.Metadata.Uid,
		conn:             conn,
		downstreamWriter: downstreamWriter,
		downstreamReader: downstreamReader,
		req:              target.req,
		target:           target,
		createdAt:        time.Now(),
		svcConfig:        svcConfig,
		authResp:         authResp,
		upstreamSession:  upstreamSession,
	}
}

func (c *dctx) close() error {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	return nil
}

func (c *dctx) serve(
	ctx context.Context,
	lbManager *loadbalancer.LBManager,
	svc *corev1.Service,
	secretMan *secretman.SecretManager,
) error {
	c.proxy = newProxy(c, lbManager)
	return c.proxy.serve(ctx, svc, secretMan)
}
