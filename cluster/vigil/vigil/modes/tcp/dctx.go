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

package tcp

import (
	"context"
	"net"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vigilutils"
)

type dctx struct {
	id        string
	sessUID   string
	conn      net.Conn
	proxy     *proxy
	createdAt time.Time
	isTLS     bool

	svcConfig *corev1.Service_Spec_Config
	authResp  *coctovigilv1.AuthenticateAndAuthorizeResponse
}

func newDctx(ctx context.Context,
	conn net.Conn, i *corev1.RequestContext,
	authResp *coctovigilv1.AuthenticateAndAuthorizeResponse) *dctx {
	return &dctx{
		id:        vutils.GenerateLogID(),
		sessUID:   i.Session.Metadata.Uid,
		conn:      conn,
		isTLS:     authResp.RequestContext.Service.Spec.IsTLS,
		createdAt: time.Now(),
		svcConfig: vigilutils.GetServiceConfig(ctx, authResp),
		authResp:  authResp,
	}
}

func (c *dctx) close() error {
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn = nil
	return nil
}

func (c *dctx) serve(ctx context.Context, lbManager *loadbalancer.LBManager, svc *corev1.Service, secretMan *secretman.SecretManager) {
	c.proxy = newProxy(c, lbManager)
	c.proxy.serve(ctx, svc, secretMan)
}
