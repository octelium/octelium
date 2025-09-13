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

package udp

import (
	"net"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"go.uber.org/zap"
)

type dctx struct {
	id           string
	sessUID      string
	addr         *net.UDPAddr
	connUpstream *net.UDPConn

	createdAt time.Time
	i         *corev1.RequestContext
}

func newDctx(addr *net.UDPAddr, i *corev1.RequestContext) *dctx {
	return &dctx{
		id:        vutils.GenerateLogID(),
		sessUID:   i.Session.Metadata.Uid,
		addr:      addr,
		createdAt: time.Now(),
		i:         i,
	}
}

func (c *dctx) close() error {
	zap.L().Debug("Closing dctx", zap.String("id", c.id))
	if c.connUpstream != nil {
		c.connUpstream.Close()
	}

	zap.L().Debug("dctx closed", zap.String("id", c.id))

	return nil
}
