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
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/mtls"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"go.uber.org/zap"
)

type proxy struct {
	lbManager *loadbalancer.LBManager
	dctx      *dctx
	recvBytes int64
	sentBytes int64
	wg        sync.WaitGroup
}

func newProxy(dctx *dctx, lbManager *loadbalancer.LBManager) *proxy {
	return &proxy{
		dctx:      dctx,
		lbManager: lbManager,
	}
}

func (p *proxy) serve(ctx context.Context, svc *corev1.Service, secretMan *secretman.SecretManager) {

	var conn connCloser
	if p.dctx.isTLS {
		conn = p.dctx.conn.(*tls.Conn)
	} else {
		conn = p.dctx.conn.(*net.TCPConn)
	}

	upstreamConn, err := p.getUpstreamConn(ctx, svc, secretMan)
	if err != nil {
		zap.S().Warnf("Could not get upstream conn: %+v", err)
		return
	}

	p.doServe(conn, upstreamConn)
	zap.S().Debugf("Done serving dctx: %s, recv: %d - sent: %d", p.dctx.id, p.recvBytes, p.sentBytes)
}

func (p *proxy) getUpstreamConn(ctx context.Context, svc *corev1.Service, secretMan *secretman.SecretManager) (connCloser, error) {

	upstream, err := p.lbManager.GetUpstream(ctx, p.dctx.authResp)
	if err != nil {
		return nil, err
	}

	if p.dctx.svcConfig != nil &&
		p.dctx.svcConfig.ClientCertificate != nil {
		tlsCfg, err := mtls.GetClientTLSCfg(ctx, svc, p.dctx.svcConfig, secretMan, upstream)
		if err != nil {
			return nil, err
		}
		return tls.Dial("tcp", upstream.HostPort, tlsCfg)
	}

	ret, err := net.DialTimeout("tcp", upstream.HostPort, 20*time.Second)
	if err != nil {
		return nil, err
	}
	return ret.(*net.TCPConn), nil

}

func (p *proxy) doServe(conn, connBackend connCloser) {
	defer connBackend.Close()

	p.wg.Add(2)
	go p.connCopy(conn, connBackend, true)
	go p.connCopy(connBackend, conn, false)
	p.wg.Wait()
}

func (p *proxy) connCopy(dst, src connCloser, isRecv bool) {
	defer p.wg.Done()

	n, _ := io.Copy(dst, src)
	if isRecv {
		p.recvBytes = n
	} else {
		p.sentBytes = n
	}

	if err := dst.CloseWrite(); err != nil {
		zap.S().Debugf("Could not closeWrite dst: %+v", err)
		return
	}

	if err := dst.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		zap.S().Debugf("Could not set read deadline: %+v", err)
	}

}

type connCloser interface {
	net.Conn
	CloseWrite() error
}
