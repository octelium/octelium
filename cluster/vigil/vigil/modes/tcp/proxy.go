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
	"github.com/octelium/octelium/cluster/common/otelutils"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/mtls"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"go.uber.org/zap"
)

const upstreamDialTimeout = 20 * time.Second

type proxy struct {
	lbManager *loadbalancer.LBManager
	dctx      *dctx
	wg        sync.WaitGroup

	bytesToDownstream   int64
	bytesFromDownstream int64

	upstreamErr error
}

func newProxy(dctx *dctx, lbManager *loadbalancer.LBManager) *proxy {
	return &proxy{
		dctx:      dctx,
		lbManager: lbManager,
	}
}

func (p *proxy) serve(ctx context.Context, svc *corev1.Service, secretMan *secretman.SecretManager, startTime time.Time) {
	conn := p.dctx.conn

	upstreamConn, err := p.getUpstreamConn(ctx, svc, secretMan)
	if err != nil {
		zap.L().Warn("Could not get upstream conn", zap.Error(err))
		p.upstreamErr = err
		return
	}

	p.dctx.network = logentry.WithUpstream(p.dctx.network, upstreamConn)

	stop := context.AfterFunc(ctx, func() {
		conn.Close()
		upstreamConn.Close()
	})
	defer stop()

	logE := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
		StartTime:       startTime,
		IsAuthenticated: true,
		IsAuthorized:    true,
		ReqCtx:          p.dctx.authResp.RequestContext,
		ConnectionID:    p.dctx.id,
		Reason:          p.dctx.authResp.AuthorizationDecisionReason,
		Network:         p.dctx.network,
	})
	logE.Entry.Info.Type = &corev1.AccessLog_Entry_Info_Tcp{
		Tcp: &corev1.AccessLog_Entry_Info_TCP{
			Type: corev1.AccessLog_Entry_Info_TCP_CONNECTED,
		},
	}
	otelutils.EmitAccessLog(logE)

	p.doServe(conn, upstreamConn)
	zap.L().Debug("Done serving",
		zap.String("id", p.dctx.id),
		zap.Int64("bytesFromDownstream", p.bytesFromDownstream),
		zap.Int64("bytesToDownstream", p.bytesToDownstream))
}

func (p *proxy) getUpstreamConn(ctx context.Context, svc *corev1.Service, secretMan *secretman.SecretManager) (net.Conn, error) {
	upstream, err := p.lbManager.GetUpstream(ctx, p.dctx.authResp)
	if err != nil {
		return nil, err
	}

	tlsCfg, err := mtls.GetClientTLSCfg(ctx, svc, p.dctx.svcConfig, secretMan, upstream)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, upstreamDialTimeout)
	defer cancel()

	dialer := &net.Dialer{
		Timeout: upstreamDialTimeout,
	}

	if tlsCfg == nil && !isUpstreamTLS(upstream) {
		return dialer.DialContext(ctx, "tcp", upstream.HostPort)
	}

	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
			ServerName: upstream.SNIHost,
		}
	}

	tlsDialer := &tls.Dialer{
		NetDialer: dialer,
		Config:    tlsCfg,
	}

	return tlsDialer.DialContext(ctx, "tcp", upstream.HostPort)
}

func isUpstreamTLS(upstream *loadbalancer.Upstream) bool {
	if upstream.URL == nil {
		return false
	}

	switch upstream.URL.Scheme {
	case "tls", "https":
		return true
	default:
		return false
	}
}

func (p *proxy) doServe(clientConn, backendConn net.Conn) {
	defer backendConn.Close()

	p.wg.Add(2)
	go p.connCopy(clientConn, backendConn, true)
	go p.connCopy(backendConn, clientConn, false)
	p.wg.Wait()
}

func (p *proxy) connCopy(dst, src net.Conn, isToDownstream bool) {
	defer p.wg.Done()
	defer modes.Recover(func(any) {
		dst.Close()
		src.Close()
	})

	n, err := io.Copy(dst, src)
	if isToDownstream {
		p.bytesToDownstream = n
	} else {
		p.bytesFromDownstream = n
	}

	if err != nil {
		dst.Close()
		src.Close()
		return
	}

	if err := closeWrite(dst); err != nil {
		zap.L().Debug("Could not closeWrite dst", zap.String("id", p.dctx.id), zap.Error(err))
		dst.Close()
		src.Close()
	}
}

func closeWrite(conn net.Conn) error {
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return conn.Close()
}

type closeWriter interface {
	CloseWrite() error
}
