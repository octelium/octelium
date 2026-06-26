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
	"sync"
	"time"

	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	xproxy "golang.org/x/net/proxy"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type proxy struct {
	lbManager *loadbalancer.LBManager
	dctx      *dctx

	recvBytes int64
	sentBytes int64

	wg sync.WaitGroup
}

func newProxy(dctx *dctx, lbManager *loadbalancer.LBManager) *proxy {
	return &proxy{
		dctx:      dctx,
		lbManager: lbManager,
	}
}

func (p *proxy) serve(ctx context.Context, svc *corev1.Service, secretMan *secretman.SecretManager) error {
	upstreamConn, err := p.getUpstreamConn(ctx, svc, secretMan)
	if err != nil {
		zap.L().Warn("Could not get SOCKS5 upstream conn",
			zap.String("id", p.dctx.id),
			zap.String("target", p.dctx.target.addr),
			zap.Error(err))

		gosocks5.SendReply(p.dctx.downstreamWriter, statute.RepServerFailure, nil)
		return err
	}

	defer upstreamConn.Close()

	if err := gosocks5.SendReply(p.dctx.downstreamWriter, statute.RepSuccess, upstreamConn.LocalAddr()); err != nil {
		return err
	}

	p.doServe(p.dctx.downstreamWriter, p.dctx.downstreamReader, upstreamConn)

	zap.L().Debug("Done serving SOCKS5 connection",
		zap.String("id", p.dctx.id),
		zap.String("target", p.dctx.target.addr),
		zap.Int64("received", p.recvBytes),
		zap.Int64("sent", p.sentBytes))

	return nil
}

func (p *proxy) getUpstreamConn(
	ctx context.Context,
	svc *corev1.Service,
	secretMan *secretman.SecretManager,
) (net.Conn, error) {
	upstream, err := p.lbManager.GetUpstream(ctx, p.dctx.authResp)
	if err != nil {
		return nil, err
	}

	p.dctx.upstreamHost = upstream.Host
	p.dctx.upstreamPort = int(upstream.Port)

	if p.dctx.svcConfig == nil || p.dctx.svcConfig.GetSocks5() == nil {
		return nil, errors.Errorf("no SOCKS5 config")
	}

	cfg := p.dctx.svcConfig.GetSocks5()

	var auth *xproxy.Auth
	if cfg.GetAuth().GetUsernamePassword() != nil {
		up := cfg.GetAuth().GetUsernamePassword()
		if up.Username == "" {
			return nil, errors.Errorf("SOCKS5 upstream username is empty")
		}
		if up.Password.GetFromSecret() == "" {
			return nil, errors.Errorf("SOCKS5 upstream password secret is empty")
		}

		passwordSecret, err := secretMan.GetByName(ctx, up.Password.GetFromSecret())
		if err != nil {
			return nil, err
		}

		auth = &xproxy.Auth{
			User:     up.Username,
			Password: ucorev1.ToSecret(passwordSecret).GetValueStr(),
		}
	}

	forward := &upstreamDialer{
		ctx:     ctx,
		timeout: 20 * time.Second,
	}

	dialer, err := xproxy.SOCKS5("tcp", upstream.HostPort, auth, forward)
	if err != nil {
		return nil, err
	}

	conn, err := dialer.Dial("tcp", p.dctx.target.addr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (p *proxy) doServe(clientWriter io.Writer, clientReader io.Reader, upstreamConn net.Conn) {
	p.wg.Add(2)

	go p.connCopy(upstreamConn, clientReader, true)
	go p.connCopy(clientWriter, upstreamConn, false)

	p.wg.Wait()
}

func (p *proxy) connCopy(dst io.Writer, src io.Reader, isRecv bool) {
	defer p.wg.Done()

	n, err := io.Copy(dst, src)
	if err != nil && !isExpectedNetErr(err) {
		zap.L().Debug("SOCKS5 copy error",
			zap.String("id", p.dctx.id),
			zap.Bool("isRecv", isRecv),
			zap.Error(err))
	}

	if isRecv {
		p.recvBytes = n
	} else {
		p.sentBytes = n
	}

	if err := closeWrite(dst); err != nil {
		zap.L().Debug("Could not closeWrite",
			zap.String("id", p.dctx.id),
			zap.Error(err))
	}

	if c, ok := dst.(interface{ SetReadDeadline(time.Time) error }); ok {
		if err := c.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			zap.L().Debug("Could not set read deadline",
				zap.String("id", p.dctx.id),
				zap.Error(err))
		}
	}
}

type upstreamDialer struct {
	ctx     context.Context
	timeout time.Duration
}

func (d *upstreamDialer) Dial(network, addr string) (net.Conn, error) {
	var nd net.Dialer
	nd.Timeout = d.timeout
	return nd.DialContext(d.ctx, network, addr)
}

func closeWrite(conn any) error {
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

type closeWriter interface {
	CloseWrite() error
}

func isExpectedNetErr(err error) bool {
	if err == nil {
		return true
	}
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

var _ xproxy.Dialer = (*upstreamDialer)(nil)
