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

package rdp

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	rejectReasonHandshake    = "HANDSHAKE"
	rejectReasonUpstreamDial = "UPSTREAM_DIAL"
)

type proxy struct {
	lbManager *loadbalancer.LBManager
	dctx      *dctx

	bytesToDownstream   int64
	bytesFromDownstream int64

	upstreamErr  error
	rejectReason string
}

func (p *proxy) fail(reason string, err error) {
	p.upstreamErr = err
	p.rejectReason = reason
}

func newProxy(dctx *dctx, lbManager *loadbalancer.LBManager) *proxy {
	return &proxy{
		dctx:      dctx,
		lbManager: lbManager,
	}
}

func (p *proxy) serve(ctx context.Context, secretMan *secretman.SecretManager, tlsCfg *tls.Config) {
	cred, err := GetInjectedCredential(ctx, secretMan, p.dctx.svcConfig)
	if err != nil {
		zap.L().Warn("Could not get RDP injected credential", zap.Error(err))
		p.fail(rejectReasonHandshake, err)
		return
	}

	upstream, err := p.lbManager.GetUpstream(ctx, p.dctx.authResp)
	if err != nil {
		zap.L().Warn("Could not get RDP upstream", zap.Error(err))
		p.fail(rejectReasonUpstreamDial, err)
		return
	}

	if cred == nil {
		p.servePassthrough(ctx, upstream)
		return
	}

	if !SupportsSSL(p.dctx.clientX224) {
		p.fail(rejectReasonHandshake, errors.Errorf("RDP client does not support TLS"))
		return
	}

	trust, err := GetUpstreamTLSTrust(p.dctx.svcConfig)
	if err != nil {
		zap.L().Warn("Could not get RDP upstream TLS trust", zap.Error(err))
		p.fail(rejectReasonHandshake, err)
		return
	}

	handshake, err := PerformHandshake(ctx, &HandshakeParams{
		Upstream:   upstream,
		ClientX224: p.dctx.clientX224,
		Credential: cred,
		Trust:      trust,
	})
	if err != nil {
		zap.L().Warn("Could not perform RDP handshake", zap.Error(err))
		p.fail(rejectReasonUpstreamDial, err)
		return
	}

	p.bytesToDownstream += int64(len(handshake.X224PDU))
	if _, err := p.dctx.conn.Write(handshake.X224PDU); err != nil {
		p.fail(rejectReasonHandshake, err)
		return
	}

	if !handshake.Negotiation {
		return
	}
	defer handshake.TLSConn.Close()

	if tlsCfg == nil {
		p.fail(rejectReasonHandshake, errors.Errorf("missing downstream RDP TLS config"))
		return
	}

	downstreamTLS := tls.Server(p.dctx.conn, tlsCfg)
	if err := downstreamTLS.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		p.fail(rejectReasonHandshake, err)
		return
	}

	if err := downstreamTLS.HandshakeContext(ctx); err != nil {
		p.fail(rejectReasonHandshake, err)
		return
	}

	if err := downstreamTLS.SetDeadline(time.Time{}); err != nil {
		p.fail(rejectReasonHandshake, err)
		return
	}

	receivedBytes, sentBytes := Relay(ctx, downstreamTLS, handshake.TLSConn, true)
	p.bytesFromDownstream += int64(receivedBytes) + int64(len(p.dctx.clientX224))
	p.bytesToDownstream += int64(sentBytes)
}

func (p *proxy) servePassthrough(ctx context.Context, upstream *loadbalancer.Upstream) {
	upstreamConn, x224Response, err := DialPassthrough(ctx, upstream, p.dctx.clientX224)
	if err != nil {
		zap.L().Warn("Could not connect to RDP upstream", zap.Error(err))
		p.fail(rejectReasonUpstreamDial, err)
		return
	}
	defer upstreamConn.Close()

	p.bytesFromDownstream += int64(len(p.dctx.clientX224))
	p.bytesToDownstream += int64(len(x224Response))

	if _, err := p.dctx.conn.Write(x224Response); err != nil {
		p.fail(rejectReasonHandshake, err)
		return
	}

	if IsNegotiationFailure(x224Response) {
		return
	}

	receivedBytes, sentBytes := Relay(ctx, p.dctx.conn, upstreamConn, false)
	p.bytesFromDownstream += int64(receivedBytes)
	p.bytesToDownstream += int64(sentBytes)
}
