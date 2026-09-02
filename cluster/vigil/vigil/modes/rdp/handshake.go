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
	"net"
	"time"

	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	dialTimeout          = 20 * time.Second
	x224HandshakeTimeout = 15 * time.Second
	tlsHandshakeTimeout  = 15 * time.Second
)

type Credential struct {
	Domain   string
	Username string
	Password string
}

type HandshakeParams struct {
	Upstream   *loadbalancer.Upstream
	ClientX224 []byte
	Credential *Credential
	Trust      *TLSTrustPolicy
}

type HandshakeResult struct {
	TLSConn     *tls.Conn
	X224PDU     []byte
	CertChain   [][]byte
	ServerAddr  string
	Negotiation bool
}

func PerformHandshake(ctx context.Context, p *HandshakeParams) (*HandshakeResult, error) {
	if p == nil {
		return nil, errors.Errorf("missing RDP handshake params")
	}

	if p.Upstream == nil || p.Upstream.HostPort == "" {
		return nil, errors.Errorf("empty RDP upstream")
	}

	if p.Trust == nil {
		return nil, errors.Errorf("missing upstream TLS trust policy")
	}

	secretless := p.Credential != nil

	var x224Request []byte
	if secretless {
		x224Request = buildX224ConnectionRequest(protocolHybrid | protocolSSL)
	} else {
		if len(p.ClientX224) == 0 {
			return nil, errors.Errorf("empty client X.224 connection request")
		}
		x224Request = p.ClientX224
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	var dialer net.Dialer
	dialer.KeepAlive = 30 * time.Second

	rawConn, err := dialer.DialContext(dialCtx, "tcp", p.Upstream.HostPort)
	if err != nil {
		return nil, err
	}

	connClosed := true
	defer func() {
		if connClosed {
			rawConn.Close()
		}
	}()

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			zap.L().Debug("Could not enable RDP TCP keepalive", zap.Error(err))
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			zap.L().Debug("Could not set RDP TCP keepalive period", zap.Error(err))
		}
	}

	if err := rawConn.SetDeadline(time.Now().Add(x224HandshakeTimeout)); err != nil {
		return nil, err
	}

	zap.L().Debug("Performing RDP handshake with upstream",
		zap.String("upstream", p.Upstream.HostPort),
		zap.Bool("secretless", secretless),
		zap.Int("requestLength", len(x224Request)))

	if _, err := rawConn.Write(x224Request); err != nil {
		return nil, err
	}

	x224Response, err := ReadTPKT(rawConn)
	if err != nil {
		return nil, err
	}

	zap.L().Debug("RDP handshake X.224 response received",
		zap.String("upstream", p.Upstream.HostPort),
		zap.Bool("secretless", secretless),
		zap.Int("responseLength", len(x224Response)))

	if IsNegotiationFailure(x224Response) {
		return &HandshakeResult{
			X224PDU:     x224Response,
			ServerAddr:  p.Upstream.HostPort,
			Negotiation: false,
		}, nil
	}

	selected, ok := rdpConfirmSelectedProtocol(x224Response)
	if !ok {
		return nil, errors.Errorf("invalid X.224 connection confirm")
	}

	zap.L().Debug("RDP handshake X.224 confirm selected protocol",
		zap.String("upstream", p.Upstream.HostPort),
		zap.Bool("secretless", secretless),
		zap.Int("selectedProtocol", int(selected)))

	if secretless {
		if selected&protocolHybrid == 0 {
			return nil, errors.Errorf("upstream did not select CredSSP/HYBRID for secretless access")
		}
	} else {
		if selected == protocolRDP {
			return nil, errors.Errorf("upstream selected standard RDP security which is unsupported")
		}
	}

	if err := rawConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, buildUpstreamTLSConfig(p.Upstream, p.Trust))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		zap.L().Debug("Could not complete TLS handshake with upstream",
			zap.String("upstream", p.Upstream.HostPort),
			zap.Bool("secretless", secretless),
			zap.Error(err))
		return nil, err
	}

	x224ForDownstream := x224Response

	if secretless {
		serverPublicKey, err := getPeerLeafCredSSPPublicKey(tlsConn)
		if err != nil {
			return nil, err
		}

		if err := driveCredSSP(tlsConn, p.Credential, serverPublicKey, credsspTarget(p.Upstream)); err != nil {
			return nil, err
		}

		zap.L().Debug("CredSSP handshake with upstream completed",
			zap.String("upstream", p.Upstream.HostPort),
			zap.Bool("secretless", secretless),
			zap.String("credsspTarget", credsspTarget(p.Upstream)))

		synthetic, err := synthesizeSSLConfirm(x224Response)
		if err != nil {
			return nil, err
		}

		zap.L().Debug("Synthesized X.224 connection confirm for downstream",
			zap.String("upstream", p.Upstream.HostPort),
			zap.Bool("secretless", secretless),
			zap.Int("syntheticLength", len(synthetic)))
		x224ForDownstream = synthetic
	}

	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	connClosed = false

	return &HandshakeResult{
		TLSConn:     tlsConn,
		X224PDU:     x224ForDownstream,
		CertChain:   getPeerCertChain(tlsConn),
		ServerAddr:  p.Upstream.HostPort,
		Negotiation: true,
	}, nil
}

func DialPassthrough(ctx context.Context, upstream *loadbalancer.Upstream,
	clientX224 []byte) (net.Conn, []byte, error) {
	if upstream == nil || upstream.HostPort == "" {
		return nil, nil, errors.Errorf("empty RDP upstream")
	}

	if err := ValidateConnectionRequest(clientX224); err != nil {
		return nil, nil, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	var dialer net.Dialer
	dialer.KeepAlive = 30 * time.Second

	rawConn, err := dialer.DialContext(dialCtx, "tcp", upstream.HostPort)
	if err != nil {
		return nil, nil, err
	}

	connClosed := true
	defer func() {
		if connClosed {
			rawConn.Close()
		}
	}()

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			zap.L().Debug("Could not enable RDP TCP keepalive", zap.Error(err))
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			zap.L().Debug("Could not set RDP TCP keepalive period", zap.Error(err))
		}
	}

	if err := rawConn.SetDeadline(time.Now().Add(x224HandshakeTimeout)); err != nil {
		return nil, nil, err
	}

	if _, err := rawConn.Write(clientX224); err != nil {
		return nil, nil, err
	}

	x224Response, err := ReadTPKT(rawConn)
	if err != nil {
		return nil, nil, err
	}

	if err := rawConn.SetDeadline(time.Time{}); err != nil {
		return nil, nil, err
	}

	connClosed = false

	return rawConn, x224Response, nil
}

func credsspTarget(upstream *loadbalancer.Upstream) string {
	host := upstream.Host
	if host == "" {
		if h, _, err := net.SplitHostPort(upstream.HostPort); err == nil {
			host = h
		} else {
			host = upstream.HostPort
		}
	}

	return "TERMSRV/" + host
}
