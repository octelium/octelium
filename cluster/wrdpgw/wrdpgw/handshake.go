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

package wrdpgw

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	x224HandshakeTimeout = 15 * time.Second
	tlsHandshakeTimeout  = 15 * time.Second
)

type injectedCredential struct {
	Domain   string
	Username string
	Password string
}

type rdpHandshakeParams struct {
	upstream   *loadbalancer.Upstream
	clientX224 []byte
	cred       *injectedCredential
	trust      *tlsTrustPolicy
}

type rdpHandshakeResult struct {
	TLSConn     *tls.Conn
	X224PDU     []byte
	CertChain   [][]byte
	ServerAddr  string
	Negotiation bool
}

func performRDPHandshake(ctx context.Context, p *rdpHandshakeParams) (*rdpHandshakeResult, error) {
	if p.upstream == nil || p.upstream.HostPort == "" {
		return nil, errors.Errorf("empty RDP upstream")
	}

	if p.trust == nil {
		return nil, errors.Errorf("missing upstream TLS trust policy")
	}

	secretless := p.cred != nil

	var x224Request []byte
	if secretless {
		x224Request = buildX224ConnectionRequest(protocolHybrid | protocolSSL)
	} else {
		if len(p.clientX224) == 0 {
			return nil, errors.Errorf("empty client X.224 connection request")
		}
		x224Request = p.clientX224
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	var dialer net.Dialer
	dialer.KeepAlive = 30 * time.Second

	rawConn, err := dialer.DialContext(dialCtx, "tcp", p.upstream.HostPort)
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
			zap.L().Debug("Could not enable wrdpgw TCP keepalive", zap.Error(err))
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			zap.L().Debug("Could not set wrdpgw TCP keepalive period", zap.Error(err))
		}
	}

	if err := rawConn.SetDeadline(time.Now().Add(x224HandshakeTimeout)); err != nil {
		return nil, err
	}

	zap.L().Debug("Performing RDP handshake with upstream",
		zap.String("upstream", p.upstream.HostPort),
		zap.Bool("secretless", secretless),
		zap.Int("requestLength", len(x224Request)),
		zap.String("requestHex", fmt.Sprintf("%x", x224Request)))

	if _, err := rawConn.Write(x224Request); err != nil {
		return nil, err
	}

	zap.L().Debug("RDP handshake X.224 request sent",
		zap.String("upstream", p.upstream.HostPort),
		zap.Bool("secretless", secretless),
		zap.Int("requestLength", len(x224Request)),
		zap.String("requestHex", fmt.Sprintf("%x", x224Request)))

	x224Response, err := readTPKT(rawConn)
	if err != nil {
		return nil, err
	}

	zap.L().Debug("RDP handshake X.224 response received",
		zap.String("upstream", p.upstream.HostPort),
		zap.Bool("secretless", secretless),
		zap.Int("responseLength", len(x224Response)),
		zap.String("responseHex", fmt.Sprintf("%x", x224Response)))

	if isRDPNegotiationFailure(x224Response) {
		return &rdpHandshakeResult{
			X224PDU:     x224Response,
			ServerAddr:  p.upstream.HostPort,
			Negotiation: false,
		}, nil
	}

	selected, ok := rdpConfirmSelectedProtocol(x224Response)
	if !ok {
		return nil, errors.Errorf("invalid X.224 connection confirm")
	}

	zap.L().Debug("RDP handshake X.224 confirm selected protocol",
		zap.String("upstream", p.upstream.HostPort),
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

	tlsConn := tls.Client(rawConn, buildUpstreamTLSConfig(p.upstream, p.trust))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		zap.L().Debug("Could not complete TLS handshake with upstream",
			zap.String("upstream", p.upstream.HostPort),
			zap.Bool("secretless", secretless),
			zap.Error(err))
		return nil, err
	}

	x224ForBrowser := x224Response

	if secretless {
		spki := getPeerLeafSPKI(tlsConn)
		if len(spki) == 0 {
			return nil, errors.Errorf("could not extract upstream public key")
		}

		zap.L().Debug("Performing CredSSP handshake with upstream",
			zap.String("upstream", p.upstream.HostPort),
			zap.Bool("secretless", secretless),
			zap.String("credsspTarget", credsspTarget(p.upstream)),
			zap.Int("spkiLength", len(spki)),
			zap.String("spkiHex", fmt.Sprintf("%x", spki)))

		if err := driveCredSSP(tlsConn, p.cred, spki, credsspTarget(p.upstream)); err != nil {
			return nil, err
		}

		zap.L().Debug("CredSSP handshake with upstream completed",
			zap.String("upstream", p.upstream.HostPort),
			zap.Bool("secretless", secretless),
			zap.String("credsspTarget", credsspTarget(p.upstream)),
			zap.Int("spkiLength", len(spki)),
			zap.String("spkiHex", fmt.Sprintf("%x", spki)))

		synthetic, err := synthesizeSSLConfirm(x224Response)
		if err != nil {
			return nil, err
		}

		zap.L().Debug("Synthesized X.224 connection confirm for browser",
			zap.String("upstream", p.upstream.HostPort),
			zap.Bool("secretless", secretless),
			zap.Int("syntheticLength", len(synthetic)),
			zap.String("syntheticHex", fmt.Sprintf("%x", synthetic)))
		x224ForBrowser = synthetic
	}

	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	connClosed = false

	return &rdpHandshakeResult{
		TLSConn:     tlsConn,
		X224PDU:     x224ForBrowser,
		CertChain:   getPeerCertChain(tlsConn),
		ServerAddr:  p.upstream.HostPort,
		Negotiation: true,
	}, nil
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
