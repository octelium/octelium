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
	"io"
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

type rdpHandshakeResult struct {
	TLSConn     *tls.Conn
	X224PDU     []byte
	CertChain   [][]byte
	ServerAddr  string
	Negotiation bool
}

func performRDPHandshake(
	ctx context.Context,
	upstream *loadbalancer.Upstream,
	x224Request []byte,
) (*rdpHandshakeResult, error) {
	if upstream == nil || upstream.HostPort == "" {
		return nil, errors.Errorf("empty RDP upstream")
	}

	if len(x224Request) == 0 {
		return nil, errors.Errorf("empty X.224 connection request")
	}

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()

	var dialer net.Dialer
	dialer.KeepAlive = 30 * time.Second

	rawConn, err := dialer.DialContext(dialCtx, "tcp", upstream.HostPort)
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
			zap.L().Debug("SetKeepAlive err", zap.Error(err))
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			zap.L().Debug("SetKeepAlivePeriod err", zap.Error(err))
		}
	}

	if err := rawConn.SetDeadline(time.Now().Add(x224HandshakeTimeout)); err != nil {
		return nil, err
	}

	if _, err := rawConn.Write(x224Request); err != nil {
		return nil, err
	}

	x224Response, err := readTPKT(rawConn)
	if err != nil {
		return nil, err
	}

	if isRDPNegotiationFailure(x224Response) {
		return &rdpHandshakeResult{
			X224PDU:     x224Response,
			ServerAddr:  upstream.HostPort,
			Negotiation: false,
		}, nil
	}

	if err := rawConn.SetDeadline(time.Now().Add(tlsHandshakeTimeout)); err != nil {
		return nil, err
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         getTLSServerName(upstream),
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	connClosed = false

	return &rdpHandshakeResult{
		TLSConn:     tlsConn,
		X224PDU:     x224Response,
		CertChain:   getPeerCertChain(tlsConn),
		ServerAddr:  upstream.HostPort,
		Negotiation: true,
	}, nil
}

func readTPKT(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	if header[0] != 0x03 {
		return nil, errors.Errorf("invalid TPKT version: %d", header[0])
	}

	totalLen := int(header[2])<<8 | int(header[3])
	if totalLen < 4 {
		return nil, errors.Errorf("invalid TPKT length: %d", totalLen)
	}

	if totalLen > 64*1024 {
		return nil, errors.Errorf("TPKT length is too large: %d", totalLen)
	}

	body := make([]byte, totalLen-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	ret := make([]byte, 0, totalLen)
	ret = append(ret, header...)
	ret = append(ret, body...)
	return ret, nil
}

func isRDPNegotiationFailure(x224 []byte) bool {
	if len(x224) < 19 {
		return false
	}

	if x224[0] != 0x03 {
		return false
	}

	if x224[5] != 0xd0 {
		return false
	}

	negOffset := 11
	if x224[negOffset] != 0x03 {
		return false
	}

	if x224[negOffset+2] != 0x08 || x224[negOffset+3] != 0x00 {
		return false
	}

	return true
}

func getTLSServerName(upstream *loadbalancer.Upstream) string {
	if upstream == nil {
		return ""
	}

	if upstream.SNIHost != "" {
		return upstream.SNIHost
	}

	if upstream.Host != "" {
		return upstream.Host
	}

	host, _, err := net.SplitHostPort(upstream.HostPort)
	if err != nil {
		return ""
	}

	if ip := net.ParseIP(host); ip != nil {
		return ""
	}

	return host
}

func getPeerCertChain(conn *tls.Conn) [][]byte {
	state := conn.ConnectionState()

	var ret [][]byte
	for _, cert := range state.PeerCertificates {
		ret = append(ret, append([]byte(nil), cert.Raw...))
	}

	return ret
}
