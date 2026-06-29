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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"net"

	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/pkg/errors"
)

type tlsTrustPolicy struct {
	pinnedSHA256 [][32]byte
	allowAnyCert bool
}

func (p *tlsTrustPolicy) verifyPeerCertificate(rawCerts [][]byte) error {
	if p == nil {
		return errors.Errorf("missing upstream TLS trust policy")
	}

	if len(rawCerts) == 0 {
		return errors.Errorf("upstream presented no certificate")
	}

	if len(p.pinnedSHA256) > 0 {
		sum := sha256.Sum256(rawCerts[0])
		for i := range p.pinnedSHA256 {
			if subtle.ConstantTimeCompare(sum[:], p.pinnedSHA256[i][:]) == 1 {
				return nil
			}
		}
		return errors.Errorf("upstream certificate does not match any pinned fingerprint")
	}

	if p.allowAnyCert {
		return nil
	}

	return errors.Errorf("no upstream TLS trust configured")
}

func buildUpstreamTLSConfig(upstream *loadbalancer.Upstream, trust *tlsTrustPolicy) *tls.Config {
	return &tls.Config{
		ServerName:         getTLSServerName(upstream),
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       nil,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return trust.verifyPeerCertificate(rawCerts)
		},
	}
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

func getPeerLeafCredSSPPublicKey(conn *tls.Conn) ([]byte, error) {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.Errorf("upstream presented no certificate")
	}

	leaf := state.PeerCertificates[0]
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		return x509.MarshalPKCS1PublicKey(pub), nil
	default:
		return nil, errors.Errorf("unsupported upstream RDP certificate public key type %T", leaf.PublicKey)
	}
}
