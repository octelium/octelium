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
	"crypto/tls"
	"io"
	"time"

	"github.com/pkg/errors"
)

const (
	credsspStepTimeout   = 15 * time.Second
	credsspMaxTSRequest  = 16 * 1024 * 1024
	credsspMaxRoundTrips = 8
)

func driveCredSSP(tlsConn *tls.Conn, cred *injectedCredential, serverPubkey []byte, target string) error {
	if cred == nil {
		return errors.Errorf("missing injected credential")
	}

	if len(serverPubkey) == 0 {
		return errors.Errorf("missing upstream public key")
	}

	client, err := ffiCredsspNew(serverPubkey, cred.Domain, cred.Username, cred.Password, target)
	if err != nil {
		return err
	}
	defer client.free()

	var incoming []byte

	for i := 0; i < credsspMaxRoundTrips; i++ {
		outgoing, state, err := client.step(incoming)
		if err != nil {
			return err
		}

		if len(outgoing) > 0 {
			if err := tlsConn.SetWriteDeadline(time.Now().Add(credsspStepTimeout)); err != nil {
				return err
			}
			if _, err := tlsConn.Write(outgoing); err != nil {
				return err
			}
		}

		if state == credsspStateFinal {
			return nil
		}

		if err := tlsConn.SetReadDeadline(time.Now().Add(credsspStepTimeout)); err != nil {
			return err
		}

		incoming, err = readTSRequest(tlsConn)
		if err != nil {
			return err
		}
	}

	return errors.Errorf("CredSSP did not complete within %d round trips", credsspMaxRoundTrips)
}

func readTSRequest(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	if header[0] != derTagSequence {
		return nil, errors.Errorf("TSRequest is not a DER SEQUENCE: 0x%x", header[0])
	}

	var bodyLen int
	var lengthBytes []byte

	if header[1] < 0x80 {
		bodyLen = int(header[1])
	} else {
		numBytes := int(header[1] & 0x7f)
		if numBytes == 0 || numBytes > 4 {
			return nil, errors.Errorf("invalid TSRequest DER length")
		}

		lengthBytes = make([]byte, numBytes)
		if _, err := io.ReadFull(r, lengthBytes); err != nil {
			return nil, err
		}

		for _, b := range lengthBytes {
			bodyLen = (bodyLen << 8) | int(b)
		}
	}

	if bodyLen < 0 || bodyLen > credsspMaxTSRequest {
		return nil, errors.Errorf("TSRequest is too large: %d", bodyLen)
	}

	total := 2 + len(lengthBytes) + bodyLen
	out := make([]byte, 0, total)
	out = append(out, header...)
	out = append(out, lengthBytes...)

	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	out = append(out, body...)

	return out, nil
}