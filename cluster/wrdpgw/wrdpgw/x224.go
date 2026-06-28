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
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
)

const (
	protocolRDP      uint32 = 0x00000000
	protocolSSL      uint32 = 0x00000001
	protocolHybrid   uint32 = 0x00000002
	protocolHybridEx uint32 = 0x00000008

	negTypeRequest  byte = 0x01
	negTypeResponse byte = 0x02
	negTypeFailure  byte = 0x03

	tpktVersion  byte = 0x03
	x224TypeCR   byte = 0xe0
	x224TypeCC   byte = 0xd0
	negRspOffset      = 11
)

func buildX224ConnectionRequest(requested uint32) []byte {
	neg := make([]byte, 8)
	neg[0] = negTypeRequest
	neg[1] = 0x00
	binary.LittleEndian.PutUint16(neg[2:4], 0x0008)
	binary.LittleEndian.PutUint32(neg[4:8], requested)

	x224 := make([]byte, 0, 7+len(neg))
	x224 = append(x224, byte(6+len(neg)))
	x224 = append(x224, x224TypeCR)
	x224 = append(x224, 0x00, 0x00)
	x224 = append(x224, 0x00, 0x00)
	x224 = append(x224, 0x00)
	x224 = append(x224, neg...)

	total := 4 + len(x224)
	out := make([]byte, 0, total)
	out = append(out, tpktVersion, 0x00, byte(total>>8), byte(total))
	out = append(out, x224...)

	return out
}

func rdpConfirmSelectedProtocol(x224 []byte) (uint32, bool) {
	if len(x224) < 19 {
		return 0, false
	}

	if x224[0] != tpktVersion {
		return 0, false
	}

	if x224[5] != x224TypeCC {
		return 0, false
	}

	if x224[negRspOffset] != negTypeResponse {
		return 0, false
	}

	return binary.LittleEndian.Uint32(x224[15:19]), true
}

func synthesizeSSLConfirm(realConfirm []byte) ([]byte, error) {
	if len(realConfirm) < 19 {
		return nil, errors.Errorf("X.224 confirm too short to synthesize")
	}

	if realConfirm[negRspOffset] != negTypeResponse {
		return nil, errors.Errorf("X.224 confirm has no RDP_NEG_RSP to rewrite")
	}

	out := make([]byte, len(realConfirm))
	copy(out, realConfirm)
	binary.LittleEndian.PutUint32(out[15:19], protocolSSL)

	return out, nil
}

func isRDPNegotiationFailure(x224 []byte) bool {
	if len(x224) < 19 {
		return false
	}

	if x224[0] != tpktVersion {
		return false
	}

	if x224[5] != x224TypeCC {
		return false
	}

	if x224[negRspOffset] != negTypeFailure {
		return false
	}

	if x224[negRspOffset+2] != 0x08 || x224[negRspOffset+3] != 0x00 {
		return false
	}

	return true
}

func readTPKT(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	if header[0] != tpktVersion {
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