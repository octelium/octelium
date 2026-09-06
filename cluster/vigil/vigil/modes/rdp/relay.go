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
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/coder/websocket"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

type copyResult struct {
	direction string
	err       error
}

type countingReader struct {
	src io.Reader
	n   atomic.Int64
}

type RelayOptions struct {
	rewriteSelectedProtocol bool
	credential              *Credential
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		r.n.Add(int64(n))
	}
	return n, err
}

type mcsSelectedProtocolRewriter struct {
	src       io.Reader
	target    uint32
	rewritten bool
}

func (r *mcsSelectedProtocolRewriter) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 && !r.rewritten {
		r.rewritten = true
		rewriteMCSSelectedProtocol(p[:n], r.target)
	}
	return n, err
}

func rewriteMCSSelectedProtocol(buf []byte, target uint32) {
	const (
		coreHeaderLen       = 4
		selectedProtoInCore = 208
		selectedProtoLen    = 4
	)

	for i := 0; i+coreHeaderLen < len(buf)-1; i++ {
		if buf[i] != 0x01 || buf[i+1] != 0xc0 {
			continue
		}

		coreLen := int(buf[i+2]) | int(buf[i+3])<<8
		if coreLen < coreHeaderLen+selectedProtoInCore+selectedProtoLen || coreLen > 1024 {
			continue
		}

		fieldAt := i + coreHeaderLen + selectedProtoInCore
		if fieldAt+selectedProtoLen > len(buf) {
			continue
		}

		current := uint32(buf[fieldAt]) |
			uint32(buf[fieldAt+1])<<8 |
			uint32(buf[fieldAt+2])<<16 |
			uint32(buf[fieldAt+3])<<24

		if current == target {
			return
		}

		buf[fieldAt] = byte(target)
		buf[fieldAt+1] = byte(target >> 8)
		buf[fieldAt+2] = byte(target >> 16)
		buf[fieldAt+3] = byte(target >> 24)

		zap.L().Debug("RDP rewrote MCS serverSelectedProtocol",
			zap.Int("offset", fieldAt),
			zap.Uint32("from", current),
			zap.Uint32("to", target))
		return
	}

	zap.L().Debug("RDP did not find MCS CS_CORE to rewrite serverSelectedProtocol")
}

type clientInfoCredentialInjector struct {
	src         io.Reader
	credential  *Credential
	pending     []byte
	pendingAt   int
	injected    bool
	injectAfter bool
}

func (r *clientInfoCredentialInjector) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if r.injected {
		return r.src.Read(p)
	}

	if len(r.pending) == 0 {
		packet, err := ReadTPKT(r.src)
		if err != nil {
			return 0, err
		}

		r.pending, r.injectAfter, err = rewriteClientInfoCredential(packet, r.credential)
		if err != nil {
			return 0, err
		}
	}

	n := copy(p, r.pending[r.pendingAt:])
	r.pendingAt += n
	if r.pendingAt == len(r.pending) {
		for i := range r.pending {
			r.pending[i] = 0
		}
		r.pending = nil
		r.pendingAt = 0
		if r.injectAfter {
			r.credential = nil
			r.injected = true
			r.injectAfter = false
		}
	}

	return n, nil
}

func rewriteClientInfoCredential(packet []byte, credential *Credential) ([]byte, bool, error) {
	const (
		x224DataLen          = 3
		mcsHeaderLen         = 6
		clientInfoHeaderLen  = 18
		securityHeaderLen    = 4
		mcsSendDataRequest   = 0x64
		securityInfoPacket   = 0x0040
		securityEncrypt      = 0x0008
		infoAutoLogon        = 0x00000008
		infoUnicode          = 0x00000010
		infoPasswordIsSCPIN  = 0x00040000
		maxClientInfoTextLen = 512
	)

	if credential == nil {
		return nil, false, errors.Errorf("missing RDP credential")
	}

	if len(packet) < 4+x224DataLen+mcsHeaderLen+1 {
		return packet, false, nil
	}

	if packet[4] != 0x02 || packet[5] != 0xf0 || packet[6] != 0x80 || packet[7] != mcsSendDataRequest {
		return packet, false, nil
	}

	userDataLen, lengthLen, err := readPERLength(packet[13:])
	if err != nil {
		return nil, false, err
	}

	userDataAt := 13 + lengthLen
	if userDataAt+userDataLen != len(packet) {
		return nil, false, errors.Errorf("invalid MCS SendDataRequest user data length")
	}

	userData := packet[userDataAt:]
	if len(userData) < securityHeaderLen {
		return packet, false, nil
	}

	securityFlags := binary.LittleEndian.Uint16(userData[:2])
	if securityFlags&securityInfoPacket == 0 {
		return packet, false, nil
	}

	if securityFlags&securityEncrypt != 0 {
		return nil, false, errors.Errorf("encrypted RDP Client Info is unsupported for credential injection")
	}

	clientInfo := userData[securityHeaderLen:]
	if len(clientInfo) < clientInfoHeaderLen {
		return nil, false, errors.Errorf("RDP Client Info is too short")
	}

	flags := binary.LittleEndian.Uint32(clientInfo[4:8])
	if flags&infoUnicode == 0 {
		return nil, false, errors.Errorf("non-Unicode RDP Client Info is unsupported for credential injection")
	}

	lengths := make([]uint16, 5)
	for i := range lengths {
		lengths[i] = binary.LittleEndian.Uint16(clientInfo[8+i*2 : 10+i*2])
	}

	preservedAt := 0
	fieldAt := clientInfoHeaderLen
	for i, fieldLen := range lengths {
		if fieldLen%2 != 0 {
			return nil, false, errors.Errorf("invalid Unicode RDP Client Info field length")
		}

		fieldEnd := fieldAt + int(fieldLen)
		if fieldEnd+2 > len(clientInfo) {
			return nil, false, errors.Errorf("RDP Client Info field exceeds packet length")
		}
		if clientInfo[fieldEnd] != 0 || clientInfo[fieldEnd+1] != 0 {
			return nil, false, errors.Errorf("RDP Client Info field has no null terminator")
		}

		fieldAt = fieldEnd + 2
		if i == 2 {
			preservedAt = fieldAt
		}
	}

	domain, err := encodeClientInfoText(credential.Domain, maxClientInfoTextLen)
	if err != nil {
		return nil, false, errors.Wrap(err, "could not encode RDP credential domain")
	}
	username, err := encodeClientInfoText(credential.Username, maxClientInfoTextLen)
	if err != nil {
		return nil, false, errors.Wrap(err, "could not encode RDP credential username")
	}
	password, err := encodeClientInfoText(credential.Password, maxClientInfoTextLen)
	if err != nil {
		return nil, false, errors.Wrap(err, "could not encode RDP credential password")
	}

	newClientInfo := make([]byte, 0, len(clientInfo)+len(domain)+len(username)+len(password))
	newClientInfo = append(newClientInfo, clientInfo[:4]...)
	flags = flags | infoAutoLogon
	flags = flags &^ infoPasswordIsSCPIN
	newClientInfo = binary.LittleEndian.AppendUint32(newClientInfo, flags)
	newClientInfo = binary.LittleEndian.AppendUint16(newClientInfo, uint16(len(domain)-2))
	newClientInfo = binary.LittleEndian.AppendUint16(newClientInfo, uint16(len(username)-2))
	newClientInfo = binary.LittleEndian.AppendUint16(newClientInfo, uint16(len(password)-2))
	newClientInfo = binary.LittleEndian.AppendUint16(newClientInfo, lengths[3])
	newClientInfo = binary.LittleEndian.AppendUint16(newClientInfo, lengths[4])
	newClientInfo = append(newClientInfo, domain...)
	newClientInfo = append(newClientInfo, username...)
	newClientInfo = append(newClientInfo, password...)
	newClientInfo = append(newClientInfo, clientInfo[preservedAt:]...)

	newUserDataLen := securityHeaderLen + len(newClientInfo)
	if newUserDataLen > 0x7fff {
		return nil, false, errors.Errorf("RDP Client Info exceeds MCS user data length limit")
	}

	newPacket := make([]byte, 0, userDataAt+newUserDataLen)
	newPacket = append(newPacket, packet[:13]...)
	newPacket = appendPERLength(newPacket, newUserDataLen)
	newPacket = append(newPacket, userData[:securityHeaderLen]...)
	newPacket = append(newPacket, newClientInfo...)
	if len(newPacket) > 0xffff {
		return nil, false, errors.Errorf("RDP Client Info exceeds TPKT length limit")
	}
	binary.BigEndian.PutUint16(newPacket[2:4], uint16(len(newPacket)))

	return newPacket, true, nil
}

func readPERLength(buf []byte) (int, int, error) {
	if len(buf) == 0 {
		return 0, 0, errors.Errorf("missing MCS user data length")
	}

	if buf[0]&0x80 == 0 {
		return int(buf[0]), 1, nil
	}

	if len(buf) < 2 {
		return 0, 0, errors.Errorf("incomplete MCS user data length")
	}

	return int(buf[0]&0x7f)<<8 | int(buf[1]), 2, nil
}

func appendPERLength(buf []byte, length int) []byte {
	if length < 0x80 {
		return append(buf, byte(length))
	}

	return append(buf, byte(length>>8)|0x80, byte(length))
}

func encodeClientInfoText(val string, maxLen int) ([]byte, error) {
	for _, r := range val {
		if r == 0 {
			return nil, errors.Errorf("RDP Client Info text contains a null character")
		}
	}

	units := utf16.Encode([]rune(val))
	if len(units)*2+2 > maxLen {
		return nil, errors.Errorf("RDP Client Info text exceeds %d bytes", maxLen)
	}

	ret := make([]byte, (len(units)+1)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(ret[i*2:i*2+2], unit)
	}

	return ret, nil
}

func Relay(ctx context.Context, downstream net.Conn, upstream net.Conn,
	options *RelayOptions) (uint64, uint64) {
	resCh := make(chan copyResult, 2)

	fromDownstream := &countingReader{src: downstream}
	toDownstream := &countingReader{src: upstream}

	var downstreamSrc io.Reader = fromDownstream
	if options != nil && options.rewriteSelectedProtocol {
		downstreamSrc = &mcsSelectedProtocolRewriter{
			src:    downstreamSrc,
			target: protocolHybrid,
		}
	}
	if options != nil && options.credential != nil {
		downstreamSrc = &clientInfoCredentialInjector{
			src:        downstreamSrc,
			credential: options.credential,
		}
	}

	go copyConn(resCh, "downstream_to_upstream", upstream, downstreamSrc)
	go copyConn(resCh, "upstream_to_downstream", downstream, toDownstream)

	first := <-resCh

	if !isExpectedNetErr(first.err) {
		zap.L().Debug("RDP relay copy ended with error",
			zap.String("direction", first.direction),
			zap.Error(first.err))
	}

	downstream.Close()
	upstream.Close()

	var second copyResult
	select {
	case second = <-resCh:
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		zap.L().Debug("Timed out waiting for RDP relay copy shutdown")
	}

	if !isExpectedNetErr(second.err) {
		zap.L().Debug("RDP relay copy ended with error",
			zap.String("direction", second.direction),
			zap.Error(second.err))
	}

	return safeUint64(fromDownstream.n.Load()), safeUint64(toDownstream.n.Load())
}

func copyConn(resCh chan<- copyResult, direction string, dst io.Writer, src io.Reader) {
	_, err := io.Copy(dst, src)

	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		if closeErr := cw.CloseWrite(); closeErr != nil && !isExpectedNetErr(closeErr) {
			zap.L().Debug("Could not CloseWrite in RDP relay",
				zap.String("direction", direction),
				zap.Error(closeErr))
		}
	}

	resCh <- copyResult{
		direction: direction,
		err:       err,
	}
}

func safeUint64(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

func isExpectedNetErr(err error) bool {
	if err == nil {
		return true
	}

	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}

	if websocket.CloseStatus(err) != -1 {
		return true
	}

	msg := strings.ToLower(err.Error())

	return strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "connection reset by peer") ||
		strings.Contains(msg, "broken pipe")
}
