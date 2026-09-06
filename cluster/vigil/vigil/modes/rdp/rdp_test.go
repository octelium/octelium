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
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"testing/iotest"
	"unicode/utf16"

	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/stretchr/testify/assert"
)

func TestDialPassthrough(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer lis.Close()

	clientX224 := buildX224ConnectionRequest(protocolSSL | protocolHybrid)
	serverX224 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02,
		0x00, 0x00, 0x00,
	}

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		conn, err := lis.Accept()
		assert.Nil(t, err)
		defer conn.Close()

		req, err := ReadTPKT(conn)
		assert.Nil(t, err)
		assert.Equal(t, clientX224, req)

		_, err = conn.Write(serverX224)
		assert.Nil(t, err)

		_, err = io.Copy(conn, conn)
		assert.Nil(t, err)
	}()

	conn, resp, err := DialPassthrough(context.Background(), &loadbalancer.Upstream{
		HostPort: lis.Addr().String(),
	}, clientX224)
	assert.Nil(t, err)
	assert.Equal(t, serverX224, resp)

	msg := []byte("native RDP payload")
	_, err = conn.Write(msg)
	assert.Nil(t, err)

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(conn, buf)
	assert.Nil(t, err)
	assert.Equal(t, msg, buf)

	conn.Close()
	<-doneCh
}

func TestX224ConnectionRequest(t *testing.T) {
	req := buildX224ConnectionRequest(protocolSSL | protocolHybrid)

	assert.Nil(t, ValidateConnectionRequest(req))
	assert.True(t, SupportsSSL(req))
	assert.False(t, SupportsSSL(buildX224ConnectionRequest(protocolHybrid)))

	invalid := append([]byte(nil), req...)
	invalid[5] = x224TypeCC
	assert.NotNil(t, ValidateConnectionRequest(invalid))

	read, err := ReadTPKT(bytes.NewReader(req))
	assert.Nil(t, err)
	assert.Equal(t, req, read)
}

func TestRewriteMCSSelectedProtocol(t *testing.T) {
	const mcsConnectInitialHex = "0300019f02f0807f658201930401010401010101ff301a020122020102020100020101020100020101020300ffff0201023019020101020101020101020101020100020101020204200201023020020300ffff020300fc17020300ffff020101020100020101020300ffff0201020482012d000500147c00018122000800100001c00044756361811601c0ea000400080040061a0301ca03aa0000000000000000690072006f006e007200640070002d007700650062000000000000000000000004000000000000000c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ca01000000000010000f0029080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000100000000000000000000000000000000000000000002c00c00000000000000000003c0200002000000636c69707264720000008000647264796e76630000008000"

	const fieldOffset = 349

	buf, err := hex.DecodeString(mcsConnectInitialHex)
	assert.Nil(t, err)

	before := binary.LittleEndian.Uint32(buf[fieldOffset : fieldOffset+4])
	assert.Equal(t, protocolSSL, before)

	rewriteMCSSelectedProtocol(buf, protocolHybrid)

	after := binary.LittleEndian.Uint32(buf[fieldOffset : fieldOffset+4])
	assert.Equal(t, protocolHybrid, after)
}

func TestRewriteMCSSelectedProtocolNoCoreData(t *testing.T) {
	buf := []byte("not an MCS connect initial and has no CS_CORE block")
	original := append([]byte(nil), buf...)

	rewriteMCSSelectedProtocol(buf, protocolHybrid)

	assert.Equal(t, original, buf)
}

func TestSecretlessRelayOptions(t *testing.T) {
	credential := &Credential{
		Domain:   "domain",
		Username: "user",
		Password: "password",
	}

	hybrid, err := newSecretlessRelayOptions(protocolHybrid, credential)
	assert.Nil(t, err)
	assert.True(t, hybrid.rewriteSelectedProtocol)
	assert.Nil(t, hybrid.credential)

	ssl, err := newSecretlessRelayOptions(protocolSSL, credential)
	assert.Nil(t, err)
	assert.False(t, ssl.rewriteSelectedProtocol)
	assert.Same(t, credential, ssl.credential)

	unsupported, err := newSecretlessRelayOptions(protocolRDP, credential)
	assert.NotNil(t, err)
	assert.Nil(t, unsupported)
}

func TestRewriteClientInfoCredential(t *testing.T) {
	extraInfo := bytes.Repeat([]byte{0x5a}, 160)
	packet := buildClientInfoPacket(t, []string{
		"browser-domain",
		"browser-user",
		"browser-password",
		"shell",
		"working-dir",
	}, 0x00040010, extraInfo)
	original := append([]byte(nil), packet...)

	rewritten, matched, err := rewriteClientInfoCredential(packet, &Credential{
		Domain:   "",
		Username: "root",
		Password: "päss",
	})
	assert.Nil(t, err)
	assert.True(t, matched)
	assert.Equal(t, original, packet)
	assert.Equal(t, len(rewritten), int(binary.BigEndian.Uint16(rewritten[2:4])))

	userDataLen, lengthLen, err := readPERLength(rewritten[13:])
	assert.Nil(t, err)
	assert.Equal(t, 2, lengthLen)
	assert.Equal(t, len(rewritten)-(13+lengthLen), userDataLen)

	userData := rewritten[13+lengthLen:]
	assert.Equal(t, []byte{0x40, 0x00, 0x00, 0x00}, userData[:4])
	clientInfo := userData[4:]
	assert.Equal(t, uint32(0x00000018), binary.LittleEndian.Uint32(clientInfo[4:8]))

	fields, tail := decodeClientInfoFields(t, clientInfo)
	assert.Equal(t, []string{"", "root", "päss", "shell", "working-dir"}, fields)
	assert.Equal(t, extraInfo, tail)
}

func TestClientInfoCredentialInjector(t *testing.T) {
	first := []byte{0x03, 0x00, 0x00, 0x07, 0x02, 0xf0, 0x80}
	packet := buildClientInfoPacket(t, []string{"", "", "", "", ""}, 0x00000010, nil)
	trailing := []byte{0x00, 0x06, 0x03, 0xeb, 0x70, 0x01}
	credential := &Credential{Username: "root", Password: "password"}

	expected, matched, err := rewriteClientInfoCredential(packet, credential)
	assert.Nil(t, err)
	assert.True(t, matched)

	stream := append(append(append([]byte(nil), first...), packet...), trailing...)
	injector := &clientInfoCredentialInjector{
		src:        iotest.OneByteReader(bytes.NewReader(stream)),
		credential: credential,
	}

	got, err := io.ReadAll(injector)
	assert.Nil(t, err)
	assert.Equal(t, append(append(append([]byte(nil), first...), expected...), trailing...), got)
	assert.True(t, injector.injected)
	assert.Nil(t, injector.credential)
}

func TestRewriteClientInfoCredentialIgnoresOtherPacket(t *testing.T) {
	packet := []byte{0x03, 0x00, 0x00, 0x07, 0x02, 0xf0, 0x80}

	got, matched, err := rewriteClientInfoCredential(packet, &Credential{Username: "root"})
	assert.Nil(t, err)
	assert.False(t, matched)
	assert.Equal(t, packet, got)
}

func buildClientInfoPacket(t *testing.T, values []string, flags uint32, tail []byte) []byte {
	assert.Len(t, values, 5)

	fields := make([][]byte, len(values))
	clientInfo := binary.LittleEndian.AppendUint32(nil, 0x00000409)
	clientInfo = binary.LittleEndian.AppendUint32(clientInfo, flags)
	for i, val := range values {
		field, err := encodeClientInfoText(val, 512)
		assert.Nil(t, err)
		fields[i] = field
		clientInfo = binary.LittleEndian.AppendUint16(clientInfo, uint16(len(field)-2))
	}
	for _, field := range fields {
		clientInfo = append(clientInfo, field...)
	}
	clientInfo = append(clientInfo, tail...)

	userData := append([]byte{0x40, 0x00, 0x00, 0x00}, clientInfo...)
	packet := []byte{
		0x03, 0x00, 0x00, 0x00,
		0x02, 0xf0, 0x80,
		0x64, 0x00, 0x01, 0x03, 0xeb, 0x70,
	}
	packet = appendPERLength(packet, len(userData))
	packet = append(packet, userData...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))

	return packet
}

func decodeClientInfoFields(t *testing.T, clientInfo []byte) ([]string, []byte) {
	assert.GreaterOrEqual(t, len(clientInfo), 18)

	lengths := make([]uint16, 5)
	for i := range lengths {
		lengths[i] = binary.LittleEndian.Uint16(clientInfo[8+i*2 : 10+i*2])
	}

	fields := make([]string, len(lengths))
	at := 18
	for i, length := range lengths {
		assert.Equal(t, uint16(0), length%2)
		assert.LessOrEqual(t, at+int(length)+2, len(clientInfo))

		units := make([]uint16, int(length)/2)
		for j := range units {
			units[j] = binary.LittleEndian.Uint16(clientInfo[at+j*2 : at+j*2+2])
		}
		fields[i] = string(utf16.Decode(units))
		at += int(length) + 2
	}

	return fields, clientInfo[at:]
}

func TestSafeUint64(t *testing.T) {
	assert.Equal(t, uint64(0), safeUint64(-1))
	assert.Equal(t, uint64(0), safeUint64(-9999))
	assert.Equal(t, uint64(0), safeUint64(0))
	assert.Equal(t, uint64(123), safeUint64(123))
}

func TestIsExpectedNetErr(t *testing.T) {
	assert.True(t, isExpectedNetErr(nil))
	assert.True(t, isExpectedNetErr(io.EOF))
	assert.True(t, isExpectedNetErr(net.ErrClosed))
	assert.True(t, isExpectedNetErr(errors.New("use of closed network connection")))
	assert.True(t, isExpectedNetErr(errors.New("connection reset by peer")))
	assert.True(t, isExpectedNetErr(errors.New("write: broken pipe")))
	assert.False(t, isExpectedNetErr(errors.New("some unexpected failure")))
}
