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
	"math"

	"github.com/pkg/errors"
)

const (
	rdcleanpathBaseVersion = 3389
	rdcleanpathVersion1    = rdcleanpathBaseVersion + 1

	rdcleanpathGeneralErrorCode     = 1
	rdcleanpathNegotiationErrorCode = 2

	derTagSequence     = 0x30
	derTagInteger      = 0x02
	derTagOctetString  = 0x04
	derTagUTF8String   = 0x0c
	derTagContextBase  = 0xa0
	rdcleanpathMaxSize = 16 * 1024 * 1024
)

type rdcleanpathRequest struct {
	Destination       string
	ProxyAuth         string
	ServerAuth        string
	PreconnectionBlob string
	X224ConnectionPDU []byte
}

type derTLV struct {
	tag         byte
	value       []byte
	totalLength int
}

func decodeRDCleanPathRequest(src []byte) (*rdcleanpathRequest, error) {
	if len(src) == 0 {
		return nil, errors.Errorf("empty RDCleanPath request")
	}

	if len(src) > rdcleanpathMaxSize {
		return nil, errors.Errorf("RDCleanPath request is too large")
	}

	outer, err := derDecodeTLV(src, 0)
	if err != nil {
		return nil, err
	}

	if outer.tag != derTagSequence {
		return nil, errors.Errorf("RDCleanPath request must be a DER SEQUENCE")
	}

	if outer.totalLength != len(src) {
		return nil, errors.Errorf("RDCleanPath request contains trailing bytes")
	}

	children, err := derDecodeChildren(outer.value)
	if err != nil {
		return nil, err
	}

	ret := &rdcleanpathRequest{}
	var version uint64
	var foundVersion bool

	for _, child := range children {
		if child.tag < derTagContextBase || child.tag > derTagContextBase+31 {
			return nil, errors.Errorf("unexpected RDCleanPath DER tag: 0x%x", child.tag)
		}

		tagNum := int(child.tag - derTagContextBase)

		switch tagNum {
		case 0:
			version, err = derDecodeExplicitUint64(child.value)
			if err != nil {
				return nil, errors.Errorf("could not decode RDCleanPath version: %+v", err)
			}
			foundVersion = true

		case 2:
			ret.Destination, err = derDecodeExplicitString(child.value)
			if err != nil {
				return nil, errors.Errorf("could not decode RDCleanPath destination: %+v", err)
			}

		case 3:
			ret.ProxyAuth, err = derDecodeExplicitString(child.value)
			if err != nil {
				return nil, errors.Errorf("could not decode RDCleanPath proxy_auth: %+v", err)
			}

		case 4:
			ret.ServerAuth, err = derDecodeExplicitString(child.value)
			if err != nil {
				return nil, errors.Errorf("could not decode RDCleanPath server_auth: %+v", err)
			}

		case 5:
			ret.PreconnectionBlob, err = derDecodeExplicitString(child.value)
			if err != nil {
				return nil, errors.Errorf("could not decode RDCleanPath preconnection_blob: %+v", err)
			}

		case 6:
			ret.X224ConnectionPDU, err = derDecodeExplicitOctetString(child.value)
			if err != nil {
				return nil, errors.Errorf("could not decode RDCleanPath x224_connection_pdu: %+v", err)
			}
		}
	}

	if !foundVersion {
		return nil, errors.Errorf("missing RDCleanPath version")
	}

	if version != rdcleanpathVersion1 {
		return nil, errors.Errorf("unsupported RDCleanPath version: %d", version)
	}

	if ret.Destination == "" {
		return nil, errors.Errorf("missing RDCleanPath destination")
	}

	if len(ret.X224ConnectionPDU) == 0 {
		return nil, errors.Errorf("missing RDCleanPath x224_connection_pdu")
	}

	return ret, nil
}

func encodeRDCleanPathResponse(serverAddr string, x224PDU []byte, certChain [][]byte) ([]byte, error) {
	if serverAddr == "" {
		return nil, errors.Errorf("empty RDCleanPath server address")
	}

	if len(x224PDU) == 0 {
		return nil, errors.Errorf("empty RDCleanPath x224 response")
	}

	var certItems [][]byte
	for _, cert := range certChain {
		certItems = append(certItems, derWrap(derTagOctetString, cert))
	}

	certSeq := derWrap(derTagSequence, concatDER(certItems...))

	return derWrap(derTagSequence, concatDER(
		derWrapContext(0, derEncodeUint64(rdcleanpathVersion1)),
		derWrapContext(6, derWrap(derTagOctetString, x224PDU)),
		derWrapContext(7, certSeq),
		derWrapContext(9, derWrap(derTagUTF8String, []byte(serverAddr))),
	)), nil
}

func encodeRDCleanPathHTTPError(status uint16) []byte {
	return encodeRDCleanPathError(&rdcleanpathError{
		ErrorCode:      rdcleanpathGeneralErrorCode,
		HTTPStatusCode: status,
	})
}

func encodeRDCleanPathGeneralError() []byte {
	return encodeRDCleanPathError(&rdcleanpathError{
		ErrorCode: rdcleanpathGeneralErrorCode,
	})
}

func encodeRDCleanPathTLSError(alertCode uint8) []byte {
	return encodeRDCleanPathError(&rdcleanpathError{
		ErrorCode:    rdcleanpathGeneralErrorCode,
		TLSAlertCode: alertCode,
	})
}

func encodeRDCleanPathNegotiationError(x224PDU []byte) ([]byte, error) {
	if len(x224PDU) == 0 {
		return nil, errors.Errorf("empty RDCleanPath negotiation error x224 response")
	}

	return derWrap(derTagSequence, concatDER(
		derWrapContext(0, derEncodeUint64(rdcleanpathVersion1)),
		derWrapContext(1, encodeRDCleanPathErrorValue(&rdcleanpathError{
			ErrorCode: rdcleanpathNegotiationErrorCode,
		})),
		derWrapContext(6, derWrap(derTagOctetString, x224PDU)),
	)), nil
}

type rdcleanpathError struct {
	ErrorCode      uint16
	HTTPStatusCode uint16
	WSALastError   uint16
	TLSAlertCode   uint8
}

func encodeRDCleanPathError(e *rdcleanpathError) []byte {
	return derWrap(derTagSequence, concatDER(
		derWrapContext(0, derEncodeUint64(rdcleanpathVersion1)),
		derWrapContext(1, encodeRDCleanPathErrorValue(e)),
	))
}

func encodeRDCleanPathErrorValue(e *rdcleanpathError) []byte {
	var parts [][]byte

	parts = append(parts, derWrapContext(0, derEncodeUint64(uint64(e.ErrorCode))))

	if e.HTTPStatusCode != 0 {
		parts = append(parts, derWrapContext(1, derEncodeUint64(uint64(e.HTTPStatusCode))))
	}

	if e.WSALastError != 0 {
		parts = append(parts, derWrapContext(2, derEncodeUint64(uint64(e.WSALastError))))
	}

	if e.TLSAlertCode != 0 {
		parts = append(parts, derWrapContext(3, derEncodeUint64(uint64(e.TLSAlertCode))))
	}

	return derWrap(derTagSequence, concatDER(parts...))
}

func derDecodeChildren(src []byte) ([]*derTLV, error) {
	var ret []*derTLV

	offset := 0
	for offset < len(src) {
		tlv, err := derDecodeTLV(src, offset)
		if err != nil {
			return nil, err
		}

		ret = append(ret, tlv)
		offset += tlv.totalLength
	}

	if offset != len(src) {
		return nil, errors.Errorf("invalid DER child length")
	}

	return ret, nil
}

func derDecodeTLV(src []byte, offset int) (*derTLV, error) {
	if offset < 0 || offset >= len(src) {
		return nil, errors.Errorf("invalid DER offset")
	}

	tag := src[offset]

	length, lengthBytes, err := derDecodeLength(src, offset+1)
	if err != nil {
		return nil, err
	}

	headerLen := 1 + lengthBytes
	totalLen := headerLen + length

	if totalLen < headerLen {
		return nil, errors.Errorf("DER length overflow")
	}

	if offset+totalLen > len(src) {
		return nil, errors.Errorf("incomplete DER TLV")
	}

	return &derTLV{
		tag:         tag,
		value:       src[offset+headerLen : offset+totalLen],
		totalLength: totalLen,
	}, nil
}

func derDecodeLength(src []byte, offset int) (int, int, error) {
	if offset >= len(src) {
		return 0, 0, errors.Errorf("missing DER length")
	}

	first := src[offset]
	if first < 0x80 {
		return int(first), 1, nil
	}

	numBytes := int(first & 0x7f)
	if numBytes == 0 {
		return 0, 0, errors.Errorf("indefinite DER length is not allowed")
	}

	if numBytes > 4 {
		return 0, 0, errors.Errorf("DER length is too large")
	}

	if offset+1+numBytes > len(src) {
		return 0, 0, errors.Errorf("incomplete DER long length")
	}

	if src[offset+1] == 0 {
		return 0, 0, errors.Errorf("non-minimal DER length")
	}

	var length int
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(src[offset+1+i])
	}

	if length < 128 {
		return 0, 0, errors.Errorf("non-minimal DER long length")
	}

	return length, 1 + numBytes, nil
}

func derDecodeExplicitUint64(src []byte) (uint64, error) {
	tlv, err := derDecodeSingleInner(src)
	if err != nil {
		return 0, err
	}

	if tlv.tag != derTagInteger {
		return 0, errors.Errorf("expected DER INTEGER")
	}

	if len(tlv.value) == 0 {
		return 0, errors.Errorf("empty DER INTEGER")
	}

	if len(tlv.value) > 9 {
		return 0, errors.Errorf("DER INTEGER is too large")
	}

	if len(tlv.value) > 1 && tlv.value[0] == 0 && tlv.value[1]&0x80 == 0 {
		return 0, errors.Errorf("non-minimal DER INTEGER")
	}

	if tlv.value[0]&0x80 != 0 {
		return 0, errors.Errorf("negative DER INTEGER is unsupported")
	}

	var ret uint64
	for _, b := range tlv.value {
		ret = (ret << 8) | uint64(b)
	}

	return ret, nil
}

func derDecodeExplicitString(src []byte) (string, error) {
	tlv, err := derDecodeSingleInner(src)
	if err != nil {
		return "", err
	}

	if tlv.tag != derTagUTF8String {
		return "", errors.Errorf("expected DER UTF8String")
	}

	return string(tlv.value), nil
}

func derDecodeExplicitOctetString(src []byte) ([]byte, error) {
	tlv, err := derDecodeSingleInner(src)
	if err != nil {
		return nil, err
	}

	if tlv.tag != derTagOctetString {
		return nil, errors.Errorf("expected DER OCTET STRING")
	}

	return append([]byte(nil), tlv.value...), nil
}

func derDecodeSingleInner(src []byte) (*derTLV, error) {
	tlv, err := derDecodeTLV(src, 0)
	if err != nil {
		return nil, err
	}

	if tlv.totalLength != len(src) {
		return nil, errors.Errorf("explicit DER value contains trailing bytes")
	}

	return tlv, nil
}

func derWrapContext(tagNum int, content []byte) []byte {
	if tagNum < 0 || tagNum > 30 {
		panic("invalid DER context tag")
	}

	return derWrap(byte(derTagContextBase+tagNum), content)
}

func derWrap(tag byte, content []byte) []byte {
	return concatDER([]byte{tag}, derEncodeLength(len(content)), content)
}

func derEncodeLength(length int) []byte {
	if length < 0 {
		panic("invalid negative DER length")
	}

	if length < 0x80 {
		return []byte{byte(length)}
	}

	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(length))

	i := 0
	for i < len(tmp) && tmp[i] == 0 {
		i++
	}

	out := tmp[i:]
	if len(out) > math.MaxUint8 {
		panic("invalid DER length")
	}

	return append([]byte{0x80 | byte(len(out))}, out...)
}

func derEncodeUint64(v uint64) []byte {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], v)

	i := 0
	for i < len(tmp)-1 && tmp[i] == 0 {
		i++
	}

	content := tmp[i:]
	if content[0]&0x80 != 0 {
		content = append([]byte{0}, content...)
	}

	return derWrap(derTagInteger, content)
}

func concatDER(parts ...[]byte) []byte {
	var total int
	for _, p := range parts {
		total += len(p)
	}

	ret := make([]byte, 0, total)
	for _, p := range parts {
		ret = append(ret, p...)
	}

	return ret
}
