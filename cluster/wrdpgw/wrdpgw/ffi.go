//go:build cgo && wrdpgw_credssp

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

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo LDFLAGS: -L${SRCDIR}/.libs -lwrdpgw_credssp -ldl -lm -lpthread
#include <stdlib.h>
#include "wrdpgw_credssp.h"
*/
import "C"

import (
	"unsafe"

	"github.com/pkg/errors"
)

const (
	credsspStateReplyNeeded = int(C.WRDPGW_CREDSSP_STATE_REPLY_NEEDED)
	credsspStateFinal       = int(C.WRDPGW_CREDSSP_STATE_FINAL)

	maxCGoBytesLen = int(^uint32(0) >> 1)
)

type ffiCredssp struct {
	ptr *C.WrdpgwCredssp
}

func ffiCredsspNew(serverPubkey []byte, domain, username, password, target string) (*ffiCredssp, error) {
	domainBytes := []byte(domain)
	userBytes := []byte(username)
	passBytes := []byte(password)
	targetBytes := []byte(target)
	defer zeroBytes(passBytes)

	var out *C.WrdpgwCredssp
	var cErr *C.char

	kind := C.wrdpgw_credssp_new(
		bytesPtr(serverPubkey), C.size_t(len(serverPubkey)),
		bytesPtr(domainBytes), C.size_t(len(domainBytes)),
		bytesPtr(userBytes), C.size_t(len(userBytes)),
		bytesPtr(passBytes), C.size_t(len(passBytes)),
		bytesPtr(targetBytes), C.size_t(len(targetBytes)),
		&out, &cErr,
	)

	if int(kind) != int(C.WRDPGW_OK) {
		return nil, ffiError(int(kind), cErr)
	}

	if out == nil {
		return nil, errors.Errorf("wrdpgw_credssp_new returned no client")
	}

	return &ffiCredssp{ptr: out}, nil
}

func (c *ffiCredssp) step(incoming []byte) ([]byte, int, error) {
	if c == nil || c.ptr == nil {
		return nil, 0, errors.Errorf("CredSSP client is closed")
	}

	var outPtr *C.uint8_t
	var outLen C.size_t
	var state C.int32_t
	var cErr *C.char

	kind := C.wrdpgw_credssp_step(
		c.ptr,
		bytesPtr(incoming), C.size_t(len(incoming)),
		&outPtr, &outLen, &state, &cErr,
	)

	if int(kind) != int(C.WRDPGW_OK) {
		return nil, 0, ffiError(int(kind), cErr)
	}

	if outPtr != nil {
		defer C.wrdpgw_free_bytes(outPtr, outLen)
	}

	st := int(state)
	switch st {
	case credsspStateReplyNeeded, credsspStateFinal:
	default:
		return nil, 0, errors.Errorf("CredSSP returned invalid state: %d", st)
	}

	if outPtr == nil || outLen == 0 {
		return nil, st, nil
	}

	if outLen > C.size_t(maxCGoBytesLen) {
		return nil, 0, errors.Errorf("CredSSP output is too large: %d", uint64(outLen))
	}

	outgoing := C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen))

	return outgoing, st, nil
}

func (c *ffiCredssp) free() {
	if c == nil || c.ptr == nil {
		return
	}

	C.wrdpgw_credssp_free(c.ptr)
	c.ptr = nil
}

func bytesPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}

	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func ffiError(kind int, cErr *C.char) error {
	msg := "unknown CredSSP error"
	if cErr != nil {
		msg = C.GoString(cErr)
		C.wrdpgw_free_string(cErr)
	}

	switch kind {
	case int(C.WRDPGW_ERR_INVALID_ARGUMENT):
		return errors.Errorf("CredSSP invalid argument: %s", msg)
	case int(C.WRDPGW_ERR_KERBEROS_KDC_REQUIRED):
		return errors.Wrapf(errCredsspKDCRequired, "%s", msg)
	case int(C.WRDPGW_ERR_AUTH_FAILED):
		return errors.Wrapf(errCredsspAuthFailed, "%s", msg)
	case int(C.WRDPGW_ERR_CREDSSP):
		return errors.Errorf("CredSSP error: %s", msg)
	case int(C.WRDPGW_ERR_INTERNAL):
		return errors.Errorf("CredSSP internal error: %s", msg)
	default:
		return errors.Errorf("CredSSP error (kind=%d): %s", kind, msg)
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
