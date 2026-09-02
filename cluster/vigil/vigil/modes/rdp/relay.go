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
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

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

func Relay(ctx context.Context, downstream net.Conn, upstream net.Conn,
	rewriteSelectedProtocol bool) (uint64, uint64) {
	resCh := make(chan copyResult, 2)

	fromDownstream := &countingReader{src: downstream}
	toDownstream := &countingReader{src: upstream}

	var downstreamSrc io.Reader = fromDownstream
	if rewriteSelectedProtocol {
		downstreamSrc = &mcsSelectedProtocolRewriter{
			src:    downstreamSrc,
			target: protocolHybrid,
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
