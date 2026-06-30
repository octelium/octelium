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
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

type echoSrv struct {
	lis net.Listener
}

func newEchoSrv(t *testing.T, port int) *echoSrv {
	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	assert.Nil(t, err)

	s := &echoSrv{lis: lis}

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return s
}

func (s *echoSrv) close() {
	if s.lis != nil {
		s.lis.Close()
	}
}

func TestRenderIndex(t *testing.T) {
	srv := &server{}

	req := httptest.NewRequest("GET", "http://localhost/", nil)
	w := httptest.NewRecorder()
	srv.handleIndex(w, req)

	resp := w.Result()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	assert.Nil(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	csp := resp.Header.Get("Content-Security-Policy")
	assert.True(t, strings.Contains(csp, "frame-ancestors 'none'"))
	assert.True(t, strings.Contains(csp, "default-src 'none'"))
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.True(t, len(body) > 0)
}

func TestSecurityHeaders(t *testing.T) {
	srv := &server{}

	w := httptest.NewRecorder()
	srv.setIndexSecurityHeaders(w, "testnonce")

	csp := w.Header().Get("Content-Security-Policy")
	assert.True(t, strings.Contains(csp, "default-src 'none'"))
	assert.True(t, strings.Contains(csp, "script-src 'self' 'nonce-testnonce' 'wasm-unsafe-eval'"))
	assert.True(t, strings.Contains(csp, "frame-ancestors 'none'"))
	assert.True(t, strings.Contains(csp, "object-src 'none'"))
	assert.True(t, strings.Contains(csp, "base-uri 'none'"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
}

func TestStaticHeaders(t *testing.T) {
	srv := &server{}

	w := httptest.NewRecorder()
	srv.setStaticHeaders(w)

	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "public, max-age=31536000, immutable", w.Header().Get("Cache-Control"))
}

func TestRelay(t *testing.T) {
	ctx := context.Background()

	upstreamPort := tests.GetPort()
	echo := newEchoSrv(t, upstreamPort)
	defer echo.close()

	upstreamConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", upstreamPort))
	assert.Nil(t, err)

	clientEnd, downstream := net.Pipe()

	resCh := make(chan [2]uint64, 1)
	go func() {
		recv, sent := relay(ctx, downstream, upstreamConn, 0)
		resCh <- [2]uint64{recv, sent}
	}()

	msg := []byte("rdp relay payload")

	_, err = clientEnd.Write(msg)
	assert.Nil(t, err)

	buf := make([]byte, 4096)
	n, err := clientEnd.Read(buf)
	assert.Nil(t, err)
	assert.Equal(t, msg, buf[:n])

	clientEnd.Close()

	res := <-resCh
	assert.Equal(t, uint64(len(msg)), res[0])
	assert.Equal(t, uint64(len(msg)), res[1])
}

func TestWebSocketRejectsInvalidRDCleanPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})

	upstreamPort := tests.GetPort()
	echo := newEchoSrv(t, upstreamPort)
	defer echo.close()

	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(6),
		},
		Spec: &corev1.Service_Spec{
			Port: uint32(tests.GetPort()),
			Mode: corev1.Service_Spec_TCP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: fmt.Sprintf("tcp://localhost:%d", upstreamPort),
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	svcV, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
	assert.Nil(t, err)

	srv, err := newServer(ctx, fakeC.OcteliumC, svcV)
	assert.Nil(t, err)

	err = srv.lbManager.Run(ctx)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	ts := httptest.NewServer(srv.getMux())
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + webSocketPath

	ws, _, err := websocket.Dial(ctx, wsURL, nil)
	assert.Nil(t, err, "%+v", err)
	defer ws.CloseNow()

	ws.SetReadLimit(maxMessageSize)

	err = ws.Write(ctx, websocket.MessageBinary, []byte("this is not a valid RDCleanPath request"))
	assert.Nil(t, err)

	var closeErr error
	for {
		_, _, readErr := ws.Read(ctx)
		if readErr != nil {
			closeErr = readErr
			break
		}
	}

	assert.Equal(t, websocket.StatusUnsupportedData, websocket.CloseStatus(closeErr))
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
