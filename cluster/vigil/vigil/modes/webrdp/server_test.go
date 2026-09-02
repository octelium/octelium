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

package webrdp

import (
	"context"
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
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/rdp"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
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

func newServer(ctx context.Context, octeliumC octeliumc.ClientInterface, svc *corev1.Service) (*Server, error) {
	vCache, err := vcache.NewCache(ctx)
	if err != nil {
		return nil, err
	}
	vCache.SetService(svc)

	secretMan, err := secretman.New(ctx, octeliumC, vCache)
	if err != nil {
		return nil, err
	}

	return &Server{
		octeliumC: octeliumC,
		vCache:    vCache,
		lbManager: loadbalancer.NewLbManager(octeliumC, vCache),
		secretMan: secretMan,
	}, nil
}

func TestRenderIndex(t *testing.T) {
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

	srv, err := newServer(ctx, fakeC.OcteliumC, svc)
	assert.Nil(t, err)

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
	srv := &Server{}

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
	srv := &Server{}

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
		recv, sent := rdp.Relay(ctx, downstream, upstreamConn, false)
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

	srv, err := newServer(ctx, fakeC.OcteliumC, svc)
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
