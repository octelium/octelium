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

package httpg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/net/http2/hpack"
)

func TestDownstreamBody(t *testing.T) {
	readErr := errors.New("stream error: stream ID 11; INTERNAL_ERROR")

	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()

	expiredCtx, cancelExpired := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancelExpired()

	tstCases := []struct {
		name string
		ctx  context.Context
		r    io.Reader
		err  error
	}{
		{"active", t.Context(), iotest.ErrReader(readErr), readErr},
		{"canceled", canceledCtx, iotest.ErrReader(readErr), context.Canceled},
		{"deadline", expiredCtx, iotest.ErrReader(readErr), context.DeadlineExceeded},
		{"eof", canceledCtx, strings.NewReader(""), io.EOF},
	}

	for _, tc := range tstCases {
		t.Run(tc.name, func(t *testing.T) {
			b := &downstreamBody{
				ReadCloser: io.NopCloser(tc.r),
				ctx:        tc.ctx,
			}
			_, err := b.Read(make([]byte, 8))
			assert.Equal(t, tc.err, err)
		})
	}
}

type tstLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *tstLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *tstLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type tstDuplexUpstream struct {
	addr      string
	started   chan struct{}
	bodyErrCh chan error
}

func newTestDuplexUpstream(t *testing.T, abort bool) *tstDuplexUpstream {
	t.Helper()
	ret := &tstDuplexUpstream{
		started:   make(chan struct{}, 4),
		bodyErrCh: make(chan error, 4),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
		w.(http.Flusher).Flush()
		ret.started <- struct{}{}
		if abort {
			panic(http.ErrAbortHandler)
		}
		_, err := io.Copy(io.Discard, r.Body)
		ret.bodyErrCh <- err
	})

	upstream := httptest.NewServer(h2c.NewHandler(handler, &http2.Server{}))
	t.Cleanup(upstream.Close)
	ret.addr = upstream.Listener.Addr().String()

	return ret
}

func (u *tstDuplexUpstream) waitBodyErr(t *testing.T) error {
	t.Helper()
	select {
	case err := <-u.bodyErrCh:
		return err
	case <-time.After(10 * time.Second):
		require.FailNow(t, "timed out waiting for the upstream request body to end")
		return nil
	}
}

func (u *tstDuplexUpstream) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-u.started:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "timed out waiting for the upstream handler")
	}
}

func newTestResetServer(t *testing.T,
	mode corev1.Service_Spec_Mode, upstreamURL string,
	httpCfg *corev1.Service_Spec_Config_HTTP) (string, *tstLogBuffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })

	cfg := &corev1.Service_Spec_Config{
		Upstream: &corev1.Service_Spec_Config_Upstream{
			Type: &corev1.Service_Spec_Config_Upstream_Url{Url: upstreamURL},
		},
	}
	if httpCfg != nil {
		cfg.Type = &corev1.Service_Spec_Config_Http{Http: httpCfg}
	}

	adminSrv := admin.NewServer(&admin.Opts{OcteliumC: tst.C.OcteliumC, IsEmbedded: true})
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec: &corev1.Service_Spec{
			Mode: mode, Port: uint32(tests.GetPort()), IsPublic: true, IsAnonymous: true,
			Config: cfg,
		},
	})
	require.Nil(t, err)
	vc, err := vcache.NewCache(ctx)
	require.Nil(t, err)
	vc.SetService(svc)
	secretMan, err := secretman.New(ctx, tst.C.OcteliumC, vc)
	require.Nil(t, err)
	oc, err := octovigilc.NewClient(ctx, &octovigilc.Opts{OcteliumC: tst.C.OcteliumC, VCache: vc})
	require.Nil(t, err)
	srv, err := New(ctx, &modes.Opts{
		OcteliumC: tst.C.OcteliumC, VCache: vc, SecretMan: secretMan, OctovigilC: oc,
		LBManager: loadbalancer.NewLbManager(tst.C.OcteliumC, vc),
	})
	require.Nil(t, err)
	proxyLog := &tstLogBuffer{}
	srv.reverseProxyErrLogger = log.New(proxyLog, "", 0)
	require.Nil(t, srv.Run(ctx))
	t.Cleanup(func() { srv.Close() })

	return fmt.Sprintf("127.0.0.1:%d", ucorev1.ToService(svc).RealPort()), proxyLog
}

type tstH2Conn struct {
	addr string
	conn net.Conn
	fr   *http2.Framer
}

func newTestH2Conn(t *testing.T, addr string) *tstH2Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.Nil(t, err)
	t.Cleanup(func() { conn.Close() })
	require.Nil(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	_, err = conn.Write([]byte(http2.ClientPreface))
	require.Nil(t, err)
	fr := http2.NewFramer(conn, conn)
	require.Nil(t, fr.WriteSettings())

	return &tstH2Conn{
		addr: addr,
		conn: conn,
		fr:   fr,
	}
}

func (c *tstH2Conn) openStream(t *testing.T, streamID uint32) {
	t.Helper()
	var hdrs bytes.Buffer
	enc := hpack.NewEncoder(&hdrs)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: http.MethodPost},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: c.addr},
		{Name: ":path", Value: "/test.v1.Service/Stream"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
	} {
		require.Nil(t, enc.WriteField(f))
	}
	require.Nil(t, c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: hdrs.Bytes(),
		EndHeaders:    true,
	}))
	require.Nil(t, c.fr.WriteData(streamID, false, []byte("ping")))
}

func (c *tstH2Conn) waitFrame(t *testing.T, streamID uint32) http2.Frame {
	t.Helper()
	for {
		f, err := c.fr.ReadFrame()
		require.Nil(t, err)
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				require.Nil(t, c.fr.WriteSettingsAck())
			}
		case *http2.DataFrame:
			if f.StreamID == streamID && len(f.Data()) > 0 {
				return f
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == streamID {
				return f
			}
		}
	}
}

func TestHTTP2DownstreamResetCancelsUpstream(t *testing.T) {
	tstCases := []struct {
		name    string
		mode    corev1.Service_Spec_Mode
		scheme  string
		httpCfg *corev1.Service_Spec_Config_HTTP
	}{
		{"grpc", corev1.Service_Spec_GRPC, "http", nil},
		{"http", corev1.Service_Spec_HTTP, "h2c", &corev1.Service_Spec_Config_HTTP{ListenHTTP2: true}},
	}

	for _, tc := range tstCases {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newTestDuplexUpstream(t, false)
			addr, proxyLog := newTestResetServer(t, tc.mode,
				fmt.Sprintf("%s://%s", tc.scheme, upstream.addr), tc.httpCfg)

			c := newTestH2Conn(t, addr)
			c.openStream(t, 11)
			require.IsType(t, &http2.DataFrame{}, c.waitFrame(t, 11))

			require.Nil(t, c.fr.WriteRSTStream(11, http2.ErrCodeInternal))

			err := upstream.waitBodyErr(t)
			assert.ErrorContains(t, err, "CANCEL")
			assert.NotContains(t, err.Error(), "INTERNAL_ERROR")
			assert.Never(t, func() bool {
				return proxyLog.String() != ""
			}, 500*time.Millisecond, 10*time.Millisecond, proxyLog.String())

			c.openStream(t, 13)
			require.IsType(t, &http2.DataFrame{}, c.waitFrame(t, 13))
		})
	}
}

func TestHTTP1DownstreamCloseCancelsHTTP2Upstream(t *testing.T) {
	upstream := newTestDuplexUpstream(t, false)
	addr, proxyLog := newTestResetServer(t, corev1.Service_Spec_HTTP,
		fmt.Sprintf("h2c://%s", upstream.addr), &corev1.Service_Spec_Config_HTTP{})

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.Nil(t, err)
	_, err = conn.Write([]byte(fmt.Sprintf(
		"POST /upload HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nping\r\n", addr)))
	require.Nil(t, err)

	upstream.waitStarted(t)
	require.Nil(t, conn.Close())

	err = upstream.waitBodyErr(t)
	assert.ErrorContains(t, err, "CANCEL")
	assert.Never(t, func() bool {
		return proxyLog.String() != ""
	}, 500*time.Millisecond, 10*time.Millisecond, proxyLog.String())
}

func TestHTTP2UpstreamResetIsLogged(t *testing.T) {
	upstream := newTestDuplexUpstream(t, true)
	addr, proxyLog := newTestResetServer(t, corev1.Service_Spec_GRPC,
		fmt.Sprintf("http://%s", upstream.addr), nil)

	c := newTestH2Conn(t, addr)
	c.openStream(t, 11)

	f := c.waitFrame(t, 11)
	if _, ok := f.(*http2.DataFrame); ok {
		f = c.waitFrame(t, 11)
	}
	rst, ok := f.(*http2.RSTStreamFrame)
	require.True(t, ok)
	assert.Equal(t, http2.ErrCodeInternal, rst.ErrCode)

	assert.Contains(t, proxyLog.String(), "INTERNAL_ERROR; received from peer")
}
