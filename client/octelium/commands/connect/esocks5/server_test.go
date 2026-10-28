// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package esocks5

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"go.uber.org/zap"
	xproxy "golang.org/x/net/proxy"
)

type tstGoNetCtl struct {
}

func (c *tstGoNetCtl) GetGoNet() ccommon.GoNet {
	return nil
}

func newEchoTarget(t *testing.T) net.Listener {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)

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

	return lis
}

func TestServer(t *testing.T) {
	zapCfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.DebugLevel),
		Development:      true,
		Encoding:         "console",
		EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := zapCfg.Build()
	assert.Nil(t, err)

	zap.ReplaceGlobals(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targetLis := newEchoTarget(t)
	defer targetLis.Close()

	targetAddr := targetLis.Addr().String()

	proxyAddr := "127.0.0.1:3055"

	opts := &Opts{
		GoNetCtl: &tstGoNetCtl{},
		ListenAddrs: []string{
			proxyAddr,
		},
	}

	srv, err := NewServer(opts)
	assert.Nil(t, err)

	err = srv.Start(ctx)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	{
		doConnect := func(target string) {
			dialer, err := xproxy.SOCKS5("tcp", proxyAddr, nil, xproxy.Direct)
			assert.Nil(t, err, "%+v", err)

			conn, err := dialer.Dial("tcp", target)
			assert.Nil(t, err, "%+v", err)

			msg := []byte("hello octelium embedded socks5")

			_, err = conn.Write(msg)
			assert.Nil(t, err)

			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			assert.Nil(t, err, "%+v", err)
			assert.Equal(t, msg, buf[:n])

			conn.Close()
		}

		doConnect(targetAddr)
		doConnect(targetAddr)
	}

	time.Sleep(2 * time.Second)
	err = srv.Close()
	assert.Nil(t, err)
}

func TestServerRejectsIncompleteOptions(t *testing.T) {
	for _, opts := range []*Opts{nil, {}, {GoNetCtl: &tstGoNetCtl{}}, {ListenAddrs: []string{"127.0.0.1:0"}}} {
		srv, err := NewServer(opts)
		assert.Error(t, err)
		assert.Nil(t, srv)
	}
}

func TestSOCKSTargetAddressesAndValidation(t *testing.T) {
	for _, tt := range []struct {
		name string
		addr *statute.AddrSpec
		want string
	}{
		{"domain", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: " EXAMPLE.COM. ", Port: 443}, "example.com:443"},
		{"ipv4", &statute.AddrSpec{AddrType: statute.ATYPIPv4, IP: net.ParseIP("192.0.2.1"), Port: 65535}, "192.0.2.1:65535"},
		{"ipv6", &statute.AddrSpec{AddrType: statute.ATYPIPv6, IP: net.ParseIP("2001:db8::1"), Port: 80}, "[2001:db8::1]:80"},
		{"nil", nil, ""},
		{"zero-port", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: "example.com"}, ""},
		{"large-port", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: "example.com", Port: 65536}, ""},
		{"negative-port", &statute.AddrSpec{AddrType: statute.ATYPDomain, FQDN: "example.com", Port: -1}, ""},
		{"wrong-ipv4", &statute.AddrSpec{AddrType: statute.ATYPIPv4, IP: net.ParseIP("::1"), Port: 80}, ""},
		{"wrong-ipv6", &statute.AddrSpec{AddrType: statute.ATYPIPv6, IP: net.ParseIP("127.0.0.1"), Port: 80}, ""},
		{"unknown-type", &statute.AddrSpec{AddrType: 255, Port: 80}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newTarget(&gosocks5.Request{Request: statute.Request{Command: statute.CommandConnect}, RawDestAddr: tt.addr})
			if tt.want == "" {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got.addr)
			}
		})
	}
	_, err := newTarget(nil)
	assert.Error(t, err)
	_, err = newTarget(&gosocks5.Request{Request: statute.Request{Command: statute.CommandBind}, RawDestAddr: &statute.AddrSpec{Port: 80}})
	assert.Error(t, err)
	for _, domain := range []string{"", " ", ".", "host/name", `host\name`, "host\x00name", strings.Repeat("a", 254)} {
		_, err := normalizeDomain(domain)
		assert.Error(t, err, "%q", domain)
	}
}

func TestSOCKSProtocolRejectsUnsupportedMethodsAndCommands(t *testing.T) {
	srv, err := NewServer(&Opts{GoNetCtl: &tstGoNetCtl{}, ListenAddrs: []string{"127.0.0.1:0"}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	require.NoError(t, srv.Start(ctx))
	t.Cleanup(func() { srv.Close() })
	for _, cmd := range []byte{statute.CommandBind, statute.CommandAssociate} {
		conn, err := net.DialTimeout("tcp", srv.listeners[0].Addr().String(), time.Second)
		require.NoError(t, err)
		require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
		_, err = conn.Write([]byte{5, 1, 0})
		require.NoError(t, err)
		var method [2]byte
		_, err = io.ReadFull(conn, method[:])
		require.NoError(t, err)
		assert.Equal(t, [2]byte{5, 0}, method)
		_, err = conn.Write([]byte{5, cmd, 0, 1, 127, 0, 0, 1, 0, 80})
		require.NoError(t, err)
		var reply [10]byte
		_, err = io.ReadFull(conn, reply[:])
		require.NoError(t, err)
		assert.Equal(t, byte(statute.RepRuleFailure), reply[1])
		assert.NoError(t, conn.Close())
	}
	conn, err := net.DialTimeout("tcp", srv.listeners[0].Addr().String(), time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	_, err = conn.Write([]byte{5, 1, 2})
	require.NoError(t, err)
	var reply [2]byte
	_, err = io.ReadFull(conn, reply[:])
	require.NoError(t, err)
	assert.Equal(t, [2]byte{5, 255}, reply)
}

func TestSOCKSCancelClosesIncompleteHandshakes(t *testing.T) {
	srv, err := NewServer(&Opts{GoNetCtl: &tstGoNetCtl{}, ListenAddrs: []string{"127.0.0.1:0"}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	require.NoError(t, srv.Start(ctx))
	t.Cleanup(func() { srv.Close() })
	conn, err := net.DialTimeout("tcp", srv.listeners[0].Addr().String(), time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	_, err = conn.Write([]byte{5, 1, 0})
	require.NoError(t, err)
	var method [2]byte
	_, err = io.ReadFull(conn, method[:])
	require.NoError(t, err)
	cancel()
	_, err = conn.Read(make([]byte, 1))
	assert.Error(t, err)
	if netErr, ok := err.(net.Error); ok {
		assert.False(t, netErr.Timeout())
	} else {
		assert.ErrorIs(t, err, io.EOF)
	}
	assert.NoError(t, srv.Close())
	assert.NoError(t, srv.Close())
}

func TestSOCKSUnsupportedWriterReturnsProtocolFailure(t *testing.T) {
	var buf bytes.Buffer
	srv := &Server{}
	err := srv.handleConnect(t.Context(), &buf, &gosocks5.Request{})
	assert.Error(t, err)
	require.GreaterOrEqual(t, buf.Len(), 2)
	assert.Equal(t, byte(statute.RepServerFailure), buf.Bytes()[1])
}

func TestSOCKSKnownIssues(t *testing.T) {
	if os.Getenv("OCTELIUM_TEST_KNOWN_ISSUES") != "true" {
		t.Skip("set OCTELIUM_TEST_KNOWN_ISSUES=true to reproduce CL-017 in tmp/client-test-report.md")
	}
	t.Run("CL-017-canceled-bind-retries", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer lis.Close()
			srv, err := NewServer(&Opts{GoNetCtl: &tstGoNetCtl{}, ListenAddrs: []string{lis.Addr().String()}})
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			started := time.Now()
			assert.Error(t, srv.Start(ctx))
			assert.Less(t, time.Since(started), time.Second)
		})
	})
}
