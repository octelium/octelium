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
	"context"
	"net"
	"testing"
	"time"

	"github.com/octelium/octelium/client/octelium/commands/connect/ccommon"
	"github.com/stretchr/testify/assert"
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
