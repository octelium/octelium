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

package ssh

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

type forwardSpec struct {
	bindAddr string
	bindPort string
	destAddr string
	destPort string
}

func parseForwardSpec(spec string) (*forwardSpec, error) {
	parts := strings.SplitN(spec, ":", 4)
	switch len(parts) {
	case 3:
		return &forwardSpec{
			bindAddr: "127.0.0.1",
			bindPort: parts[0],
			destAddr: parts[1],
			destPort: parts[2],
		}, nil
	case 4:
		return &forwardSpec{
			bindAddr: parts[0],
			bindPort: parts[1],
			destAddr: parts[2],
			destPort: parts[3],
		}, nil
	default:
		return nil, errors.Errorf("Expected [bind_addr:]port:host:hostport, got %q", spec)
	}
}

func parseDynamicSpec(spec string) (bindAddr, bindPort string, err error) {
	parts := strings.SplitN(spec, ":", 2)
	switch len(parts) {
	case 1:
		return "127.0.0.1", parts[0], nil
	case 2:
		return parts[0], parts[1], nil
	default:
		return "", "", errors.Errorf("Expected [bind_addr:]port, got %q", spec)
	}
}

func runLocalForward(ctx context.Context, sshClient *ssh.Client, spec *forwardSpec) {
	listenAddr := net.JoinHostPort(spec.bindAddr, spec.bindPort)
	destAddr := net.JoinHostPort(spec.destAddr, spec.destPort)

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		zap.L().Error("Local forward: Could not listen",
			zap.String("addr", listenAddr), zap.Error(err))
		return
	}
	defer lis.Close()

	zap.L().Debug("Local forward listening", zap.String("local", listenAddr),
		zap.String("dest", destAddr))

	go func() {
		<-ctx.Done()
		lis.Close()
	}()

	for {
		conn, err := lis.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				zap.L().Warn("Local forward: accept error", zap.Error(err))
				time.Sleep(200 * time.Millisecond)
				continue
			}
		}
		go handleLocalForwardConn(ctx, sshClient, conn, destAddr)
	}
}

func handleLocalForwardConn(ctx context.Context, sshClient *ssh.Client, localConn net.Conn, destAddr string) {
	defer localConn.Close()

	remoteConn, err := sshClient.Dial("tcp", destAddr)
	if err != nil {
		zap.L().Debug("Local forward: Could not dial remote",
			zap.String("dest", destAddr), zap.Error(err))
		return
	}
	defer remoteConn.Close()

	bidirectionalCopy(ctx, localConn, remoteConn)
}

func runDynamicForward(ctx context.Context, sshClient *ssh.Client, spec string) {
	bindAddr, bindPort, err := parseDynamicSpec(spec)
	if err != nil {
		zap.L().Error("Could not parseDynamicSpec", zap.String("spec", spec), zap.Error(err))
		return
	}

	listenAddr := net.JoinHostPort(bindAddr, bindPort)
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		zap.L().Error("Dynamic forward: Could not listen",
			zap.String("addr", listenAddr), zap.Error(err))
		return
	}
	defer lis.Close()

	zap.L().Debug("Dynamic forward (SOCKS5) listening", zap.String("addr", listenAddr))

	go func() {
		<-ctx.Done()
		lis.Close()
	}()

	for {
		conn, err := lis.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				zap.L().Debug("Dynamic forward: accept error", zap.Error(err))
				return
			}
		}
		go handleSOCKS5Conn(ctx, sshClient, conn)
	}
}

func handleSOCKS5Conn(ctx context.Context, sshClient *ssh.Client, conn net.Conn) {
	defer conn.Close()

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}
	if reqHeader[0] != 0x05 || reqHeader[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var destHost string
	switch reqHeader[3] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		destHost = net.IP(addr).String()
	case 0x04:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return
		}
		destHost = "[" + net.IP(addr).String() + "]"
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return
		}
		destHost = string(domain)
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	destPort := binary.BigEndian.Uint16(portBuf)
	destAddr := fmt.Sprintf("%s:%d", destHost, destPort)

	remoteConn, err := sshClient.Dial("tcp", destAddr)
	if err != nil {
		zap.L().Debug("Dynamic forward: Could not dial via SSH",
			zap.String("dest", destAddr), zap.Error(err))
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remoteConn.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	bidirectionalCopy(ctx, conn, remoteConn)
}

func bidirectionalCopy(ctx context.Context, a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if wc, ok := a.(writeCloser); ok {
			wc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if wc, ok := b.(writeCloser); ok {
			wc.CloseWrite()
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		a.Close()
		b.Close()
		<-done
	case <-done:
	}
}

type writeCloser interface {
	CloseWrite() error
}
