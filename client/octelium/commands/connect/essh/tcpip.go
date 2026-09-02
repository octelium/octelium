//go:build !windows
// +build !windows

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

package essh

import (
	"context"
	"io"
	"net"
	"strconv"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

const tcpipTerminationDelay = 5 * time.Second

type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

func (c *dctx) handleTCPIPChan(ctx context.Context, nch ssh.NewChannel) {

	d := localForwardChannelData{}
	if err := ssh.Unmarshal(nch.ExtraData(), &d); err != nil {
		zap.L().Debug("Could not parse tcpip data", zap.Error(err))
		nch.Reject(ssh.ConnectionFailed, "Could not parse data: "+err.Error())
		return
	}
	dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))

	var dialer net.Dialer
	dconn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		zap.L().Debug("Could not dial destination", zap.Error(err))
		nch.Reject(ssh.ConnectionFailed, "Could not dial destination")
		return
	}

	ch, reqs, err := nch.Accept()
	if err != nil {
		zap.L().Debug("Could not accept tcpip nch", zap.Error(err))
		dconn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)

	errCh := make(chan struct{}, 2)

	go func() {
		io.Copy(ch, dconn)
		ch.CloseWrite()
		errCh <- struct{}{}
	}()

	go func() {
		io.Copy(dconn, ch)
		if tc, ok := dconn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		errCh <- struct{}{}
	}()

	defer ch.Close()
	defer dconn.Close()

	select {
	case <-ctx.Done():
		return
	case <-errCh:
	}

	select {
	case <-ctx.Done():
	case <-errCh:
	case <-time.After(tcpipTerminationDelay):
		zap.L().Debug("Timed out waiting for the forwarded conn to drain",
			zap.String("dest", dest))
	}
}
