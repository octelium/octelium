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

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestListen(t *testing.T) {
	addr := path.Join(t.TempDir(), "sub", "daemon.sock")

	lis, err := Listen(addr)
	assert.Nil(t, err)
	t.Cleanup(func() {
		lis.Close()
	})

	info, err := os.Stat(addr)
	assert.Nil(t, err)
	assert.Equal(t, os.FileMode(0666), info.Mode().Perm())

	assert.Nil(t, lis.Close())

	lis2, err := Listen(addr)
	assert.Nil(t, err)
	assert.Nil(t, lis2.Close())
}

func TestPeerPrincipal(t *testing.T) {
	addr := path.Join(t.TempDir(), "daemon.sock")

	lis, err := Listen(addr)
	assert.Nil(t, err)
	t.Cleanup(func() {
		lis.Close()
	})

	type acceptResult struct {
		principal *Principal
		err       error
	}

	resCh := make(chan *acceptResult, 1)

	go func() {
		conn, err := lis.Accept()
		if err != nil {
			resCh <- &acceptResult{err: err}
			return
		}
		defer conn.Close()

		_, authInfo, err := NewTransportCredentials().ServerHandshake(conn)
		if err != nil {
			resCh <- &acceptResult{err: err}
			return
		}

		resCh <- &acceptResult{
			principal: authInfo.(*AuthInfo).Principal,
		}
	}()

	conn, err := Dial(context.Background(), addr)
	assert.Nil(t, err)
	t.Cleanup(func() {
		conn.Close()
	})

	res := <-resCh
	assert.Nil(t, res.err)
	assert.Equal(t, fmt.Sprintf("%d", os.Getuid()), res.principal.ID)
	assert.Equal(t, int32(os.Getpid()), res.principal.PID)
	assert.Equal(t, AuthType, NewTransportCredentials().Info().SecurityProtocol)
}

func TestGetPrincipal(t *testing.T) {
	{
		_, err := GetPrincipal(context.Background())
		assert.NotNil(t, err)
	}
}

func TestGetPeerPrincipalNonLocal(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	t.Cleanup(func() {
		lis.Close()
	})

	errCh := make(chan error, 1)

	go func() {
		conn, err := lis.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		_, err = getPeerPrincipal(conn)
		errCh <- err
	}()

	conn, err := net.Dial("tcp", lis.Addr().String())
	assert.Nil(t, err)
	t.Cleanup(func() {
		conn.Close()
	})

	assert.NotNil(t, <-errCh)
}
