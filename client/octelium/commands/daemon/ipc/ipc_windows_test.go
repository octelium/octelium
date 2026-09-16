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
	"os/user"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func getTestPipeName(t *testing.T) string {
	return fmt.Sprintf(`\\.\pipe\octelium-%d-%d`, os.Getpid(), time.Now().UnixNano())
}

func TestListen(t *testing.T) {
	lis, err := Listen(getTestPipeName(t))
	assert.Nil(t, err)
	assert.Nil(t, lis.Close())
}

func TestPeerPrincipal(t *testing.T) {
	addr := getTestPipeName(t)
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

	current, err := user.Current()
	assert.Nil(t, err)

	res := <-resCh
	assert.Nil(t, res.err)
	assert.Equal(t, current.Uid, res.principal.ID)
	assert.Equal(t, int32(os.Getpid()), res.principal.PID)
	assert.Equal(t, AuthType, NewTransportCredentials().Info().SecurityProtocol)
}

func TestGetPrincipal(t *testing.T) {
	_, err := GetPrincipal(context.Background())
	assert.NotNil(t, err)
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

func TestListenSingleton(t *testing.T) {
	addr := getTestPipeName(t)
	lis, err := Listen(addr)
	assert.Nil(t, err)
	t.Cleanup(func() {
		lis.Close()
	})

	_, err = Listen(addr)
	assert.NotNil(t, err)
}

func TestLookupPrincipal(t *testing.T) {
	current, err := user.Current()
	assert.Nil(t, err)

	pr, err := LookupPrincipal(current.Uid)
	assert.Nil(t, err)
	assert.Equal(t, current.Uid, pr.ID)
	assert.NotEmpty(t, pr.Name)
	assert.NotEmpty(t, pr.HomeDir)

	_, err = LookupPrincipal("not-a-sid")
	assert.NotNil(t, err)
}

func TestGetDefaultAddressOverride(t *testing.T) {
	t.Setenv("OCTELIUM_DAEMON_SOCKET", `\\.\pipe\custom-octelium`)
	assert.Equal(t, `\\.\pipe\custom-octelium`, GetDefaultAddress())
}
