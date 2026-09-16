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
	"net"
	"os"
	"os/user"

	"github.com/Microsoft/go-winio"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

const defaultPipeName = `\\.\pipe\octelium-daemon`

func GetDefaultAddress() string {
	if ret := os.Getenv("OCTELIUM_DAEMON_SOCKET"); ret != "" {
		return ret
	}

	return defaultPipeName
}

func Listen(addr string) (net.Listener, error) {
	return winio.ListenPipe(addr, &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)",
	})
}

func Dial(ctx context.Context, addr string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, addr)
}

func getPeerPrincipal(conn net.Conn) (*Principal, error) {
	connWithHandle, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return nil, errors.Errorf("The daemon API is only served over local IPC")
	}

	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(connWithHandle.Fd()), &pid); err != nil {
		return nil, err
	}

	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(process)

	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return nil, err
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}

	ret, err := lookupPrincipal(tokenUser.User.Sid.String())
	if err != nil {
		return nil, err
	}
	ret.PID = int32(pid)

	return ret, nil
}

func LookupPrincipal(id string) (*Principal, error) {
	return lookupPrincipal(id)
}

func lookupPrincipal(id string) (*Principal, error) {
	usr, err := user.LookupId(id)
	if err != nil {
		return nil, errors.Errorf("Could not find the OS user: %s. %+v", id, err)
	}

	return &Principal{
		ID:      usr.Uid,
		GID:     usr.Gid,
		Name:    usr.Username,
		HomeDir: usr.HomeDir,
	}, nil
}
