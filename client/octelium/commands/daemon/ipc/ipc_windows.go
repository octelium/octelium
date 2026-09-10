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

	"github.com/pkg/errors"
)

const defaultPipeName = `\\.\pipe\octelium-daemon`

func GetDefaultAddress() string {
	return defaultPipeName
}

func Listen(addr string) (net.Listener, error) {
	return nil, errors.Errorf("The Octelium daemon is not supported on Windows yet")
}

func Dial(ctx context.Context, addr string) (net.Conn, error) {
	return nil, errors.Errorf("The Octelium daemon is not supported on Windows yet")
}

func getPeerPrincipal(conn net.Conn) (*Principal, error) {
	return nil, errors.Errorf("The Octelium daemon is not supported on Windows yet")
}

func LookupPrincipal(id string) (*Principal, error) {
	return nil, errors.Errorf("The Octelium daemon is not supported on Windows yet")
}
