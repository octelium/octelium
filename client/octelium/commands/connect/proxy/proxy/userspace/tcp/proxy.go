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

package tcp

import (
	"io"
	"net"
	"time"

	"go.uber.org/zap"
)

type Proxy struct {
}

func NewProxy(address string) (*Proxy, error) {
	return &Proxy{}, nil
}

func (p *Proxy) ServeTCP(conn, connBackend WriteCloser) {

	defer conn.Close()
	defer connBackend.Close()

	errChan := make(chan error, 2)
	go p.connCopy(conn, connBackend, errChan)
	go p.connCopy(connBackend, conn, errChan)

	<-errChan
}

func (p Proxy) connCopy(dst, src WriteCloser, errCh chan error) {
	_, err := io.Copy(dst, src)
	errCh <- err

	errClose := dst.CloseWrite()
	if errClose != nil {
		zap.S().Debugf("conn copy err: %+v", errClose)
		return
	}

	{
		err := dst.SetReadDeadline(time.Now().Add(2 * time.Second))
		if err != nil {
			zap.S().Debugf("Could not set read deadline: %+v", err)
		}
	}
}

type WriteCloser interface {
	net.Conn
	CloseWrite() error
}
