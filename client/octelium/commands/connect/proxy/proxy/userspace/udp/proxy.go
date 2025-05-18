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

package udp

import (
	"io"
	"net"
)

// Proxy is a reverse-proxy implementation of the Handler interface.
type Proxy struct {
	// TODO: maybe optimize by pre-resolving it at proxy creation time
	target string
}

// NewProxy creates a new Proxy.
func NewProxy(address string) (*Proxy, error) {
	return &Proxy{target: address}, nil
}

// ServeUDP implements the Handler interface.
func (p *Proxy) ServeUDP(conn *Conn) {

	// needed because of e.g. server.trackedConnection
	defer conn.Close()

	connBackend, err := net.Dial("udp", p.target)
	if err != nil {

		return
	}

	// maybe not needed, but just in case
	defer connBackend.Close()

	errChan := make(chan error)
	go p.connCopy(conn, connBackend, errChan)
	go p.connCopy(connBackend, conn, errChan)

	err = <-errChan
	if err != nil {

	}

	<-errChan
}

func (p Proxy) connCopy(dst io.WriteCloser, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	errCh <- err

	if err := dst.Close(); err != nil {

	}
}
