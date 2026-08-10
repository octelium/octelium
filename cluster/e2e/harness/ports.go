/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package harness

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type PortAllocator struct {
	mu    sync.Mutex
	taken map[int]struct{}
}

func NewPortAllocator() *PortAllocator {
	return &PortAllocator{taken: map[int]struct{}{}}
}

func (p *PortAllocator) Get() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	for range 1000 {
		port, err := freePort()
		if err != nil {
			continue
		}
		if _, ok := p.taken[port]; ok {
			continue
		}
		p.taken[port] = struct{}{}
		return port
	}

	panic("Could not allocate a free localhost port")
}

func freePort() (int, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer lis.Close()

	return lis.Addr().(*net.TCPAddr).Port, nil
}

func WaitPortOpen(port int, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(DefaultPollInterval)
	}

	return fmt.Errorf("nothing is listening on %s after %s: %w", addr, budget, lastErr)
}
