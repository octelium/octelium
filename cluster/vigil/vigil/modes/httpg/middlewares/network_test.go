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

package middlewares

import (
	"net"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
)

type networkTestConn struct {
	net.Conn
	port int
}

func (c *networkTestConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.port}
}

func (c *networkTestConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.port + 1}
}

func TestRequestContextNetworkConcurrent(t *testing.T) {
	r := &RequestContext{}
	r.SetNetwork(&corev1.AccessLog_Entry_Common_Network{ForwardedClientIP: "203.0.113.1"})
	start := r.GetNetwork()
	r.SetUpstreamConnection(&networkTestConn{port: 10000})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				r.SetUpstreamConnection(&networkTestConn{port: 10000 + i})
				network := r.GetNetwork()
				assert.Equal(t, "203.0.113.1", network.ForwardedClientIP)
				assert.Equal(t, network.UpstreamLocal.Port+1, network.UpstreamRemote.Port)
				_, err := pbutils.MarshalJSON(network, false)
				assert.Nil(t, err)
			}
		})
	}
	wg.Wait()
	assert.Nil(t, start.UpstreamLocal)
	assert.Nil(t, start.UpstreamRemote)
}

func BenchmarkRequestContextNetworkSnapshot(b *testing.B) {
	r := &RequestContext{}
	network := &corev1.AccessLog_Entry_Common_Network{ForwardedClientIP: "203.0.113.1"}
	r.SetNetwork(network)
	b.ReportAllocs()
	for b.Loop() {
		if r.GetNetwork() != network {
			b.Fatal("network snapshot changed")
		}
	}
}
