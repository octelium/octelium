package udp

import (
	"net"
	"testing"
	"time"

	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestUDPNetwork(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			ip := net.IPv4(127, 0, 0, 1)
			if network == "udp6" {
				ip = net.IPv6loopback
			}
			upstream, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
			require.Nil(t, err)
			defer upstream.Close()
			require.Nil(t, upstream.SetDeadline(time.Now().Add(5*time.Second)))
			srv := newTestUDPServer(t, upstream.LocalAddr().String())
			client, err := net.DialUDP("udp4", nil, &net.UDPAddr{
				IP: net.IPv4(127, 0, 0, 1), Port: srv.lis.LocalAddr().(*net.UDPAddr).Port,
			})
			require.Nil(t, err)
			defer client.Close()
			require.Nil(t, client.SetDeadline(time.Now().Add(5*time.Second)))
			_, err = client.Write([]byte("request"))
			require.Nil(t, err)
			buf := make([]byte, 32)
			n, peer, err := upstream.ReadFromUDP(buf)
			require.Nil(t, err)
			assert.Equal(t, "request", string(buf[:n]))
			srv.dctxMap.mu.Lock()
			active := srv.dctxMap.dctxMap[client.LocalAddr().String()]
			srv.dctxMap.mu.Unlock()
			require.NotNil(t, active)
			<-active.ready
			snapshot := active.network
			check := func() {
				assert.True(t, proto.Equal(logentry.GetEndpoint(client.LocalAddr()), snapshot.Downstream))
				assert.True(t, proto.Equal(logentry.GetEndpoint(peer), snapshot.UpstreamLocal))
				assert.True(t, proto.Equal(logentry.GetEndpoint(upstream.LocalAddr()), snapshot.UpstreamRemote))
			}
			check()
			_, err = upstream.WriteToUDP([]byte("response"), peer)
			require.Nil(t, err)
			n, err = client.Read(buf)
			require.Nil(t, err)
			assert.Equal(t, "response", string(buf[:n]))
			require.Nil(t, active.close())
			require.Eventually(t, func() bool {
				srv.dctxMap.mu.Lock()
				defer srv.dctxMap.mu.Unlock()
				return srv.dctxMap.dctxMap[client.LocalAddr().String()] == nil
			}, time.Second, time.Millisecond)
			check()
		})
	}
}
