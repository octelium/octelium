package logentry

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr net.Addr
		ip   string
		port uint32
	}{
		{"TCP4", &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 54321}, "192.0.2.1", 54321},
		{"TCP6", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 65535}, "2001:db8::1", 65535},
		{"UDP4", &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 12345}, "192.0.2.2", 12345},
		{"UDP6", &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 0}, "2001:db8::2", 0},
		{"Nil", nil, "", 0},
		{"NilTCP", (*net.TCPAddr)(nil), "", 0},
		{"NilUDP", (*net.UDPAddr)(nil), "", 0},
		{"MissingIP", &net.TCPAddr{Port: 54321}, "", 0},
		{"InvalidIP", &net.TCPAddr{IP: net.IP{1, 2, 3}, Port: 54321}, "", 0},
		{"NegativePort", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: -1}, "", 0},
		{"InvalidPort", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 65536}, "", 0},
		{"Unix", &net.UnixAddr{Name: "socket", Net: "unix"}, "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := GetEndpoint(tc.addr)
			if tc.ip == "" {
				assert.Nil(t, endpoint)
				assert.Nil(t, GetNetwork(tc.addr))
				return
			}
			require.NotNil(t, endpoint)
			assert.Equal(t, tc.ip, endpoint.Ip)
			assert.Equal(t, tc.port, endpoint.Port)
		})
	}
}

func TestNetworkSocketSnapshots(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			address := "127.0.0.1:0"
			if network[len(network)-1] == '6' {
				address = "[::1]:0"
			}
			var conn net.Conn
			var peer net.Addr
			if network[:3] == "tcp" {
				lis, err := net.Listen(network, address)
				require.Nil(t, err)
				defer lis.Close()
				conn, err = net.DialTimeout(network, lis.Addr().String(), time.Second)
				require.Nil(t, err)
				accepted, err := lis.Accept()
				require.Nil(t, err)
				defer accepted.Close()
				peer = accepted.RemoteAddr()
				conn = tls.Client(conn, &tls.Config{})
			} else {
				lis, err := net.ListenPacket(network, address)
				require.Nil(t, err)
				defer lis.Close()
				conn, err = net.DialTimeout(network, lis.LocalAddr().String(), time.Second)
				require.Nil(t, err)
				require.Nil(t, lis.SetReadDeadline(time.Now().Add(time.Second)))
				_, err = conn.Write([]byte("packet"))
				require.Nil(t, err)
				_, peer, err = lis.ReadFrom(make([]byte, 32))
				require.Nil(t, err)
			}
			defer conn.Close()
			start := GetNetwork(&net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 40000})
			end := WithUpstream(start, conn)
			assert.NotSame(t, start, end)
			assert.Nil(t, start.UpstreamLocal)
			assert.Nil(t, start.UpstreamRemote)
			assert.Same(t, start.Downstream, end.Downstream)
			assert.Equal(t, GetEndpoint(peer), end.UpstreamLocal)
			assert.Equal(t, GetEndpoint(conn.RemoteAddr()), end.UpstreamRemote)
			require.Nil(t, conn.Close())
			assert.Equal(t, GetEndpoint(peer), end.UpstreamLocal)
		})
	}
}

func TestNetworkUnavailableUpstream(t *testing.T) {
	assert.Nil(t, WithUpstream(nil, nil))
	network := &corev1.AccessLog_Entry_Common_Network{ForwardedClientIP: "203.0.113.1"}
	assert.Same(t, network, WithUpstream(network, nil))
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	assert.Same(t, network, WithUpstream(network, conn))
}

func TestInitializeLogEntryNetwork(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		network := GetNetwork(&net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 54321})
		logE := InitializeLogEntry(&InitializeLogEntryOpts{
			StartTime:    time.Now(),
			IsAuthorized: allowed,
			ReqCtx: &corev1.RequestContext{Service: &corev1.Service{
				Metadata: &metav1.Metadata{Name: "service", Uid: "service"},
				Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_TCP},
				Status:   &corev1.Service_Status{},
			}},
			Network: network,
		})
		require.NotNil(t, logE)
		assert.Same(t, network, logE.Entry.Common.Network)
		data, err := pbutils.MarshalJSON(logE, false)
		require.Nil(t, err)
		var decoded map[string]any
		require.Nil(t, json.Unmarshal(data, &decoded))
		entry := decoded["entry"].(map[string]any)
		common := entry["common"].(map[string]any)
		downstream := common["network"].(map[string]any)["downstream"].(map[string]any)
		assert.Equal(t, "100.64.0.1", downstream["ip"])
		assert.Equal(t, float64(54321), downstream["port"])
	}
}
