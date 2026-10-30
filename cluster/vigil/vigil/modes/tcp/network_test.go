package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTCPNetwork(t *testing.T) {
	for _, dialFailure := range []bool{false, true} {
		for _, network := range []string{"tcp4", "tcp6"} {
			t.Run(fmt.Sprintf("%s/DialFailure=%t", network, dialFailure), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				ip := net.IPv4(127, 0, 0, 1)
				if network == "tcp6" {
					ip = net.IPv6loopback
				}
				lis, err := net.ListenTCP(network, &net.TCPAddr{IP: ip})
				require.Nil(t, err)
				defer lis.Close()
				require.Nil(t, lis.SetDeadline(time.Now().Add(5*time.Second)))
				client, err := net.DialTCP(network, nil, lis.Addr().(*net.TCPAddr))
				require.Nil(t, err)
				defer client.Close()
				require.Nil(t, client.SetDeadline(time.Now().Add(5*time.Second)))
				downstream, err := lis.AcceptTCP()
				require.Nil(t, err)
				defer downstream.Close()
				upstream, err := net.ListenTCP(network, &net.TCPAddr{IP: ip})
				require.Nil(t, err)
				defer upstream.Close()
				require.Nil(t, upstream.SetDeadline(time.Now().Add(5*time.Second)))
				svc := &corev1.Service{
					Metadata: &metav1.Metadata{Name: "service", Uid: "service"},
					Spec: &corev1.Service_Spec{Mode: corev1.Service_Spec_TCP, Config: &corev1.Service_Spec_Config{
						Upstream: &corev1.Service_Spec_Config_Upstream{
							Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "tcp://" + upstream.Addr().String()},
						},
					}},
					Status: &corev1.Service_Status{},
				}
				vc, err := vcache.NewCache(ctx)
				require.Nil(t, err)
				vc.SetService(svc)
				reqCtx := &corev1.RequestContext{
					Service: svc, Session: &corev1.Session{Metadata: &metav1.Metadata{Uid: "session"}},
				}
				d := newDctx(ctx, downstream, reqCtx, &coctovigilv1.AuthenticateAndAuthorizeResponse{RequestContext: reqCtx})
				start := logentry.InitializeLogEntry(&logentry.InitializeLogEntryOpts{
					StartTime: time.Now(), ReqCtx: reqCtx, Network: d.network,
				})
				if dialFailure {
					require.Nil(t, upstream.Close())
					d.serve(ctx, loadbalancer.NewLbManager(nil, vc), svc, nil)
					assert.NotNil(t, d.proxy.upstreamErr)
					assert.Same(t, start.Entry.Common.Network, d.network)
					assert.Nil(t, d.network.UpstreamLocal)
					assert.Nil(t, d.network.UpstreamRemote)
					return
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					d.serve(ctx, loadbalancer.NewLbManager(nil, vc), svc, nil)
				}()
				backend, err := upstream.AcceptTCP()
				require.Nil(t, err)
				defer backend.Close()
				require.Nil(t, backend.SetDeadline(time.Now().Add(5*time.Second)))
				_, err = client.Write([]byte("request"))
				require.Nil(t, err)
				require.Nil(t, client.CloseWrite())
				body, err := io.ReadAll(backend)
				require.Nil(t, err)
				assert.Equal(t, "request", string(body))
				_, err = backend.Write([]byte("response"))
				require.Nil(t, err)
				require.Nil(t, backend.CloseWrite())
				body, err = io.ReadAll(client)
				require.Nil(t, err)
				assert.Equal(t, "response", string(body))
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				require.Nil(t, d.close())
				assert.Equal(t, logentry.GetEndpoint(client.LocalAddr()), d.network.Downstream)
				assert.Equal(t, logentry.GetEndpoint(backend.RemoteAddr()), d.network.UpstreamLocal)
				assert.Equal(t, logentry.GetEndpoint(backend.LocalAddr()), d.network.UpstreamRemote)
				assert.Nil(t, start.Entry.Common.Network.UpstreamLocal)
				assert.Nil(t, start.Entry.Common.Network.UpstreamRemote)
			})
		}
	}
}
