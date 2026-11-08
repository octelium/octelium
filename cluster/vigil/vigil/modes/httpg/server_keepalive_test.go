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

package httpg

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes"
	"github.com/octelium/octelium/cluster/vigil/vigil/octovigilc"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"
)

func newTestGRPCServer(t *testing.T, upstreamAddr string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	adminSrv := admin.NewServer(&admin.Opts{OcteliumC: tst.C.OcteliumC, IsEmbedded: true})
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_GRPC, Port: uint32(tests.GetPort()), IsPublic: true, IsAnonymous: true,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{Url: fmt.Sprintf("http://%s", upstreamAddr)},
				},
			},
		},
	})
	require.Nil(t, err)
	vc, err := vcache.NewCache(ctx)
	require.Nil(t, err)
	vc.SetService(svc)
	secretMan, err := secretman.New(ctx, tst.C.OcteliumC, vc)
	require.Nil(t, err)
	oc, err := octovigilc.NewClient(ctx, &octovigilc.Opts{OcteliumC: tst.C.OcteliumC, VCache: vc})
	require.Nil(t, err)
	srv, err := New(ctx, &modes.Opts{
		OcteliumC: tst.C.OcteliumC, VCache: vc, SecretMan: secretMan, OctovigilC: oc,
		LBManager: loadbalancer.NewLbManager(tst.C.OcteliumC, vc),
	})
	require.Nil(t, err)
	require.Nil(t, srv.Run(ctx))
	t.Cleanup(func() { srv.Close() })
	return fmt.Sprintf("127.0.0.1:%d", ucorev1.ToService(svc).RealPort())
}

type tstHealthWatch struct {
	cc   *http2.ClientConn
	body io.ReadCloser
}

func newTestHealthWatch(t *testing.T, addr string) *tstHealthWatch {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.Nil(t, err)
	cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(conn)
	require.Nil(t, err)
	t.Cleanup(func() { cc.Close() })

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		fmt.Sprintf("http://%s/grpc.health.v1.Health/Watch", addr), bytes.NewReader(make([]byte, 5)))
	require.Nil(t, err)
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	resp, err := cc.RoundTrip(req)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	t.Cleanup(func() { resp.Body.Close() })

	return &tstHealthWatch{
		cc:   cc,
		body: resp.Body,
	}
}

func (w *tstHealthWatch) recv() (grpc_health_v1.HealthCheckResponse_ServingStatus, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(w.body, hdr); err != nil {
		return 0, err
	}
	msg := make([]byte, binary.BigEndian.Uint32(hdr[1:]))
	if _, err := io.ReadFull(w.body, msg); err != nil {
		return 0, err
	}
	resp := &grpc_health_v1.HealthCheckResponse{}
	if err := proto.Unmarshal(msg, resp); err != nil {
		return 0, err
	}
	return resp.Status, nil
}

func (w *tstHealthWatch) recvWithTimeout(t *testing.T, timeout time.Duration) (grpc_health_v1.HealthCheckResponse_ServingStatus, error) {
	t.Helper()
	type result struct {
		status grpc_health_v1.HealthCheckResponse_ServingStatus
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		status, err := w.recv()
		resCh <- result{status: status, err: err}
	}()
	select {
	case res := <-resCh:
		return res.status, res.err
	case <-time.After(timeout):
		require.FailNow(t, "timed out waiting for a stream message")
		return 0, nil
	}
}

func TestHTTP2KeepalivePingsOnLongLivedGRPCStream(t *testing.T) {
	upstreamLis, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err)
	healthSrv := health.NewServer()
	grpcSrv := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcSrv, healthSrv)
	go grpcSrv.Serve(upstreamLis)
	t.Cleanup(grpcSrv.Stop)

	vigilAddr := newTestGRPCServer(t, upstreamLis.Addr().String())

	t.Run("vigil", func(t *testing.T) {
		healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
		w := newTestHealthWatch(t, vigilAddr)
		status, err := w.recvWithTimeout(t, 10*time.Second)
		require.Nil(t, err)
		require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, status)

		for range 50 {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			err := w.cc.Ping(ctx)
			cancel()
			require.Nil(t, err)
			time.Sleep(10 * time.Millisecond)
		}
		assert.True(t, w.cc.CanTakeNewRequest())

		healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		status, err = w.recvWithTimeout(t, 10*time.Second)
		require.Nil(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, status)

		w2 := newTestHealthWatch(t, vigilAddr)
		status, err = w2.recvWithTimeout(t, 10*time.Second)
		require.Nil(t, err)
		assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, status)
	})

	t.Run("grpc-upstream-directly", func(t *testing.T) {
		healthSrv.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
		w := newTestHealthWatch(t, upstreamLis.Addr().String())
		status, err := w.recvWithTimeout(t, 10*time.Second)
		require.Nil(t, err)
		require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, status)

		for range 10 {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			err := w.cc.Ping(ctx)
			cancel()
			if err != nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		_, err = w.recvWithTimeout(t, 10*time.Second)
		require.NotNil(t, err)
		assert.ErrorContains(t, err, "too_many_pings")
	})
}
