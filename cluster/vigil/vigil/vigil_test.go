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

package vigil

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C

	adminSrv := admin.NewServer(&admin.Opts{
		OcteliumC:  fakeC.OcteliumC,
		IsEmbedded: true,
	})
	svc, err := adminSrv.CreateService(ctx, &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Port: uint32(tests.GetPort()),
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{
						Url: "https://example.com",
					},
				},
			},
		},
	})
	assert.Nil(t, err)

	srv, err := NewServer(ctx, &Opts{
		OcteliumC: fakeC.OcteliumC,
		Service:   svc,
	})
	assert.Nil(t, err, "%+v", err)

	err = srv.server.Run(ctx)
	assert.Nil(t, err, "%+v", err)

	time.Sleep(1 * time.Second)

	svc2 := pbutils.Clone(svc).(*corev1.Service)

	svc2.Spec.Port = 8081
	svc2, err = adminSrv.UpdateService(ctx, svc2)
	assert.Nil(t, err)

	err = srv.svcCtl.FnOnUpdate(ctx, svc2, svc)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	svc3 := pbutils.Clone(svc2).(*corev1.Service)
	svc3.Spec.GetConfig().GetUpstream().Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "postgres://localhost:5432",
	}

	svc3, err = adminSrv.UpdateService(ctx, svc3)
	assert.Nil(t, err)

	err = srv.svcCtl.FnOnUpdate(ctx, svc3, svc2)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	svc4 := pbutils.Clone(svc3).(*corev1.Service)
	svc4.Spec.GetConfig().GetUpstream().Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "ssh://localhost:2022",
	}
	svc4.Spec.Mode = corev1.Service_Spec_SSH

	svc4, err = adminSrv.UpdateService(ctx, svc4)
	assert.Nil(t, err)

	err = srv.svcCtl.FnOnUpdate(ctx, svc4, svc3)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	svc5 := pbutils.Clone(svc4).(*corev1.Service)
	svc5.Spec.GetConfig().GetUpstream().Type = &corev1.Service_Spec_Config_Upstream_Url{
		Url: "dns://8.8.8.8",
	}

	svc5.Spec.Mode = corev1.Service_Spec_TCP

	svc5, err = adminSrv.UpdateService(ctx, svc5)
	assert.Nil(t, err)

	err = srv.svcCtl.FnOnUpdate(ctx, svc5, svc4)
	assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	err = srv.server.Close()
	assert.Nil(t, err)
}

func TestDisabledModes(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	tst, err := tests.Initialize(nil)
	require.Nil(t, err)
	t.Cleanup(func() { tst.Destroy() })
	adminSrv := admin.NewServer(&admin.Opts{OcteliumC: tst.C.OcteliumC, IsEmbedded: true})

	for _, tc := range []struct {
		mode   corev1.Service_Spec_Mode
		scheme string
		http   bool
	}{
		{corev1.Service_Spec_HTTP, "http", true},
		{corev1.Service_Spec_WEB, "http", true},
		{corev1.Service_Spec_GRPC, "grpc", true},
		{corev1.Service_Spec_KUBERNETES, "https", true},
		{corev1.Service_Spec_MCP, "http", true},
		{corev1.Service_Spec_LLM, "https", true},
		{corev1.Service_Spec_RDP_WEB, "tcp", true},
		{corev1.Service_Spec_TCP, "tcp", false},
		{corev1.Service_Spec_UDP, "udp", false},
		{corev1.Service_Spec_DNS, "udp", false},
		{corev1.Service_Spec_SSH, "ssh", false},
		{corev1.Service_Spec_POSTGRES, "postgres", false},
		{corev1.Service_Spec_MYSQL, "mysql", false},
		{corev1.Service_Spec_RDP, "tcp", false},
	} {
		t.Run(tc.mode.String(), func(t *testing.T) {
			svc, err := adminSrv.CreateService(ctx, &corev1.Service{
				Metadata: &metav1.Metadata{Name: utilrand.GetRandomStringCanonical(8)},
				Spec: &corev1.Service_Spec{
					Mode: tc.mode, Port: uint32(tests.GetPort()), IsDisabled: true,
					Config: &corev1.Service_Spec_Config{
						Upstream: &corev1.Service_Spec_Config_Upstream{
							Type: &corev1.Service_Spec_Config_Upstream_Url{Url: tc.scheme + "://127.0.0.1:1"},
						},
					},
				},
			})
			require.Nil(t, err)
			srv, err := NewServer(ctx, &Opts{OcteliumC: tst.C.OcteliumC, Service: svc})
			require.Nil(t, err)
			require.Nil(t, srv.server.Run(ctx))
			t.Cleanup(func() { srv.server.Close() })
			addr := fmt.Sprintf("127.0.0.1:%d", ucorev1.ToService(svc).RealPort())

			switch {
			case tc.http:
				client := &http.Client{Timeout: 3 * time.Second}
				resp, err := client.Get("http://" + addr + "/")
				require.Nil(t, err)
				defer resp.Body.Close()
				assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
			case tc.mode == corev1.Service_Spec_DNS:
				req := new(dns.Msg)
				req.SetQuestion("example.com.", dns.TypeA)
				client := &dns.Client{Net: "udp", Timeout: 200 * time.Millisecond}
				require.Eventually(t, func() bool {
					resp, _, err := client.Exchange(req, addr)
					return err == nil && resp.Rcode == dns.RcodeServerFailure
				}, 3*time.Second, 20*time.Millisecond)
			case tc.mode == corev1.Service_Spec_UDP:
				conn, err := net.Dial("udp", addr)
				require.Nil(t, err)
				defer conn.Close()
				require.Nil(t, conn.SetDeadline(time.Now().Add(100*time.Millisecond)))
				_, err = conn.Write([]byte("disabled"))
				require.Nil(t, err)
				_, err = conn.Read(make([]byte, 32))
				require.NotNil(t, err)
				var netErr net.Error
				require.ErrorAs(t, err, &netErr)
				assert.True(t, netErr.Timeout())
			default:
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				require.Nil(t, err)
				defer conn.Close()
				require.Nil(t, conn.SetDeadline(time.Now().Add(2*time.Second)))
				_, err = io.Copy(io.Discard, conn)
				assert.Nil(t, err)
			}
		})
	}
}
