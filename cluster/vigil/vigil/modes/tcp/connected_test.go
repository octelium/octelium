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

package tcp

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/logentry"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"google.golang.org/protobuf/proto"
)

type tstTCPLogProcessor struct {
	records chan *corev1.AccessLog
}

func (p *tstTCPLogProcessor) Enabled(ctx context.Context, param sdklog.EnabledParameters) bool {
	return true
}

func (p *tstTCPLogProcessor) OnEmit(ctx context.Context, record *sdklog.Record) error {
	for _, field := range record.Body().AsMap() {
		if field.Key == "kind" && field.Value.AsString() == "AccessLog" {
			logE := &corev1.AccessLog{}
			if err := pbutils.UnmarshalJSONStrict([]byte(record.Body().String()), logE); err != nil {
				return err
			}
			p.records <- logE
			break
		}
	}
	return nil
}

func (p *tstTCPLogProcessor) Shutdown(ctx context.Context) error {
	return nil
}

func (p *tstTCPLogProcessor) ForceFlush(ctx context.Context) error {
	return nil
}

func newTCPLogRecorder(t *testing.T) <-chan *corev1.AccessLog {
	t.Helper()
	previous := global.GetLoggerProvider()
	processor := &tstTCPLogProcessor{records: make(chan *corev1.AccessLog, 16)}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
	global.SetLoggerProvider(provider)
	t.Cleanup(func() {
		global.SetLoggerProvider(previous)
		assert.Nil(t, provider.Shutdown(context.Background()))
	})
	return processor.records
}

func nextTCPAccessLog(t *testing.T, records <-chan *corev1.AccessLog) *corev1.AccessLog {
	t.Helper()
	select {
	case logE := <-records:
		return logE
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for a TCP access log")
		return nil
	}
}

func TestTCPConnectedLogTLS(t *testing.T) {
	for _, trusted := range []bool{false, true} {
		name := "Untrusted"
		if trusted {
			name = "Trusted"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			records := newTCPLogRecorder(t)
			peers := make(chan net.Addr, 1)
			backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			backend.Config.ConnContext = func(ctx context.Context, conn net.Conn) context.Context {
				peers <- conn.RemoteAddr()
				return ctx
			}
			backend.StartTLS()
			defer backend.Close()
			cfg := &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Url{Url: backend.URL},
				},
			}
			if trusted {
				cfg.Tls = &corev1.Service_Spec_Config_TLS{TrustedCAs: []string{
					string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw})),
				}}
			}
			svc := &corev1.Service{
				Metadata: &metav1.Metadata{Name: "service", Uid: "service"},
				Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_TCP, Config: cfg},
				Status:   &corev1.Service_Status{},
			}
			vc, err := vcache.NewCache(ctx)
			require.Nil(t, err)
			vc.SetService(svc)
			_, downstream := newTCPProxyTestPair(t)
			reqCtx := &corev1.RequestContext{
				Service: svc, Session: &corev1.Session{Metadata: &metav1.Metadata{Uid: "session"}},
			}
			d := newDctx(ctx, downstream, reqCtx, &coctovigilv1.AuthenticateAndAuthorizeResponse{RequestContext: reqCtx})
			startTime := time.Now().Add(-time.Second)
			done := make(chan struct{})
			go func() {
				defer close(done)
				d.serve(ctx, loadbalancer.NewLbManager(nil, vc), svc, nil, startTime)
			}()
			if trusted {
				connected := nextTCPAccessLog(t, records)
				assert.Equal(t, corev1.AccessLog_Entry_Info_TCP_CONNECTED, connected.Entry.Info.GetTcp().Type)
				assert.Equal(t, d.id, connected.Entry.Common.ConnectionID)
				assert.True(t, startTime.Equal(connected.Entry.Common.StartedAt.AsTime()))
				select {
				case peer := <-peers:
					assert.True(t, proto.Equal(logentry.GetEndpoint(peer), connected.Entry.Common.Network.UpstreamLocal))
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				assert.True(t, proto.Equal(logentry.GetEndpoint(backend.Listener.Addr()), connected.Entry.Common.Network.UpstreamRemote))
				select {
				case <-done:
					t.Fatal("The connection closed before application traffic was sent")
				default:
				}
				cancel()
			}
			select {
			case <-done:
			case <-ctx.Done():
				if !trusted {
					t.Fatal(ctx.Err())
				}
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("The TLS proxy did not stop after cancellation")
				}
			}
			if !trusted {
				assert.NotNil(t, d.proxy.upstreamErr)
				assert.Nil(t, d.network.UpstreamLocal)
				assert.Nil(t, d.network.UpstreamRemote)
			}
			select {
			case logE := <-records:
				t.Fatalf("Unexpected additional TCP access log: %s", logE)
			default:
			}
		})
	}
}
