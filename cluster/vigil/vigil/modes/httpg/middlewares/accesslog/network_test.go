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

package accesslog

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/stretchr/testify/assert"
)

func TestAccessLogNetwork(t *testing.T) {
	for _, mode := range []corev1.Service_Spec_Mode{
		corev1.Service_Spec_HTTP, corev1.Service_Spec_WEB, corev1.Service_Spec_GRPC,
		corev1.Service_Spec_KUBERNETES, corev1.Service_Spec_MCP, corev1.Service_Spec_LLM,
		corev1.Service_Spec_RDP_WEB,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			svc := &corev1.Service{
				Metadata: &metav1.Metadata{Name: "service", Uid: "service"},
				Spec:     &corev1.Service_Spec{Mode: mode},
				Status:   &corev1.Service_Status{},
			}
			reqCtx := &middlewares.RequestContext{
				CreatedAt: time.Now(), Service: svc,
				DownstreamInfo: &corev1.RequestContext{Service: svc},
			}
			for _, network := range []*corev1.AccessLog_Entry_Common_Network{
				nil,
				{ForwardedClientIP: "203.0.113.1"},
				{
					Downstream:     &corev1.AccessLog_Entry_Common_Network_Endpoint{Ip: "100.64.0.1", Port: 40000},
					UpstreamLocal:  &corev1.AccessLog_Entry_Common_Network_Endpoint{Ip: "192.0.2.1", Port: 40001},
					UpstreamRemote: &corev1.AccessLog_Entry_Common_Network_Endpoint{Ip: "192.0.2.2", Port: 443},
				},
			} {
				reqCtx.SetNetwork(network)
				logE := (&middleware{}).getAccessLog(
					httptest.NewRequest(http.MethodGet, "/", nil),
					newResponseWriter(httptest.NewRecorder(), streamKindNone),
					reqCtx, logPhaseComplete, "connection", 0,
				)
				assert.Same(t, network, logE.Entry.Common.Network)
			}
		})
	}
}
