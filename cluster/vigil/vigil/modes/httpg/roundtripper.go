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
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/mtls"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

type roundTripper struct {
	upstream  *loadbalancer.Upstream
	secretMan *secretman.SecretManager
}

func (s *Server) getRoundTripper(
	upstream *loadbalancer.Upstream) (*roundTripper, error) {
	return &roundTripper{
		upstream:  upstream,
		secretMan: s.secretMan,
	}, nil
}

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {

	rt, err := r.getRoundTripper(req)
	if err != nil {
		return nil, err
	}

	return rt.RoundTrip(req)
}

func (r *roundTripper) getRoundTripper(req *http.Request) (http.RoundTripper, error) {
	ctx := req.Context()
	reqCtx := middlewares.GetCtxRequestContext(ctx)
	svc := reqCtx.Service
	svcCfg := reqCtx.ServiceConfig

	tlsCfg, err := mtls.GetClientTLSCfg(ctx, svc, svcCfg, r.secretMan, r.upstream)
	if err != nil {
		return nil, err
	}

	if isHTTP2RequestUpstream(req, svc) {
		return r.getRoundTripperHTTP2(req, svc, tlsCfg)
	}

	return r.getRoundTripperHTTP1(req, svc, tlsCfg)
}

func isHTTP2RequestUpstream(req *http.Request, svc *corev1.Service) bool {
	if httpguts.HeaderValuesContainsToken(req.Header["Connection"], "Upgrade") {
		return false
	}
	return ucorev1.ToService(svc).IsUpstreamHTTP2()
}

func (r *roundTripper) getRoundTripperHTTP2(req *http.Request, svc *corev1.Service, tlsCfg *tls.Config) (http.RoundTripper, error) {
	ret, err := r.getRoundTripperHTTP1(req, svc, tlsCfg)
	if err != nil {
		return nil, err
	}
	_, err = http2.ConfigureTransports(ret)
	if err != nil {
		return nil, err
	}

	if ucorev1.ToService(svc).BackendScheme() == "h2c" || ucorev1.ToService(svc).IsGRPC() {

		return &http2.Transport{
			TLSClientConfig: tlsCfg,
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				dialer := &net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}

				return dialer.Dial(network, addr)
			},
			AllowHTTP: true,
		}, nil
	}

	return ret, nil
}

func (r *roundTripper) getRoundTripperHTTP1(req *http.Request, svc *corev1.Service, tlsCfg *tls.Config) (*http.Transport, error) {

	ret := &http.Transport{
		TLSClientConfig: tlsCfg,
		Proxy:           http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}

			return dialer.DialContext(ctx, network, addr)
		},

		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ReadBufferSize:        64 * 1024,
		WriteBufferSize:       64 * 1024,
	}

	return ret, nil
}
