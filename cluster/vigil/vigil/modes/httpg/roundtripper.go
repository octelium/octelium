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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/vigil/vigil/loadbalancer"
	"github.com/octelium/octelium/cluster/vigil/vigil/modes/httpg/middlewares"
	"github.com/octelium/octelium/cluster/vigil/vigil/mtls"
	"github.com/octelium/octelium/cluster/vigil/vigil/secretman"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/pkg/errors"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

const (
	upstreamIdleConnTimeout     = 90 * time.Second
	upstreamMaxIdleConns        = 256
	upstreamMaxIdleConnsPerHost = 32
	upstreamDialTimeout         = 30 * time.Second
	upstreamDialKeepAlive       = 30 * time.Second
	upstreamTLSHandshakeTimeout = 10 * time.Second
	upstreamReadBufferSize      = 32 * 1024
	upstreamWriteBufferSize     = 32 * 1024
)

type transportMode int

const (
	transportModeHTTP1 transportMode = iota
	transportModeHTTP2TLS
	transportModeH2
)

func (m transportMode) String() string {
	switch m {
	case transportModeHTTP2TLS:
		return "h2-tls"
	case transportModeH2:
		return "h2"
	default:
		return "http1"
	}
}

type roundTripper struct {
	upstream   *loadbalancer.Upstream
	secretMan  *secretman.SecretManager
	transports *transportCache
}

func (s *Server) getRoundTripper(upstream *loadbalancer.Upstream) (*roundTripper, error) {
	return &roundTripper{
		upstream:   upstream,
		secretMan:  s.secretMan,
		transports: s.transports,
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
	if reqCtx == nil || reqCtx.Service == nil {
		return nil, errors.Errorf("Could not get the RequestContext")
	}

	svc := reqCtx.Service
	svcCfg := reqCtx.ServiceConfig

	mode := getTransportMode(req, svc, svcCfg)

	isTLS := strings.EqualFold(req.URL.Scheme, "https")

	key, err := r.getTransportKey(svc, svcCfg, mode, isTLS)
	if err != nil {
		return nil, err
	}

	return r.transports.getOrCreate(key, func() (http.RoundTripper, func(), error) {
		tlsCfg, err := mtls.GetClientTLSCfg(ctx, svc, svcCfg, r.secretMan, r.upstream)
		if err != nil {
			return nil, nil, err
		}

		switch mode {
		case transportModeH2:
			rt := newUpstreamTransportH2(tlsCfg, isTLS)
			return rt, rt.CloseIdleConnections, nil

		case transportModeHTTP2TLS:
			rt := newUpstreamTransportHTTP1(tlsCfg)
			t2, err := http2.ConfigureTransports(rt)
			if err != nil {
				return nil, nil, err
			}
			t2.IdleConnTimeout = upstreamIdleConnTimeout
			t2.ReadIdleTimeout = 0
			t2.PingTimeout = 0

			return rt, rt.CloseIdleConnections, nil

		default:
			rt := newUpstreamTransportHTTP1(tlsCfg)
			return rt, rt.CloseIdleConnections, nil
		}
	})
}

func getTransportMode(req *http.Request,
	svc *corev1.Service, svcCfg *corev1.Service_Spec_Config) transportMode {

	if !isHTTP2RequestUpstream(req, svc, svcCfg) {
		return transportModeHTTP1
	}

	if isUpstreamH2(svc, svcCfg) {
		return transportModeH2
	}

	return transportModeHTTP2TLS
}

func isHTTP2RequestUpstream(req *http.Request,
	svc *corev1.Service, svcCfg *corev1.Service_Spec_Config) bool {

	if httpguts.HeaderValuesContainsToken(req.Header["Connection"], "Upgrade") {
		return false
	}

	return ucorev1.ToService(svc).IsUpstreamHTTP2ByConfig(svcCfg)
}

func isUpstreamH2(svc *corev1.Service, svcCfg *corev1.Service_Spec_Config) bool {
	s := ucorev1.ToService(svc)

	if s.IsGRPC() {
		return true
	}

	switch s.BackendSchemeByConfig(svcCfg) {
	case "grpc", "h2c":
		return true
	default:
		return false
	}
}

func (r *roundTripper) getTransportKey(
	svc *corev1.Service,
	svcCfg *corev1.Service_Spec_Config,
	mode transportMode,
	isTLS bool) (string, error) {
	cfgHash, err := r.transports.cfgHasher.get(svcCfg)
	if err != nil {
		return "", errors.Errorf("Could not fingerprint the Service config: %+v", err)
	}

	h := sha256.New()

	fmt.Fprintf(h, "svc=%s;", svc.Metadata.Uid)
	fmt.Fprintf(h, "mode=%s;tls=%t;", mode.String(), isTLS)

	if r.upstream != nil {
		fmt.Fprintf(h, "isUser=%t;host=%s;", r.upstream.IsUser, r.upstream.HostPort)
		if r.upstream.URL != nil {
			fmt.Fprintf(h, "upScheme=%s;upHost=%s;", strings.ToLower(r.upstream.URL.Scheme), r.upstream.URL.Host)
		}

		if r.upstream.SessionRef != nil {
			fmt.Fprintf(h, "session=%s;", r.upstream.SessionRef.Uid)
		}
	}

	fmt.Fprintf(h, "cfg=%s;", cfgHash)

	return hex.EncodeToString(h.Sum(nil)), nil
}

func newUpstreamDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   upstreamDialTimeout,
		KeepAlive: upstreamDialKeepAlive,
	}
}

func newUpstreamTransportHTTP1(tlsCfg *tls.Config) *http.Transport {

	dialer := newUpstreamDialer()

	if tlsCfg != nil {
		tlsCfg = tlsCfg.Clone()
	}

	return &http.Transport{
		TLSClientConfig: tlsCfg,

		Proxy: http.ProxyFromEnvironment,

		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},

		IdleConnTimeout:       upstreamIdleConnTimeout,
		TLSHandshakeTimeout:   upstreamTLSHandshakeTimeout,
		ExpectContinueTimeout: 1 * time.Second,

		MaxIdleConns:        upstreamMaxIdleConns,
		MaxIdleConnsPerHost: upstreamMaxIdleConnsPerHost,

		MaxConnsPerHost: 0,

		ResponseHeaderTimeout: 0,

		ReadBufferSize:  upstreamReadBufferSize,
		WriteBufferSize: upstreamWriteBufferSize,
	}
}

func newUpstreamTransportH2(tlsCfg *tls.Config, isTLS bool) *http2.Transport {

	dialer := newUpstreamDialer()

	if tlsCfg != nil {
		tlsCfg = tlsCfg.Clone()
	}

	return &http2.Transport{
		TLSClientConfig: tlsCfg,
		AllowHTTP:       !isTLS,

		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			if !isTLS {
				return dialer.DialContext(ctx, network, addr)
			}

			return (&tls.Dialer{
				NetDialer: dialer,
				Config:    cfg,
			}).DialContext(ctx, network, addr)
		},

		IdleConnTimeout: upstreamIdleConnTimeout,
		ReadIdleTimeout: 0,
		PingTimeout:     0,

		StrictMaxConcurrentStreams: false,
	}
}
