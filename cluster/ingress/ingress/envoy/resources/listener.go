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

package resources

import (
	"fmt"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	grpcweb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_web/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoyhcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	wellknown "github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	brotlicompr "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/brotli/compressor/v3"
	gzipcompr "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/gzip/compressor/v3"
	zstdcompr "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/zstd/compressor/v3"
	compressv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/compressor/v3"

	corsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	tls_inspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
)

func GetListeners(domain string, svcList []*corev1.Service, crtList []*corev1.Secret) ([]types.Resource, error) {
	ret := []types.Resource{}

	mainListener, err := getListener(domain, svcList, crtList)
	if err != nil {
		return nil, err
	}

	ret = append(ret, mainListener)

	healthCheckListener, err := getListenerHealthCheck()
	if err != nil {
		return nil, err
	}

	ret = append(ret, healthCheckListener)

	return ret, nil
}

func getListener(domain string, svcList []*corev1.Service,
	crtList []*corev1.Secret) (*listenerv3.Listener, error) {

	ret := &listenerv3.Listener{
		Name: "https-listener",
	}

	tlsInspectorFilter, err := getTLSInspector()
	if err != nil {
		return nil, err
	}

	ret.ListenerFilters = append(ret.ListenerFilters, tlsInspectorFilter)

	ret.Address = &core.Address{Address: &core.Address_SocketAddress{
		SocketAddress: &core.SocketAddress{
			Address:  "0.0.0.0",
			Protocol: core.SocketAddress_TCP,
			PortSpecifier: &core.SocketAddress_PortValue{
				PortValue: 8080,
			},
		},
	}}

	filterChain, err := getFilterChainsMain(domain, crtList, svcList)
	if err != nil {
		return nil, err
	}
	ret.FilterChains = append(ret.FilterChains, filterChain)

	return ret, nil
}

func getTLSInspector() (*listenerv3.ListenerFilter, error) {
	filter := &tls_inspector.TlsInspector{}

	toPB, err := anypb.New(filter)
	if err != nil {
		return nil, err
	}

	return &listenerv3.ListenerFilter{
		Name: "envoy.filters.listener.tls_inspector",
		ConfigType: &listenerv3.ListenerFilter_TypedConfig{
			TypedConfig: toPB,
		},
	}, nil
}

func getFilterChainsMain(domain string, crtList []*corev1.Secret, svcList []*corev1.Service) (*listenerv3.FilterChain, error) {

	ret := &listenerv3.FilterChain{
		FilterChainMatch: &listenerv3.FilterChainMatch{
			ServerNames: []string{domain, fmt.Sprintf("*.%s", domain)},
		},

		TransportSocketConnectTimeout: &durationpb.Duration{
			Seconds: 5,
		},
	}

	ts, err := getListenerTransportSocket(crtList, []string{"h2", "http/1.1"})
	if err != nil {
		return nil, err
	}
	ret.TransportSocket = ts

	httpConnMan, err := getHttpConnManagerFilterMain(domain, svcList)
	if err != nil {
		return nil, err
	}
	ret.Filters = append(ret.Filters, httpConnMan)

	return ret, nil

}

func getListenerTransportSocket(crtList []*corev1.Secret, alpnProtocols []string) (*core.TransportSocket, error) {

	tlsContext := &tlsv3.DownstreamTlsContext{
		RequireSni: &wrapperspb.BoolValue{
			Value: true,
		},

		CommonTlsContext: &tlsv3.CommonTlsContext{
			AlpnProtocols: alpnProtocols,
			TlsParams: &tlsv3.TlsParameters{
				TlsMinimumProtocolVersion: tlsv3.TlsParameters_TLSv1_2,
				TlsMaximumProtocolVersion: tlsv3.TlsParameters_TLSv1_3,
				CipherSuites: []string{
					"[ECDHE-ECDSA-AES128-GCM-SHA256|ECDHE-ECDSA-CHACHA20-POLY1305]",
					"[ECDHE-RSA-AES128-GCM-SHA256|ECDHE-RSA-CHACHA20-POLY1305]",
					"ECDHE-ECDSA-AES256-GCM-SHA384",
					"ECDHE-RSA-AES256-GCM-SHA384",
				},
			},
		},
	}

	for _, crt := range crtList {
		if !vutils.IsCertReady(crt) {
			zap.L().Debug("Skipping the cert since it is not ready",
				zap.String("name", crt.Metadata.Name))
			continue
		}

		zap.L().Debug("Adding certificate for Secret", zap.String("name", crt.Metadata.Name))

		chain, key, err := ucorev1.ToSecret(crt).GetCertificateChainAndKey()
		if err != nil {
			zap.L().Error("Could not find cert data. Skipping...",
				zap.Error(err), zap.String("name", crt.Metadata.Name))
			continue
		}

		tlsContext.CommonTlsContext.TlsCertificates = append(tlsContext.CommonTlsContext.TlsCertificates,
			&tlsv3.TlsCertificate{
				CertificateChain: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: []byte(chain),
					},
				},
				PrivateKey: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: []byte(key),
					},
				},
			})
	}

	if len(tlsContext.CommonTlsContext.TlsCertificates) == 0 {
		return nil, nil
	}

	toPB, err := anypb.New(tlsContext)
	if err != nil {
		return nil, err
	}

	return &core.TransportSocket{
		Name: "envoy.transport_sockets.tls",
		ConfigType: &core.TransportSocket_TypedConfig{
			TypedConfig: toPB,
		},
	}, nil
}

func getHttpConnManagerFilterMain(domain string, svcList []*corev1.Service) (*listenerv3.Filter, error) {

	routeConfig, err := getRouteConfigMain(domain, svcList)
	if err != nil {
		return nil, err
	}

	filter := &envoyhcm.HttpConnectionManager{
		CodecType:             envoyhcm.HttpConnectionManager_AUTO,
		StatPrefix:            "hcm-main",
		ServerName:            "octelium",
		StripMatchingHostPort: true,
		RouteSpecifier: &envoyhcm.HttpConnectionManager_RouteConfig{
			RouteConfig: routeConfig,
		},

		// TODO: This value might need to be changed in the future
		StreamIdleTimeout: &durationpb.Duration{
			Seconds: idleTimeoutSeconds,
			Nanos:   0,
		},
		RequestTimeout: &durationpb.Duration{
			Seconds: 0,
			Nanos:   0,
		},

		RequestHeadersTimeout: &durationpb.Duration{
			Seconds: 5,
			Nanos:   0,
		},

		UseRemoteAddress: &wrapperspb.BoolValue{
			Value: true,
		},

		Http2ProtocolOptions: &core.Http2ProtocolOptions{
			ConnectionKeepalive: &core.KeepaliveSettings{
				Interval: &durationpb.Duration{
					Seconds: 30,
				},
				Timeout: &durationpb.Duration{
					Seconds: 10,
				},
			},
		},
	}

	filter.UpgradeConfigs = []*envoyhcm.HttpConnectionManager_UpgradeConfig{
		{
			UpgradeType: "websocket",
		},
	}

	httpFilters, err := getHttpFiltersMain()
	if err != nil {
		return nil, err
	}

	filter.HttpFilters = httpFilters

	pbFilter, err := anypb.New(filter)
	if err != nil {
		return nil, err
	}

	return &listenerv3.Filter{
		Name: wellknown.HTTPConnectionManager,
		ConfigType: &listenerv3.Filter_TypedConfig{
			TypedConfig: pbFilter,
		},
	}, nil
}

func getHttpFiltersMain() ([]*envoyhcm.HttpFilter, error) {
	filters := []*envoyhcm.HttpFilter{}

	{
		zstdFilter := &zstdcompr.Zstd{}

		zstdPbFilter, err := anypb.New(zstdFilter)
		if err != nil {
			return nil, err
		}

		compressorFilter := &compressv3.Compressor{
			CompressorLibrary: &core.TypedExtensionConfig{
				Name:        "zstd-compressor",
				TypedConfig: zstdPbFilter,
			},
		}

		pbFilter, err := anypb.New(compressorFilter)
		if err != nil {
			return nil, err
		}

		filters = append(filters, &envoyhcm.HttpFilter{
			Name: "envoy.filters.http.compressor",
			ConfigType: &envoyhcm.HttpFilter_TypedConfig{
				TypedConfig: pbFilter,
			},
		})
	}

	{
		brotliFilter := &brotlicompr.Brotli{}

		brotliPbFilter, err := anypb.New(brotliFilter)
		if err != nil {
			return nil, err
		}

		compressorFilter := &compressv3.Compressor{
			CompressorLibrary: &core.TypedExtensionConfig{
				Name:        "brotli-compressor",
				TypedConfig: brotliPbFilter,
			},
		}

		pbFilter, err := anypb.New(compressorFilter)
		if err != nil {
			return nil, err
		}

		filters = append(filters, &envoyhcm.HttpFilter{
			Name: "envoy.filters.http.compressor",
			ConfigType: &envoyhcm.HttpFilter_TypedConfig{
				TypedConfig: pbFilter,
			},
		})
	}

	{
		gzipFilter := &gzipcompr.Gzip{
			MemoryLevel: &wrapperspb.UInt32Value{
				Value: 5,
			},
			CompressionLevel:    gzipcompr.Gzip_BEST_SPEED,
			CompressionStrategy: gzipcompr.Gzip_DEFAULT_STRATEGY,
		}

		gzippbFilter, err := anypb.New(gzipFilter)
		if err != nil {
			return nil, err
		}

		compressorFilter := &compressv3.Compressor{
			CompressorLibrary: &core.TypedExtensionConfig{
				Name:        "gzip-compressor",
				TypedConfig: gzippbFilter,
			},
		}

		pbFilter, err := anypb.New(compressorFilter)
		if err != nil {
			return nil, err
		}

		filters = append(filters, &envoyhcm.HttpFilter{
			Name: "envoy.filters.http.compressor",
			ConfigType: &envoyhcm.HttpFilter_TypedConfig{
				TypedConfig: pbFilter,
			},
		})
	}
	{
		filter := &corsv3.Cors{}
		pbFilter, err := anypb.New(filter)
		if err != nil {
			return nil, err
		}
		filters = append(filters, &envoyhcm.HttpFilter{
			Name: "envoy.filters.http.cors",
			ConfigType: &envoyhcm.HttpFilter_TypedConfig{
				TypedConfig: pbFilter,
			},
		})
	}

	{
		filter := &grpcweb.GrpcWeb{}
		pbFilter, err := anypb.New(filter)
		if err != nil {
			return nil, err
		}
		filters = append(filters, &envoyhcm.HttpFilter{
			Name: "envoy.filters.http.grpc_web",
			ConfigType: &envoyhcm.HttpFilter_TypedConfig{
				TypedConfig: pbFilter,
			},
		})
	}

	{
		// Router filter must be last filter
		routerFilter := &routerv3.Router{
			SuppressEnvoyHeaders: true,
		}
		pbFilter, err := anypb.New(routerFilter)
		if err != nil {
			return nil, err
		}
		filters = append(filters, &envoyhcm.HttpFilter{
			Name: "envoy.filters.http.router",
			ConfigType: &envoyhcm.HttpFilter_TypedConfig{

				TypedConfig: pbFilter,
			},
		})
	}

	return filters, nil
}

// TODO: Non-zero values simply breaks streaming (e.g. gRPC API streaming-based methods)
const idleTimeoutSeconds = 0
