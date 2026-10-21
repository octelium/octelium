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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	gzipcompr "github.com/envoyproxy/go-control-plane/envoy/extensions/compression/gzip/compressor/v3"
	compressv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/compressor/v3"
	routerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoyhcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	utils_cert "github.com/octelium/octelium/pkg/utils/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestGetListeners(t *testing.T) {

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
	usr := tests.GenUser(nil)

	doCreateSvc := func() *corev1.Service {
		svc := tests.GenService("default")
		svc.Spec.IsPublic = true
		svc.Spec.Mode = corev1.Service_Spec_HTTP
		svc, err = adminSrv.CreateService(ctx, svc)
		assert.Nil(t, err, "%+v", err)
		ret, err := fakeC.OcteliumC.CoreC().GetService(ctx, &rmetav1.GetOptions{Uid: svc.Metadata.Uid})
		assert.Nil(t, err)
		return ret
	}

	usr, err = adminSrv.CreateUser(ctx, usr)
	assert.Nil(t, err)

	cc, err := adminSrv.GetClusterConfig(ctx, &corev1.GetClusterConfigRequest{})
	assert.Nil(t, err)

	_, err = GetListeners(ctx, &GetListenersReq{
		Domain:        "example.com",
		ClusterConfig: cc,
	})
	assert.Nil(t, err)
	_, err = GetListeners(ctx, &GetListenersReq{
		Domain:        "example.com",
		ClusterConfig: cc,
	})
	assert.Nil(t, err)

	var svcList []*corev1.Service
	for i := 0; i < 100; i++ {
		svcList = append(svcList, doCreateSvc())
	}

	_, err = GetListeners(ctx, &GetListenersReq{
		Domain:        "example.com",
		ClusterConfig: cc,
		ServiceList:   svcList,
	})
	assert.Nil(t, err)
	_, err = GetListeners(ctx, &GetListenersReq{
		Domain:        "example.com",
		ClusterConfig: cc,
		ServiceList:   svcList,
	})
	assert.Nil(t, err)

	doCreateCrt := func(name string) *corev1.Secret {
		ca, err := utils_cert.GenerateCARoot()
		crtPEM, err := ca.GetCertPEM()
		assert.Nil(t, err)
		crtPrivatePEM, err := ca.GetPrivateKeyPEM()
		assert.Nil(t, err)

		crt := &corev1.Secret{
			Metadata: &metav1.Metadata{
				Name: name,
			},
			Spec:   &corev1.Secret_Spec{},
			Status: &corev1.Secret_Status{},
		}

		ucorev1.ToSecret(crt).SetCertificate(crtPEM, crtPrivatePEM)

		ret, err := fakeC.OcteliumC.CoreC().CreateSecret(ctx, crt)
		assert.Nil(t, err)
		return ret
	}

	cc.Spec.Ingress = &corev1.ClusterConfig_Spec_Ingress{
		UseForwardedForHeader: true,
		XffNumTrustedHops:     1,
	}

	_, err = GetListeners(ctx, &GetListenersReq{
		Domain:        "example.com",
		ClusterConfig: cc,
		ServiceList:   svcList,
	})
	assert.Nil(t, err)
	listeners, err := GetListeners(ctx, &GetListenersReq{
		Domain:        "example.com",
		ClusterConfig: cc,
		ServiceList:   svcList,
		CertList: []*corev1.Secret{
			doCreateCrt("cluster"),
		},
	})

	for _, lis := range listeners {
		zap.L().Debug("Listener", zap.Any("lis", pbutils.MustConvertToMap(lis)))
	}
	assert.Nil(t, err)
}

func TestEnvoyResourceValidation(t *testing.T) {
	binary := os.Getenv("OCTELIUM_TEST_ENVOY_PATH")
	if binary == "" {
		var err error
		binary, err = exec.LookPath("envoy")
		if err != nil {
			t.Skip("Envoy is not installed")
		}
	}
	crt := newIngressCertificate(t, "cluster")
	var services []*corev1.Service
	for _, mode := range []corev1.Service_Spec_Mode{
		corev1.Service_Spec_HTTP, corev1.Service_Spec_GRPC, corev1.Service_Spec_WEB,
		corev1.Service_Spec_MCP, corev1.Service_Spec_LLM,
	} {
		svc := newIngressService(strings.ToLower(mode.String()), "default")
		svc.Spec.Mode = mode
		svc.Spec.IsTLS = true
		services = append(services, svc)
	}
	services = append(services, newAPIServerService("default.octelium-api", "/octelium.api.main.user, /octelium.api.main.core"))
	for _, frontProxy := range []bool{false, true} {
		for _, empty := range []bool{false, true} {
			t.Run(fmt.Sprintf("FrontProxy/%t/Empty/%t", frontProxy, empty), func(t *testing.T) {
				list := services
				if empty {
					list = nil
				}
				listeners, err := GetListeners(t.Context(), &GetListenersReq{
					Domain: "example.com", ClusterConfig: &corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{}},
					ServiceList: list, CertList: []*corev1.Secret{crt}, HasFrontProxy: frontProxy,
				})
				require.Nil(t, err)
				clusters, err := GetClusters("example.com", list)
				require.Nil(t, err)
				cfg := &bootstrapv3.Bootstrap{StaticResources: &bootstrapv3.Bootstrap_StaticResources{}}
				for _, item := range listeners {
					cfg.StaticResources.Listeners = append(cfg.StaticResources.Listeners, item.(*listenerv3.Listener))
				}
				for _, item := range clusters {
					cfg.StaticResources.Clusters = append(cfg.StaticResources.Clusters, item.(*clusterv3.Cluster))
				}
				data, err := protojson.Marshal(cfg)
				require.Nil(t, err)
				file := filepath.Join(t.TempDir(), "envoy.json")
				require.Nil(t, os.WriteFile(file, data, 0600))
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				output, err := exec.CommandContext(ctx, binary, "--mode", "validate", "--disable-hot-restart", "-l", "warning", "-c", file).CombinedOutput()
				assert.Nil(t, err, "%s", output)
				assert.NotContains(t, strings.ToLower(string(output)), "deprecated", "%s", output)
			})
		}
	}
}

func newIngressCertificate(t *testing.T, name string) *corev1.Secret {
	t.Helper()
	ca, err := utils_cert.GenerateSelfSignedCert("example.com", []string{"example.com", "*.example.com"}, time.Hour)
	require.Nil(t, err)
	chain, err := ca.GetCertPEM()
	require.Nil(t, err)
	key, err := ca.GetPrivateKeyPEM()
	require.Nil(t, err)
	ret := &corev1.Secret{Metadata: &metav1.Metadata{Name: name}}
	ucorev1.ToSecret(ret).SetCertificate(chain, key)
	return ret
}

func TestGetListenersModes(t *testing.T) {
	crt := newIngressCertificate(t, "cluster")
	for _, frontProxy := range []bool{false, true} {
		t.Run(fmt.Sprint(frontProxy), func(t *testing.T) {
			rscs, err := GetListeners(t.Context(), &GetListenersReq{
				Domain: "example.com", HasFrontProxy: frontProxy,
				ClusterConfig: &corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{}},
				CertList:      []*corev1.Secret{crt},
				ServiceList:   []*corev1.Service{newIngressService("app", "default")},
			})
			require.Nil(t, err)
			require.Len(t, rscs, 2)
			main := rscs[0].(*listenerv3.Listener)
			assert.Nil(t, main.ValidateAll())
			assert.Equal(t, "main-listener", main.Name)
			assert.Equal(t, "0.0.0.0", main.Address.GetSocketAddress().Address)
			assert.Equal(t, uint32(8080), main.Address.GetSocketAddress().GetPortValue())
			require.Len(t, main.ListenerFilters, 1)
			_, err = main.ListenerFilters[0].GetTypedConfig().UnmarshalNew()
			assert.Nil(t, err)
			require.Len(t, main.FilterChains, 1)
			chain := main.FilterChains[0]
			assert.Equal(t, int64(5), chain.TransportSocketConnectTimeout.Seconds)
			require.Len(t, chain.Filters, 1)
			var hcm envoyhcm.HttpConnectionManager
			require.Nil(t, chain.Filters[0].GetTypedConfig().UnmarshalTo(&hcm))
			require.Len(t, hcm.GetRouteConfig().VirtualHosts, 1)
			if frontProxy {
				assert.Equal(t, "envoy.filters.listener.http_inspector", main.ListenerFilters[0].Name)
				assert.Empty(t, chain.FilterChainMatch.ServerNames)
				assert.Nil(t, chain.TransportSocket)
				assert.Zero(t, hcm.GetRouteConfig().VirtualHosts[0].RequireTls)
			} else {
				assert.Equal(t, "envoy.filters.listener.tls_inspector", main.ListenerFilters[0].Name)
				assert.Equal(t, []string{"example.com", "*.example.com"}, chain.FilterChainMatch.ServerNames)
				assert.NotNil(t, chain.TransportSocket)
				assert.NotZero(t, hcm.GetRouteConfig().VirtualHosts[0].RequireTls)
			}
			health := rscs[1].(*listenerv3.Listener)
			assert.Nil(t, health.ValidateAll())
			assert.Equal(t, "healthcheck-listener", health.Name)
			assert.Equal(t, uint32(11012), health.Address.GetSocketAddress().GetPortValue())
			assert.Empty(t, health.ListenerFilters)
			assert.Nil(t, health.FilterChains[0].TransportSocket)
		})
	}
}

func TestGetListenerCertificates(t *testing.T) {
	valid := newIngressCertificate(t, "valid")
	second := newIngressCertificate(t, "second")
	for _, tc := range []struct {
		name string
		list []*corev1.Secret
		want []*corev1.Secret
	}{
		{"Empty", nil, nil},
		{"MissingData", []*corev1.Secret{{Metadata: &metav1.Metadata{Name: "missing"}}}, nil},
		{"MalformedChain", []*corev1.Secret{{Metadata: &metav1.Metadata{Name: "invalid"}, Spec: &corev1.Secret_Spec{Data: &corev1.Secret_Spec_Data{Type: &corev1.Secret_Spec_Data_Value{Value: "not a certificate"}}}, Data: valid.Data}}, nil},
		{"MalformedKey", []*corev1.Secret{{Metadata: &metav1.Metadata{Name: "invalid"}, Spec: valid.Spec, Data: &corev1.Secret_Data{Type: &corev1.Secret_Data_Value{Value: "not a key"}}}}, nil},
		{"Valid", []*corev1.Secret{valid}, []*corev1.Secret{valid}},
		{"Mixed", []*corev1.Secret{{Metadata: &metav1.Metadata{Name: "missing"}}, valid, second}, []*corev1.Secret{valid, second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts, err := getListenerTransportSocket(tc.list, []string{"h2", "http/1.1"})
			require.Nil(t, err)
			if len(tc.want) == 0 {
				assert.Nil(t, ts)
				return
			}
			require.NotNil(t, ts)
			assert.Equal(t, "envoy.transport_sockets.tls", ts.Name)
			var cfg tlsv3.DownstreamTlsContext
			require.Nil(t, ts.GetTypedConfig().UnmarshalTo(&cfg))
			assert.Nil(t, cfg.ValidateAll())
			assert.Equal(t, []string{"h2", "http/1.1"}, cfg.CommonTlsContext.AlpnProtocols)
			assert.Equal(t, tlsv3.TlsParameters_TLSv1_2, cfg.CommonTlsContext.TlsParams.TlsMinimumProtocolVersion)
			assert.Equal(t, tlsv3.TlsParameters_TLSv1_3, cfg.CommonTlsContext.TlsParams.TlsMaximumProtocolVersion)
			assert.Len(t, cfg.CommonTlsContext.TlsParams.CipherSuites, 6)
			require.Len(t, cfg.CommonTlsContext.TlsCertificates, len(tc.want))
			for i, secret := range tc.want {
				chain, key, err := ucorev1.ToSecret(secret).GetCertificateChainAndKey()
				require.Nil(t, err)
				assert.Equal(t, chain, cfg.CommonTlsContext.TlsCertificates[i].CertificateChain.GetInlineBytes())
				assert.Equal(t, key, cfg.CommonTlsContext.TlsCertificates[i].PrivateKey.GetInlineBytes())
			}
		})
	}
}

func TestGetHttpConnManagerSettings(t *testing.T) {
	for _, hops := range []int32{-1, 0, 1, 11} {
		t.Run(fmt.Sprint(hops), func(t *testing.T) {
			cc := &corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{}}
			if hops != -1 {
				cc.Spec.Ingress = &corev1.ClusterConfig_Spec_Ingress{XffNumTrustedHops: hops}
			}
			filter, err := getHttpConnManagerFilterMain(t.Context(), &GetListenersReq{
				Domain: "example.com", ClusterConfig: cc,
			})
			require.Nil(t, err)
			var cfg envoyhcm.HttpConnectionManager
			require.Nil(t, filter.GetTypedConfig().UnmarshalTo(&cfg))
			assert.Nil(t, cfg.ValidateAll())
			assert.Equal(t, envoyhcm.HttpConnectionManager_AUTO, cfg.CodecType)
			assert.Equal(t, "octelium", cfg.ServerName)
			assert.True(t, cfg.GetStripAnyHostPort())
			assert.True(t, cfg.UseRemoteAddress.GetValue())
			if hops > 0 && hops < 12 {
				assert.Equal(t, uint32(hops), cfg.XffNumTrustedHops)
			} else {
				assert.Zero(t, cfg.XffNumTrustedHops)
			}
			assert.Equal(t, uint32(32), cfg.MaxRequestHeadersKb.GetValue())
			assert.Equal(t, int64(3600), cfg.StreamIdleTimeout.Seconds)
			require.NotNil(t, cfg.RequestTimeout)
			assert.Zero(t, cfg.RequestTimeout.Seconds)
			assert.Equal(t, int64(5), cfg.RequestHeadersTimeout.Seconds)
			assert.Equal(t, int64(30), cfg.Http2ProtocolOptions.ConnectionKeepalive.Interval.Seconds)
			assert.Equal(t, int64(10), cfg.Http2ProtocolOptions.ConnectionKeepalive.Timeout.Seconds)
			require.Len(t, cfg.UpgradeConfigs, 1)
			assert.Equal(t, "websocket", cfg.UpgradeConfigs[0].UpgradeType)
		})
	}
}

func TestGetHttpFiltersMainConfiguration(t *testing.T) {
	filters, err := getHttpFiltersMain()
	require.Nil(t, err)
	require.Len(t, filters, 4)
	assert.Equal(t, []string{"envoy.filters.http.compressor", "envoy.filters.http.cors", "envoy.filters.http.grpc_web", "envoy.filters.http.router"},
		[]string{filters[0].Name, filters[1].Name, filters[2].Name, filters[3].Name})
	for _, filter := range filters {
		assert.Nil(t, filter.ValidateAll())
		_, err := filter.GetTypedConfig().UnmarshalNew()
		assert.Nil(t, err)
	}
	var compressor compressv3.Compressor
	require.Nil(t, filters[0].GetTypedConfig().UnmarshalTo(&compressor))
	assert.Nil(t, compressor.ValidateAll())
	assert.Empty(t, compressor.ContentType)
	assert.Nil(t, compressor.RequestDirectionConfig)
	response := compressor.ResponseDirectionConfig
	require.NotNil(t, response)
	assert.True(t, response.DisableOnEtagHeader)
	assert.True(t, response.RemoveAcceptEncodingHeader)
	assert.Equal(t, uint32(1024), response.CommonConfig.MinContentLength.GetValue())
	assert.Empty(t, response.CommonConfig.ContentType)
	var contentTypes []string
	for _, matcher := range response.CommonConfig.ContentTypeMatcher {
		assert.True(t, matcher.IgnoreCase)
		contentTypes = append(contentTypes, matcher.GetExact())
	}
	assert.Equal(t, []string{"application/xml", "application/xhtml+xml", "application/javascript", "application/x-javascript", "text/javascript", "text/html", "text/css", "text/plain", "text/xml"}, contentTypes)
	var gzip gzipcompr.Gzip
	require.Nil(t, compressor.CompressorLibrary.TypedConfig.UnmarshalTo(&gzip))
	assert.Nil(t, gzip.ValidateAll())
	assert.Equal(t, uint32(5), gzip.MemoryLevel.GetValue())
	assert.Equal(t, gzipcompr.Gzip_BEST_SPEED, gzip.CompressionLevel)
	var router routerv3.Router
	require.Nil(t, filters[3].GetTypedConfig().UnmarshalTo(&router))
	assert.True(t, router.SuppressEnvoyHeaders)
}

func TestGetHealthCheckConfiguration(t *testing.T) {
	listener, err := getListenerHealthCheck()
	require.Nil(t, err)
	require.Len(t, listener.FilterChains, 1)
	chain := listener.FilterChains[0]
	assert.Equal(t, int64(3), chain.TransportSocketConnectTimeout.Seconds)
	require.Len(t, chain.Filters, 1)
	var cfg envoyhcm.HttpConnectionManager
	require.Nil(t, chain.Filters[0].GetTypedConfig().UnmarshalTo(&cfg))
	assert.Nil(t, cfg.ValidateAll())
	assert.Equal(t, "octelium", cfg.ServerName)
	assert.Equal(t, int64(30), cfg.StreamIdleTimeout.Seconds)
	assert.Equal(t, int64(5), cfg.RequestTimeout.Seconds)
	assert.Equal(t, int64(3), cfg.RequestHeadersTimeout.Seconds)
	require.Len(t, cfg.HttpFilters, 1)
	assert.Equal(t, "envoy.filters.http.router", cfg.HttpFilters[0].Name)
	require.Len(t, cfg.GetRouteConfig().VirtualHosts, 1)
	vh := cfg.GetRouteConfig().VirtualHosts[0]
	assert.Equal(t, []string{"*"}, vh.Domains)
	require.Len(t, vh.Routes, 1)
	assert.Equal(t, "/ready", vh.Routes[0].Match.GetPath())
	assert.Equal(t, "127.0.0.1", vh.Routes[0].GetRoute().GetHostRewriteLiteral())
	assert.Equal(t, healthCheckCluster, vh.Routes[0].GetRoute().GetCluster())
}

func TestGetListenersInvalidDomain(t *testing.T) {
	for _, api := range []bool{false, true} {
		svc := newIngressService("app", "default")
		if api {
			svc = newAPIServerService("default.octelium-api", "/octelium.api.main.user")
		}
		rscs, err := GetListeners(t.Context(), &GetListenersReq{
			Domain: "\xff.example.com", ServiceList: []*corev1.Service{svc},
			ClusterConfig: &corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{}},
		})
		assert.NotNil(t, err)
		assert.Nil(t, rscs)
	}
}
