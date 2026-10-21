package envoy_test

import (
	"context"
	"fmt"
	"net"
	"path"
	"sync"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoyhcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	clusterservice "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	listenerservice "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/rsc/rcorev1"
	"github.com/octelium/octelium/apis/rsc/rmetav1"
	"github.com/octelium/octelium/cluster/common/octeliumc"
	"github.com/octelium/octelium/cluster/common/urscsrv"
	certcontroller "github.com/octelium/octelium/cluster/ingress/ingress/controllers/certificates"
	svccontroller "github.com/octelium/octelium/cluster/ingress/ingress/controllers/services"
	"github.com/octelium/octelium/cluster/ingress/ingress/envoy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type tstIngressBackend struct {
	grpc.ClientConnInterface
	sync.Mutex
	calls    map[string][]proto.Message
	fail     string
	services []*corev1.Service
	secrets  []*corev1.Secret
}

func (b *tstIngressBackend) Invoke(ctx context.Context, method string, req, resp any, opts ...grpc.CallOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.Lock()
	defer b.Unlock()
	method = path.Base(method)
	if b.calls == nil {
		b.calls = make(map[string][]proto.Message)
	}
	b.calls[method] = append(b.calls[method], proto.Clone(req.(proto.Message)))
	if method == b.fail {
		return status.Error(codes.Unavailable, "backend unavailable")
	}
	var data proto.Message
	switch method {
	case "GetRegion":
		data = &corev1.Region{Metadata: &metav1.Metadata{Name: "region", Uid: "region-uid"}}
	case "ListService":
		data = &corev1.ServiceList{Items: b.services}
	case "ListSecret":
		data = &corev1.SecretList{Items: b.secrets}
	case "GetClusterConfig":
		data = &corev1.ClusterConfig{Spec: &corev1.ClusterConfig_Spec{}}
	default:
		return status.Error(codes.Unimplemented, method)
	}
	proto.Merge(resp.(proto.Message), data)
	return nil
}

func (b *tstIngressBackend) count(method string) int {
	b.Lock()
	defer b.Unlock()
	return len(b.calls[method])
}

type tstIngressClient struct {
	octeliumc.ClientInterface
	coreC rcorev1.ResourceServiceClient
}

func (c *tstIngressClient) CoreC() rcorev1.ResourceServiceClient { return c.coreC }

func (c *tstIngressClient) CoreV1Utils() octeliumc.CoreV1Utils { return c }

func (c *tstIngressClient) GetClusterConfig(ctx context.Context) (*corev1.ClusterConfig, error) {
	return c.coreC.GetClusterConfig(ctx, &rmetav1.GetOptions{Name: "default"})
}

func newIngressServer(t *testing.T, b *tstIngressBackend, o *envoy.Opts) (*envoy.Server, *grpc.ClientConn) {
	t.Helper()
	t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "false")
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	t.Setenv("OCTELIUM_REGION_NAME", "region")
	ctx, cancel := context.WithCancel(t.Context())
	c := &tstIngressClient{coreC: rcorev1.NewResourceServiceClient(b)}
	s, err := envoy.NewServer(ctx, "example.com", c, o)
	require.Nil(t, err)
	conn, err := grpc.NewClient("localhost:8080", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.Nil(t, err)
	t.Cleanup(func() {
		cancel()
		assert.Nil(t, conn.Close())
		assert.Nil(t, s.Close())
	})
	return s, conn
}

func fetchIngress(t *testing.T, conn *grpc.ClientConn, typ string) *discovery.DiscoveryResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	resp, err := getIngress(ctx, conn, typ)
	require.Nil(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, typ, resp.TypeUrl)
	assert.Contains(t, resp.VersionInfo, "octelium-")
	return resp
}

func getIngress(ctx context.Context, conn *grpc.ClientConn, typ string) (*discovery.DiscoveryResponse, error) {
	req := &discovery.DiscoveryRequest{Node: &core.Node{Id: "octelium-ingress"}, TypeUrl: typ}
	var resp *discovery.DiscoveryResponse
	var err error
	switch typ {
	case resource.ClusterType:
		resp, err = clusterservice.NewClusterDiscoveryServiceClient(conn).FetchClusters(ctx, req)
	case resource.ListenerType:
		resp, err = listenerservice.NewListenerDiscoveryServiceClient(conn).FetchListeners(ctx, req)
	}
	return resp, err
}

func TestServerSnapshot(t *testing.T) {
	for _, frontProxy := range []bool{false, true} {
		t.Run(fmt.Sprint(frontProxy), func(t *testing.T) {
			svc := &corev1.Service{
				Metadata: &metav1.Metadata{Name: "app.default"},
				Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, IsPublic: true},
				Status:   &corev1.Service_Status{Port: 8080, NamespaceRef: &metav1.ObjectReference{Name: "default"}},
			}
			b := &tstIngressBackend{services: []*corev1.Service{svc}}
			s, conn := newIngressServer(t, b, &envoy.Opts{HasFrontProxy: frontProxy})
			require.Nil(t, s.Run(t.Context()))
			clusters := fetchIngress(t, conn, resource.ClusterType)
			listeners := fetchIngress(t, conn, resource.ListenerType)
			assert.Equal(t, clusters.VersionInfo, listeners.VersionInfo)
			require.Len(t, clusters.Resources, 2)
			require.Len(t, listeners.Resources, 2)
			var clstr clusterv3.Cluster
			for _, item := range clusters.Resources {
				require.Nil(t, item.UnmarshalTo(&clstr))
				assert.Nil(t, clstr.ValidateAll())
			}
			var listener listenerv3.Listener
			for _, item := range listeners.Resources {
				require.Nil(t, item.UnmarshalTo(&listener))
				assert.Nil(t, listener.ValidateAll())
				if listener.Name == "main-listener" {
					var hcm envoyhcm.HttpConnectionManager
					require.Nil(t, listener.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(&hcm))
					assert.Equal(t, frontProxy, hcm.GetRouteConfig().VirtualHosts[0].RequireTls == 0)
				}
			}
			b.Lock()
			assert.True(t, proto.Equal(&rmetav1.GetOptions{Name: "region"}, b.calls["GetRegion"][0]))
			assert.True(t, proto.Equal(&rmetav1.ListOptions{Filters: []*rmetav1.ListOptions_Filter{
				urscsrv.FilterFieldBooleanTrue("spec.isPublic"),
				urscsrv.FilterFieldEQValStr("status.regionRef.uid", "region-uid"),
			}}, b.calls["ListService"][0]))
			assert.True(t, proto.Equal(&rmetav1.ListOptions{SystemLabels: map[string]string{"octelium-cert": "true"}}, b.calls["ListSecret"][0]))
			assert.True(t, proto.Equal(&rmetav1.GetOptions{Name: "default"}, b.calls["GetClusterConfig"][0]))
			b.Unlock()
		})
	}
}

func TestServerSnapshotErrors(t *testing.T) {
	for _, method := range []string{"GetRegion", "ListService", "ListSecret", "GetClusterConfig"} {
		t.Run(method, func(t *testing.T) {
			b := &tstIngressBackend{fail: method}
			s, _ := newIngressServer(t, b, nil)
			assert.Equal(t, codes.Unavailable, status.Code(s.Run(t.Context())))
			assert.Equal(t, 1, b.count(method))
			passed := false
			for _, stage := range []string{"GetRegion", "ListService", "ListSecret", "GetClusterConfig"} {
				if passed {
					assert.Zero(t, b.count(stage))
				} else {
					assert.Equal(t, 1, b.count(stage))
				}
				passed = passed || stage == method
			}
		})
	}
}

func TestServerSnapshotFailurePreservesResources(t *testing.T) {
	b := &tstIngressBackend{}
	s, conn := newIngressServer(t, b, nil)
	require.Nil(t, s.Run(t.Context()))
	before := fetchIngress(t, conn, resource.ListenerType)
	b.Lock()
	b.fail = "ListSecret"
	b.Unlock()
	require.Nil(t, s.DoSnapshot(t.Context()))
	require.Eventually(t, func() bool { return b.count("ListSecret") == 2 }, 3*time.Second, 10*time.Millisecond)
	after := fetchIngress(t, conn, resource.ListenerType)
	assert.Equal(t, before.VersionInfo, after.VersionInfo)
	require.Len(t, after.Resources, len(before.Resources))
	for _, previous := range before.Resources {
		found := false
		for _, current := range after.Resources {
			found = found || proto.Equal(previous, current)
		}
		assert.True(t, found)
	}
	b.Lock()
	b.fail = ""
	b.Unlock()
	require.Nil(t, s.DoSnapshot(t.Context()))
	require.Eventually(t, func() bool { return b.count("GetClusterConfig") == 2 }, 3*time.Second, 10*time.Millisecond)
	after = fetchIngress(t, conn, resource.ListenerType)
	assert.NotEqual(t, before.VersionInfo, after.VersionInfo)
}

func TestServerSnapshotBurst(t *testing.T) {
	b := &tstIngressBackend{}
	s, conn := newIngressServer(t, b, nil)
	require.Nil(t, s.Run(t.Context()))
	before := fetchIngress(t, conn, resource.ClusterType)
	var wg sync.WaitGroup
	for range 1000 {
		wg.Go(func() { assert.Nil(t, s.DoSnapshot(t.Context())) })
	}
	wg.Wait()
	require.Eventually(t, func() bool { return b.count("GetClusterConfig") > 1 }, 3*time.Second, 10*time.Millisecond)
	after := fetchIngress(t, conn, resource.ClusterType)
	assert.NotEqual(t, before.VersionInfo, after.VersionInfo)
	assert.Less(t, b.count("GetClusterConfig"), 10)
}

func TestServerSnapshotServiceLifecycle(t *testing.T) {
	b := &tstIngressBackend{}
	s, conn := newIngressServer(t, b, &envoy.Opts{HasFrontProxy: true})
	require.Nil(t, s.Run(t.Context()))
	for _, count := range []int{1, 10, 0} {
		var services []*corev1.Service
		for i := range count {
			services = append(services, &corev1.Service{
				Metadata: &metav1.Metadata{Name: fmt.Sprintf("app%d.default", i)},
				Spec:     &corev1.Service_Spec{Mode: corev1.Service_Spec_HTTP, IsPublic: true},
				Status:   &corev1.Service_Status{Port: 8080, NamespaceRef: &metav1.ObjectReference{Name: "default"}},
			})
		}
		b.Lock()
		b.services = services
		b.Unlock()
		before := fetchIngress(t, conn, resource.ClusterType)
		require.Nil(t, s.DoSnapshot(t.Context()))
		require.Eventually(t, func() bool {
			resp, err := getIngress(t.Context(), conn, resource.ClusterType)
			return err == nil && resp.VersionInfo != before.VersionInfo
		}, 3*time.Second, 20*time.Millisecond)
		assert.Len(t, fetchIngress(t, conn, resource.ClusterType).Resources, count+1)
		listeners := fetchIngress(t, conn, resource.ListenerType)
		for _, item := range listeners.Resources {
			var listener listenerv3.Listener
			require.Nil(t, item.UnmarshalTo(&listener))
			if listener.Name == "main-listener" {
				var hcm envoyhcm.HttpConnectionManager
				require.Nil(t, listener.FilterChains[0].Filters[0].GetTypedConfig().UnmarshalTo(&hcm))
				assert.Len(t, hcm.GetRouteConfig().VirtualHosts, count)
			}
		}
	}
}

func TestServerDiscoveryStreams(t *testing.T) {
	b := &tstIngressBackend{}
	s, conn := newIngressServer(t, b, nil)
	require.Nil(t, s.Run(t.Context()))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := discovery.NewAggregatedDiscoveryServiceClient(conn).StreamAggregatedResources(ctx)
	require.Nil(t, err)
	require.Nil(t, stream.Send(&discovery.DiscoveryRequest{Node: &core.Node{Id: "octelium-ingress"}, TypeUrl: resource.ClusterType}))
	first, err := stream.Recv()
	require.Nil(t, err)
	require.Len(t, first.Resources, 1)
	require.NotEmpty(t, first.Nonce)
	require.Nil(t, stream.Send(&discovery.DiscoveryRequest{
		TypeUrl: first.TypeUrl, VersionInfo: first.VersionInfo, ResponseNonce: first.Nonce,
	}))
	require.Nil(t, s.DoSnapshot(t.Context()))
	second, err := stream.Recv()
	require.Nil(t, err)
	assert.NotEqual(t, first.VersionInfo, second.VersionInfo)
	assert.NotEqual(t, first.Nonce, second.Nonce)

	delta, err := discovery.NewAggregatedDiscoveryServiceClient(conn).DeltaAggregatedResources(ctx)
	require.Nil(t, err)
	require.Nil(t, delta.Send(&discovery.DeltaDiscoveryRequest{Node: &core.Node{Id: "octelium-ingress"}, TypeUrl: resource.ClusterType}))
	response, err := delta.Recv()
	require.Nil(t, err)
	require.Len(t, response.Resources, 1)
	assert.Equal(t, "octelium-health-check", response.Resources[0].Name)
	assert.NotEmpty(t, response.Resources[0].Version)
	require.Nil(t, delta.Send(&discovery.DeltaDiscoveryRequest{TypeUrl: resource.ClusterType, ResponseNonce: response.Nonce}))
}

func TestServerNodeIsolation(t *testing.T) {
	b := &tstIngressBackend{}
	s, conn := newIngressServer(t, b, nil)
	require.Nil(t, s.Run(t.Context()))
	for _, node := range []*core.Node{nil, {Id: ""}, {Id: "other-node"}} {
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		resp, err := clusterservice.NewClusterDiscoveryServiceClient(conn).FetchClusters(ctx, &discovery.DiscoveryRequest{
			Node: node, TypeUrl: resource.ClusterType,
		})
		cancel()
		assert.NotNil(t, err)
		assert.Nil(t, resp)
	}
	assert.Len(t, fetchIngress(t, conn, resource.ClusterType).Resources, 1)
}

func TestServerNewErrors(t *testing.T) {
	t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "false")
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "")
	l, err := net.Listen("tcp", ":8080")
	require.Nil(t, err)
	defer l.Close()
	s, err := envoy.NewServer(t.Context(), "example.com", nil, nil)
	assert.NotNil(t, err)
	assert.Nil(t, s)
	t.Setenv("OCTELIUM_ENABLE_SPIFFE_CSI", "true")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s, err = envoy.NewServer(ctx, "example.com", nil, nil)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, s)
}

func TestServiceControllerEvents(t *testing.T) {
	b := &tstIngressBackend{}
	s, conn := newIngressServer(t, b, nil)
	require.Nil(t, s.Run(t.Context()))
	c := svccontroller.NewController(nil, s)
	service := func(public bool) *corev1.Service {
		return &corev1.Service{Spec: &corev1.Service_Spec{IsPublic: public}}
	}
	for _, tc := range []struct {
		name string
		call func() error
		want bool
	}{
		{"PrivateAdd", func() error { return c.OnAdd(t.Context(), service(false)) }, false},
		{"PrivateDelete", func() error { return c.OnDelete(t.Context(), service(false)) }, false},
		{"PrivateUpdate", func() error { return c.OnUpdate(t.Context(), service(false), service(false)) }, false},
		{"PublicAdd", func() error { return c.OnAdd(t.Context(), service(true)) }, true},
		{"PublicDelete", func() error { return c.OnDelete(t.Context(), service(true)) }, true},
		{"Publish", func() error { return c.OnUpdate(t.Context(), service(true), service(false)) }, true},
		{"Withdraw", func() error { return c.OnUpdate(t.Context(), service(false), service(true)) }, true},
		{"PublicUpdate", func() error { return c.OnUpdate(t.Context(), service(true), service(true)) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := fetchIngress(t, conn, resource.ClusterType).VersionInfo
			require.Nil(t, tc.call())
			if tc.want {
				require.Eventually(t, func() bool {
					resp, err := getIngress(t.Context(), conn, resource.ClusterType)
					return err == nil && resp.VersionInfo != before
				}, 3*time.Second, 20*time.Millisecond)
			} else {
				assert.Never(t, func() bool {
					resp, err := getIngress(t.Context(), conn, resource.ClusterType)
					return err == nil && resp.VersionInfo != before
				}, 400*time.Millisecond, 20*time.Millisecond)
			}
		})
	}
}

func TestCertificateControllerEvents(t *testing.T) {
	b := &tstIngressBackend{}
	s, conn := newIngressServer(t, b, nil)
	require.Nil(t, s.Run(t.Context()))
	c := certcontroller.NewController(nil, s)
	secret := func(labels map[string]string) *corev1.Secret {
		return &corev1.Secret{Metadata: &metav1.Metadata{SystemLabels: labels}}
	}
	for _, labels := range []map[string]string{nil, {}, {"octelium-cert": "false"}, {"octelium-cert": "TRUE"}, {"other": "true"}, {"octelium-cert": "true"}} {
		for _, event := range []string{"Add", "Update", "Delete"} {
			t.Run(fmt.Sprintf("%v/%s", labels, event), func(t *testing.T) {
				before := fetchIngress(t, conn, resource.ClusterType).VersionInfo
				crt := secret(labels)
				var err error
				switch event {
				case "Add":
					err = c.OnAdd(t.Context(), crt)
				case "Update":
					err = c.OnUpdate(t.Context(), crt, secret(nil))
				case "Delete":
					err = c.OnDelete(t.Context(), crt)
				}
				require.Nil(t, err)
				if labels["octelium-cert"] == "true" {
					require.Eventually(t, func() bool {
						resp, err := getIngress(t.Context(), conn, resource.ClusterType)
						return err == nil && resp.VersionInfo != before
					}, 3*time.Second, 20*time.Millisecond)
				} else {
					assert.Never(t, func() bool {
						resp, err := getIngress(t.Context(), conn, resource.ClusterType)
						return err == nil && resp.VersionInfo != before
					}, 400*time.Millisecond, 20*time.Millisecond)
				}
			})
		}
	}
}
