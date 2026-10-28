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

package loadbalancer

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCache struct {
	s *corev1.Service
}

func TestUpstreamEndpointAddresses(t *testing.T) {
	lb := NewLbManager(nil, nil)
	svc := &corev1.Service{Spec: &corev1.Service_Spec{}}
	for _, tc := range []struct {
		url  string
		addr string
		sni  string
		path string
	}{
		{"http://example.com", "example.com:80", "example.com", ""},
		{"https://example.com/base/?ignored=true", "example.com:443", "example.com", "/base"},
		{"ssh://example.com", "example.com:22", "example.com", ""},
		{"postgres://example.com", "example.com:5432", "example.com", ""},
		{"mysql://example.com", "example.com:3306", "example.com", ""},
		{"tcp://192.0.2.1:9000", "192.0.2.1:9000", "", ""},
		{"https://[2001:db8::1]:8443/a", "[2001:db8::1]:8443", "", "/a"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			got, err := lb.doGetUpstream(&corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{Url: tc.url}, svc)
			require.Nil(t, err)
			assert.Equal(t, tc.addr, got.HostPort)
			assert.Equal(t, tc.sni, got.SNIHost)
			assert.Equal(t, tc.path, got.GetPath())
			assert.Empty(t, got.URL.RawQuery)
			assert.False(t, got.IsUser)
		})
	}
	got, err := lb.doGetUpstream(&corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{Url: "http://%zz"}, svc)
	assert.NotNil(t, err)
	assert.Nil(t, got)
	var upstream *Upstream
	assert.Empty(t, upstream.GetPath())
	for _, path := range []string{"", "/", "relative"} {
		assert.Empty(t, (&Upstream{Path: path}).GetPath())
	}
}

func TestUpstreamSessionAddressFamilies(t *testing.T) {
	vc, err := vcache.NewCache(t.Context())
	require.Nil(t, err)
	svc := &corev1.Service{Metadata: &metav1.Metadata{Uid: "service"}, Spec: &corev1.Service_Spec{}}
	vc.SetService(svc)
	for _, tc := range []struct {
		name string
		mode corev1.Session_Status_Connection_L3Mode
		addr *metav1.DualStackNetwork
		want string
	}{
		{"V4", corev1.Session_Status_Connection_V4, &metav1.DualStackNetwork{V4: "192.0.2.1/32"}, "192.0.2.1:8080"},
		{"V6", corev1.Session_Status_Connection_V6, &metav1.DualStackNetwork{V6: "2001:db8::1/128"}, "[2001:db8::1]:8080"},
		{"Both", corev1.Session_Status_Connection_BOTH, &metav1.DualStackNetwork{V4: "192.0.2.1/32", V6: "2001:db8::1/128"}, "[2001:db8::1]:8080"},
		{"MissingV4", corev1.Session_Status_Connection_V4, &metav1.DualStackNetwork{V6: "2001:db8::1/128"}, ""},
		{"MissingV6", corev1.Session_Status_Connection_V6, &metav1.DualStackNetwork{V4: "192.0.2.1/32"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lb := NewLbManager(nil, vc)
			sess := newTestSession("session", "user", "service", 8080)
			sess.Status.Connection.L3Mode = tc.mode
			sess.Status.Connection.Addresses = []*metav1.DualStackNetwork{tc.addr}
			sess.Status.Connection.Ed25519PublicKey = []byte("public-key")
			lb.SetSession(sess)
			got, err := lb.doGetUpstream(&corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
				Url: "https://virtual.example.com/base", User: "user",
			}, svc)
			if tc.want == "" {
				assert.ErrorIs(t, err, ErrNoUpstream)
				assert.Nil(t, got)
				return
			}
			require.Nil(t, err)
			assert.Equal(t, tc.want, got.HostPort)
			assert.Equal(t, "virtual.example.com", got.SNIHost)
			assert.Equal(t, "session", got.SessionRef.Uid)
			assert.Equal(t, []byte("public-key"), got.Ed25519PublicKey)
			assert.True(t, got.IsUser)
			assert.Equal(t, "/base", got.GetPath())
			lb.DeleteSession(sess)
			_, err = lb.doGetUpstream(&corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
				Url: "https://virtual.example.com", User: "user",
			}, svc)
			assert.ErrorIs(t, err, ErrNoUpstream)
		})
	}
}

func TestSessionStopsServingService(t *testing.T) {
	vc, err := vcache.NewCache(t.Context())
	require.Nil(t, err)
	svc := &corev1.Service{Metadata: &metav1.Metadata{Uid: "service"}}
	vc.SetService(svc)
	lb := NewLbManager(nil, vc)
	old := newTestSession("session", "user", "service", 80)
	lb.SetSession(old)
	updated := pbutils.Clone(old).(*corev1.Session)
	updated.Status.Connection.Upstreams = nil
	require.Nil(t, lb.OnUpdate(t.Context(), updated, old))
	assert.Nil(t, lb.cache.getByUserName("user", svc))
	unrelated := newTestSession("other", "user", "other-service", 80)
	require.Nil(t, lb.onAdd(t.Context(), unrelated))
	assert.Empty(t, lb.cache.sMap)
}

func TestManagedUpstreamSchemes(t *testing.T) {
	for _, mode := range []corev1.Service_Spec_Mode{
		corev1.Service_Spec_HTTP, corev1.Service_Spec_WEB, corev1.Service_Spec_GRPC,
		corev1.Service_Spec_KUBERNETES, corev1.Service_Spec_MCP, corev1.Service_Spec_LLM,
		corev1.Service_Spec_SSH, corev1.Service_Spec_DNS, corev1.Service_Spec_UDP,
		corev1.Service_Spec_TCP, corev1.Service_Spec_MYSQL, corev1.Service_Spec_POSTGRES,
	} {
		t.Run(mode.String(), func(t *testing.T) {
			svc := &corev1.Service{Spec: &corev1.Service_Spec{Mode: mode}}
			want := "tcp"
			switch mode {
			case corev1.Service_Spec_HTTP, corev1.Service_Spec_WEB, corev1.Service_Spec_GRPC,
				corev1.Service_Spec_KUBERNETES, corev1.Service_Spec_MCP, corev1.Service_Spec_LLM:
				want = "http"
			case corev1.Service_Spec_SSH:
				want = "ssh"
			case corev1.Service_Spec_DNS, corev1.Service_Spec_UDP:
				want = "udp"
			}
			assert.Equal(t, want, getScheme(svc))
		})
	}
}

func newTestSession(uid, user, service string, port int32) *corev1.Session {
	return &corev1.Session{
		Metadata: &metav1.Metadata{Uid: uid},
		Status: &corev1.Session_Status{
			Type:    corev1.Session_Status_CLIENT,
			UserRef: &metav1.ObjectReference{Name: user},
			Connection: &corev1.Session_Status_Connection{
				L3Mode:    corev1.Session_Status_Connection_V4,
				Addresses: []*metav1.DualStackNetwork{{V4: "192.0.2.1/32"}},
				Upstreams: []*corev1.Session_Status_Connection_Upstream{
					{ServiceRef: &metav1.ObjectReference{Uid: service}, Port: port},
				},
			},
		},
	}
}

func TestSessionCacheLifecycle(t *testing.T) {
	c := newCache()
	svc := &corev1.Service{Metadata: &metav1.Metadata{Uid: "service"}}
	assert.Nil(t, c.getByUserName("user", svc))
	c.deleteSession(newTestSession("missing", "user", "service", 80))

	first := newTestSession("first", "user", "other", 80)
	second := newTestSession("second", "user", "service", 81)
	c.setSession(first)
	c.setSession(second)
	assert.Equal(t, second, c.getByUserName("user", svc))
	assert.Nil(t, c.getByUserName("other-user", svc))

	replacement := newTestSession("second", "user", "service", 82)
	c.setSession(replacement)
	assert.Equal(t, replacement, c.getByUserName("user", svc))
	assert.Len(t, c.sMap["user"], 2)
	c.deleteSession(replacement)
	assert.Nil(t, c.getByUserName("user", svc))
	assert.Len(t, c.sMap["user"], 1)
	c.deleteSession(first)
	assert.Empty(t, c.sMap)
}

func TestSessionCacheConcurrentAccess(t *testing.T) {
	c := newCache()
	svc := &corev1.Service{Metadata: &metav1.Metadata{Uid: "service"}}
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			sess := newTestSession(fmt.Sprintf("session-%d", i), "user", "service", 80)
			for range 32 {
				c.setSession(sess)
				got := c.getByUserName("user", svc)
				if got != nil {
					assert.Equal(t, int32(80), got.Status.Connection.Upstreams[0].Port)
				}
				c.deleteSession(sess)
			}
		})
	}
	wg.Wait()
	assert.Empty(t, c.sMap)
}

func TestSessionUpdate(t *testing.T) {
	vc, err := vcache.NewCache(t.Context())
	require.Nil(t, err)
	svc := &corev1.Service{Metadata: &metav1.Metadata{Uid: "service"}}
	vc.SetService(svc)
	lb := NewLbManager(nil, vc)

	old := newTestSession("session", "user", "service", 80)
	require.Nil(t, lb.onAdd(t.Context(), old))
	assert.Equal(t, old, lb.cache.getByUserName("user", svc))

	updated := newTestSession("session", "user", "service", 81)
	require.Nil(t, lb.OnUpdate(t.Context(), updated, old))
	assert.Equal(t, updated, lb.cache.getByUserName("user", svc))
	require.Nil(t, lb.OnUpdate(t.Context(), updated, updated))

	disconnected := newTestSession("session", "user", "service", 81)
	disconnected.Status.Connection = nil
	require.Nil(t, lb.OnUpdate(t.Context(), disconnected, updated))
	assert.Nil(t, lb.cache.getByUserName("user", svc))

	lb.SetSession(updated)
	require.Nil(t, lb.onDelete(t.Context(), updated))
	assert.Nil(t, lb.cache.getByUserName("user", svc))
}

func TestGetUpstreamMissing(t *testing.T) {
	lb := NewLbManager(nil, nil)
	for _, resp := range []*coctovigilv1.AuthenticateAndAuthorizeResponse{
		nil,
		{},
		{RequestContext: &corev1.RequestContext{}},
		{RequestContext: &corev1.RequestContext{Service: &corev1.Service{Spec: &corev1.Service_Spec{}, Status: &corev1.Service_Status{}}}},
	} {
		got, err := lb.GetUpstream(t.Context(), resp)
		assert.ErrorIs(t, err, ErrNoUpstream)
		assert.Nil(t, got)
	}
}

func (c *fakeCache) GetService() *corev1.Service {
	return c.s
}

func TestLoadBalancer(t *testing.T) {
	ctx := context.Background()

	tst, err := tests.Initialize(nil)
	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})
	fakeC := tst.C
	{
		vCache, err := vcache.NewCache(ctx)
		assert.Nil(t, err)
		vCache.SetService(&corev1.Service{
			Metadata: &metav1.Metadata{},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://google.com",
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		})
		lb := NewLbManager(fakeC.OcteliumC, vCache)

		u, err := lb.GetUpstream(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext: &corev1.RequestContext{
				Service: vCache.GetService(),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, "google.com:443", u.HostPort)
	}

	{
		vCache, err := vcache.NewCache(ctx)
		assert.Nil(t, err)
		vCache.SetService(&corev1.Service{
			Metadata: &metav1.Metadata{},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://google.com/search?q=linux",
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		})
		lb := NewLbManager(fakeC.OcteliumC, vCache)

		u, err := lb.GetUpstream(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext: &corev1.RequestContext{
				Service: vCache.GetService(),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, "https://google.com", u.URL.String())
		assert.Equal(t, "google.com:443", u.HostPort)
		assert.Equal(t, "/search", u.GetPath())
	}

	{
		vCache, err := vcache.NewCache(ctx)
		assert.Nil(t, err)
		vCache.SetService(&corev1.Service{
			Metadata: &metav1.Metadata{},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				Config: &corev1.Service_Spec_Config{
					Upstream: &corev1.Service_Spec_Config_Upstream{
						Type: &corev1.Service_Spec_Config_Upstream_Url{
							Url: "https://google.com",
						},
					},
				},
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "example",

							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Url{
									Url: "https://example.com",
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		})
		lb := NewLbManager(fakeC.OcteliumC, vCache)

		u, err := lb.GetUpstream(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext: &corev1.RequestContext{
				Service: vCache.GetService(),
			},
			ServiceConfigName: "example",
		})
		assert.Nil(t, err)
		assert.Equal(t, "example.com:443", u.HostPort)
	}

	{
		vCache, err := vcache.NewCache(ctx)
		assert.Nil(t, err)
		vCache.SetService(&corev1.Service{
			Metadata: &metav1.Metadata{},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,

				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "v1",

							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Url{
									Url: "https://v1.example.com",
								},
							},
						},
						{
							Name: "v2",

							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Url{
									Url: "https://v2.example.com",
								},
							},
						},
					},
				},
			},
			Status: &corev1.Service_Status{},
		})
		lb := NewLbManager(fakeC.OcteliumC, vCache)

		u, err := lb.GetUpstream(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext: &corev1.RequestContext{
				Service: vCache.GetService(),
			},
			ServiceConfigName: "v2",
		})
		assert.Nil(t, err)
		assert.Equal(t, "v2.example.com:443", u.HostPort)
	}

	/*
		{
			lb := NewLbManager(fakeC.OcteliumC)

			err = lb.Set(ctx, &corev1.Service{
				Metadata: &metav1.Metadata{},
				Spec: &corev1.Service_Spec{
					Config: &corev1.Service_Spec_Config{
						Upstream: &corev1.Service_Spec_Config_Upstream{
							Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{
								Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{
									Endpoints: []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
										{
											Url: "https://google.com",
										},
										{
											Url: "https://wikipedia.org",
										},
										{
											Url: "https://linux.org",
										},
									},
								},
							},
						},
					},
				},
				Status: &corev1.Service_Status{},
			})
			assert.Nil(t, err)
			assert.Equal(t, 3, len(lb.upstreams))
			u, err := lb.GetUpstream()
			assert.Nil(t, err)
			assert.Equal(t, "google.com:443", u.HostPort)
			u, err = lb.GetUpstream()
			assert.Nil(t, err)
			assert.Equal(t, "wikipedia.org:443", u.HostPort)
			u, err = lb.GetUpstream()
			assert.Nil(t, err)
			assert.Equal(t, "linux.org:443", u.HostPort)
			u, err = lb.GetUpstream()
			assert.Nil(t, err)
			assert.Equal(t, "google.com:443", u.HostPort)
		}
	*/

	{

		vCache, err := vcache.NewCache(ctx)
		assert.Nil(t, err)
		vCache.SetService(&corev1.Service{
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				ManagedService: &corev1.Service_Status_ManagedService{},
			},
		})
		lb := NewLbManager(fakeC.OcteliumC, vCache)

		u, err := lb.GetUpstream(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext: &corev1.RequestContext{
				Service: vCache.GetService(),
			},
		})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, "localhost:49999", u.HostPort)
	}

	{
		vCache, err := vcache.NewCache(ctx)
		assert.Nil(t, err)
		vCache.SetService(&corev1.Service{
			Spec: &corev1.Service_Spec{},
			Status: &corev1.Service_Status{
				ManagedService: &corev1.Service_Status_ManagedService{
					Port: 7890,
				},
			},
		})
		lb := NewLbManager(fakeC.OcteliumC, vCache)

		u, err := lb.GetUpstream(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
			RequestContext: &corev1.RequestContext{
				Service: vCache.GetService(),
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, "localhost:7890", u.HostPort)
	}
}

func TestSetUpstreamSession(t *testing.T) {
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

	usr, err := tstuser.NewUserWithType(fakeC.OcteliumC, adminSrv, nil, nil, corev1.User_Spec_HUMAN, corev1.Session_Status_CLIENT)
	assert.Nil(t, err)

	svc := &corev1.Service{
		Metadata: &metav1.Metadata{
			Name: utilrand.GetRandomStringCanonical(8),
		},
		Spec: &corev1.Service_Spec{
			Mode: corev1.Service_Spec_HTTP,
			Config: &corev1.Service_Spec_Config{
				Upstream: &corev1.Service_Spec_Config_Upstream{
					Type: &corev1.Service_Spec_Config_Upstream_Loadbalance_{
						Loadbalance: &corev1.Service_Spec_Config_Upstream_Loadbalance{
							Endpoints: []*corev1.Service_Spec_Config_Upstream_Loadbalance_Endpoint{
								{
									Url:  "https://example.com",
									User: usr.Usr.Metadata.Name,
								},
							},
						},
					},
				},
			},
		},
	}

	svc, err = adminSrv.DoCreateService(ctx, svc, false)
	assert.Nil(t, err)

	vCache, err := vcache.NewCache(ctx)
	assert.Nil(t, err)
	vCache.SetService(svc)
	lb := NewLbManager(fakeC.OcteliumC, vCache)

	err = usr.ConnectWithServeAll()
	assert.Nil(t, err)

	_, err = lb.GetUpstream(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
		RequestContext: &corev1.RequestContext{
			Service: vCache.GetService(),
		},
	})
	assert.NotNil(t, err)
	assert.Equal(t, ErrNoUpstream, err)

	lb.SetSession(usr.Session)

	upstream, err := lb.GetUpstream(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
		RequestContext: &corev1.RequestContext{
			Service: vCache.GetService(),
		},
	})
	assert.Nil(t, err)

	assert.Equal(t, usr.Session.Metadata.Uid, upstream.SessionRef.Uid)
	assert.True(t, upstream.IsUser)

	lb.DeleteSession(usr.Session)
	_, err = lb.GetUpstream(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
		RequestContext: &corev1.RequestContext{
			Service: vCache.GetService(),
		},
	})
	assert.NotNil(t, err)
	assert.Equal(t, ErrNoUpstream, err)
}

func TestUpstreamGetPath(t *testing.T) {
	assert.Equal(t, "", (*Upstream)(nil).GetPath())
	assert.Equal(t, "", (&Upstream{}).GetPath())
	assert.Equal(t, "", (&Upstream{Path: "/"}).GetPath())
	assert.Equal(t, "", (&Upstream{Path: "v1"}).GetPath())

	assert.Equal(t, "/api/v1", (&Upstream{Path: "/api/v1"}).GetPath())
	assert.Equal(t, "/api/v1", (&Upstream{Path: "/api/v1/"}).GetPath())
	assert.Equal(t, "/mcp", (&Upstream{Path: "/mcp"}).GetPath())
}
