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
	"testing"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/cluster/vigil/vigil/vcache"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

type fakeCache struct {
	s *corev1.Service
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
