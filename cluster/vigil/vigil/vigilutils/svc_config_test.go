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

package vigilutils

import (
	"context"
	"net"
	"testing"

	"github.com/octelium/octelium/apis/cluster/coctovigilv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/admin"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/tests/tstuser"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestGetServiceConfig(t *testing.T) {
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
	{
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
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "cfg1",
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Url{
									Url: "https://cfg1.example.com",
								},
							},
						},
						{
							Name: "cfg2",
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Url{
									Url: "https://cfg2.example.com",
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.DoCreateService(ctx, svc, false)
		assert.Nil(t, err)

		{
			res := GetServiceConfig(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
				RequestContext: &corev1.RequestContext{
					Service: svc,
				},
			})
			assert.True(t, pbutils.IsEqual(res, svc.Spec.Config))
		}

		{
			res := GetServiceConfig(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
				RequestContext: &corev1.RequestContext{
					Service: svc,
				},
				ServiceConfigName: "cfg1",
			})
			assert.True(t, pbutils.IsEqual(res, svc.Spec.DynamicConfig.Configs[0]))
		}
		{
			res := GetServiceConfig(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
				RequestContext: &corev1.RequestContext{
					Service: svc,
				},
				ServiceConfigName: "cfg2",
			})
			assert.True(t, pbutils.IsEqual(res, svc.Spec.DynamicConfig.Configs[1]))
		}
	}

	// No default config
	{
		svc := &corev1.Service{
			Metadata: &metav1.Metadata{
				Name: utilrand.GetRandomStringCanonical(8),
			},
			Spec: &corev1.Service_Spec{
				Mode: corev1.Service_Spec_HTTP,
				DynamicConfig: &corev1.Service_Spec_DynamicConfig{
					Configs: []*corev1.Service_Spec_Config{
						{
							Name: "cfg1",
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Url{
									Url: "https://cfg1.example.com",
								},
							},
						},
						{
							Name: "cfg2",
							Upstream: &corev1.Service_Spec_Config_Upstream{
								Type: &corev1.Service_Spec_Config_Upstream_Url{
									Url: "https://cfg2.example.com",
								},
							},
						},
					},
				},
			},
		}

		svc, err = adminSrv.DoCreateService(ctx, svc, false)
		assert.Nil(t, err)

		{
			res := GetServiceConfig(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
				RequestContext: &corev1.RequestContext{
					Service: svc,
				},
			})
			assert.True(t, pbutils.IsEqual(res, svc.Spec.Config))
		}

		{
			res := GetServiceConfig(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
				RequestContext: &corev1.RequestContext{
					Service: svc,
				},
				ServiceConfigName: "cfg1",
			})
			assert.True(t, pbutils.IsEqual(res, svc.Spec.DynamicConfig.Configs[0]))
		}
		{
			res := GetServiceConfig(ctx, &coctovigilv1.AuthenticateAndAuthorizeResponse{
				RequestContext: &corev1.RequestContext{
					Service: svc,
				},
				ServiceConfigName: "cfg2",
			})
			assert.True(t, pbutils.IsEqual(res, svc.Spec.DynamicConfig.Configs[1]))
		}
	}
}

func TestServiceConfigSelection(t *testing.T) {
	base := &corev1.Service_Spec_Config{
		Upstream: &corev1.Service_Spec_Config_Upstream{
			Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "https://default.example.com"},
		},
		Type: &corev1.Service_Spec_Config_Http{Http: &corev1.Service_Spec_Config_HTTP{
			EnableRequestBuffering: true,
		}},
	}
	child := &corev1.Service_Spec_Config{Name: "child", Parent: "default"}
	svc := &corev1.Service{Spec: &corev1.Service_Spec{
		Config: base,
		DynamicConfig: &corev1.Service_Spec_DynamicConfig{
			Configs: []*corev1.Service_Spec_Config{child},
		},
	}}
	original := pbutils.Clone(svc)
	for _, name := range []string{"", "default", "missing", "child"} {
		t.Run(name, func(t *testing.T) {
			got := GetServiceConfig(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeResponse{
				RequestContext: &corev1.RequestContext{Service: svc}, ServiceConfigName: name,
			})
			if assert.NotNil(t, got) {
				assert.Equal(t, "https://default.example.com", got.GetUpstream().GetUrl())
				assert.True(t, got.GetHttp().EnableRequestBuffering)
			}
		})
	}
	assert.True(t, pbutils.IsEqual(original, svc))
	explicit := &corev1.Service_Spec_Config{Name: "resolved"}
	assert.Same(t, explicit, GetServiceConfig(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeResponse{
		RequestContext: &corev1.RequestContext{Service: svc}, ServiceConfigName: "child", Config: explicit,
	}))
	for _, resp := range []*coctovigilv1.AuthenticateAndAuthorizeResponse{
		nil, {}, {RequestContext: &corev1.RequestContext{}},
	} {
		assert.Nil(t, GetServiceConfig(t.Context(), resp))
	}
	svc.Spec.DynamicConfig = nil
	assert.Same(t, base, GetServiceConfig(t.Context(), &coctovigilv1.AuthenticateAndAuthorizeResponse{
		RequestContext: &corev1.RequestContext{Service: svc}, ServiceConfigName: "missing",
	}))
}

type sourceTestConn struct {
	net.Conn
	addr net.Addr
}

func (c *sourceTestConn) RemoteAddr() net.Addr {
	return c.addr
}

func TestDownstreamRequestSource(t *testing.T) {
	for _, tc := range []struct {
		name string
		conn net.Conn
		ip   string
		port int32
	}{
		{name: "nil"},
		{name: "TCPv4", conn: &sourceTestConn{addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}}, ip: "192.0.2.10", port: 1234},
		{name: "TCPv6", conn: &sourceTestConn{addr: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 65535}}, ip: "2001:db8::1", port: 65535},
		{name: "UDP", conn: &sourceTestConn{addr: &net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 53}}, ip: "192.0.2.20", port: 53},
		{name: "Unix", conn: &sourceTestConn{addr: &net.UnixAddr{Name: "/tmp/vigil.sock", Net: "unix"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := GetDownstreamRequestSource(tc.conn)
			assert.Equal(t, tc.ip, got.Address)
			assert.Equal(t, tc.port, got.Port)
		})
	}
}
