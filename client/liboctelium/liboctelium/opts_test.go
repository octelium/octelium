// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package liboctelium

import (
	"testing"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
)

func TestGetConnectOpts(t *testing.T) {

	{
		opts, err := getConnectOpts(nil)
		assert.Nil(t, err)
		assert.Equal(t, "v6", opts.L3Mode)
		assert.Equal(t, "", opts.TunnelMode)
		assert.Equal(t, "", opts.ImplementationMode)
		assert.False(t, opts.IgnoreDNS)
		assert.False(t, opts.UseFullDNS)
		assert.False(t, opts.UseLocalDNS)
		assert.Nil(t, opts.Platform)
	}

	{
		opts, err := getConnectOpts(&daemonv1.ConnectionOptions{
			L3Mode:     daemonv1.ConnectionOptions_V4,
			TunnelMode: daemonv1.ConnectionOptions_QUICV0,
			Mtu:        1280,
			Dns: &daemonv1.ConnectionOptions_DNS{
				Mode: daemonv1.ConnectionOptions_DNS_FULL,
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, "v4", opts.L3Mode)
		assert.Equal(t, "quicv0", opts.TunnelMode)
		assert.Equal(t, int32(1280), opts.MTU)
		assert.True(t, opts.UseFullDNS)
		assert.False(t, opts.IgnoreDNS)
		assert.False(t, opts.UseLocalDNS)
	}

	{
		opts, err := getConnectOpts(&daemonv1.ConnectionOptions{
			L3Mode:     daemonv1.ConnectionOptions_BOTH,
			TunnelMode: daemonv1.ConnectionOptions_WIREGUARD,
			Dns: &daemonv1.ConnectionOptions_DNS{
				Mode: daemonv1.ConnectionOptions_DNS_DISABLED,
			},
		})
		assert.Nil(t, err)
		assert.Equal(t, "both", opts.L3Mode)
		assert.Equal(t, "wg", opts.TunnelMode)
		assert.True(t, opts.IgnoreDNS)
		assert.False(t, opts.UseFullDNS)
	}

	{
		opts, err := getConnectOpts(&daemonv1.ConnectionOptions{
			L3Mode: daemonv1.ConnectionOptions_V6,
		})
		assert.Nil(t, err)
		assert.Equal(t, "v6", opts.L3Mode)
	}

	invalidOpts := []*daemonv1.ConnectionOptions{
		{
			L3Mode: daemonv1.ConnectionOptions_L3Mode(100),
		},
		{
			TunnelMode: daemonv1.ConnectionOptions_TunnelMode(100),
		},
		{
			ImplementationMode: daemonv1.ConnectionOptions_ImplementationMode(100),
		},
		{
			ImplementationMode: daemonv1.ConnectionOptions_KERNEL,
		},
		{
			ImplementationMode: daemonv1.ConnectionOptions_GVISOR,
		},
		{
			Dns: &daemonv1.ConnectionOptions_DNS{
				Mode: daemonv1.ConnectionOptions_DNS_Mode(100),
			},
		},
		{
			Dns: &daemonv1.ConnectionOptions_DNS{
				EnableLocalServer: true,
			},
		},
		{
			Dns: &daemonv1.ConnectionOptions_DNS{
				LocalServerListenAddress: "127.0.0.1:5353",
			},
		},
		{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				ServeAll: true,
			},
		},
		{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				Serve: []*daemonv1.ConnectionOptions_ServiceReference{
					{Name: "svc1"},
				},
			},
		},
		{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				Publish: []*daemonv1.ConnectionOptions_PublishedService{
					{
						Service: &daemonv1.ConnectionOptions_ServiceReference{Name: "svc1"},
						Port:    8080,
					},
				},
			},
		},
		{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				EnableEmbeddedSSH: true,
			},
		},
		{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				EnableEmbeddedSOCKS5: true,
			},
		},
		{
			Mtu: 575,
		},
		{
			Mtu: 1501,
		},
		{
			Mtu: -1,
		},
	}

	for _, o := range invalidOpts {
		_, err := getConnectOpts(o)
		assert.NotNil(t, err, "%+v", o)
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", o)
	}

	{
		opts, err := getConnectOpts(&daemonv1.ConnectionOptions{
			ImplementationMode: daemonv1.ConnectionOptions_TUN,
			ServiceOptions:     &daemonv1.ConnectionOptions_ServiceOptions{},
			Dns:                &daemonv1.ConnectionOptions_DNS{},
			Mtu:                1500,
		})
		assert.Nil(t, err)
		assert.Equal(t, "", opts.ImplementationMode)
	}
}

func TestNormalizeConnectionOptions(t *testing.T) {
	{
		ret := normalizeConnectionOptions(nil)
		assert.Equal(t, daemonv1.ConnectionOptions_DNS_DEFAULT, ret.Dns.Mode)
		assert.False(t, ret.Dns.EnableLocalServer)
	}

	{
		o := &daemonv1.ConnectionOptions{
			Dns: &daemonv1.ConnectionOptions_DNS{
				Mode: daemonv1.ConnectionOptions_DNS_FULL,
			},
		}
		ret := normalizeConnectionOptions(o)
		assert.Equal(t, daemonv1.ConnectionOptions_DNS_FULL, ret.Dns.Mode)
		assert.False(t, ret.Dns.EnableLocalServer)

		ret.Mtu = 1300
		assert.Equal(t, int32(0), o.Mtu)
	}
}

func TestSetConnectionStatusFromConnection(t *testing.T) {
	{
		st := &daemonv1.ConnectionStatus{}
		setConnectionStatusFromConnection(st, nil)
		assert.Nil(t, st.Dns)
	}

	{
		st := &daemonv1.ConnectionStatus{}
		setConnectionStatusFromConnection(st, &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Addresses: []*metav1.DualStackNetwork{
					{V6: "fdee:be1d::3/128"},
				},
				Dns: &userv1.DNS{
					Servers: []string{"fdee:be1d::53"},
				},
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				Mtu:     1300,
				FullDNS: true,
			},
		})

		assert.Equal(t, int32(1300), st.Mtu)
		assert.Equal(t, daemonv1.ConnectionOptions_WIREGUARD, st.TunnelMode)
		assert.Equal(t, daemonv1.ConnectionOptions_TUN, st.ImplementationMode)
		assert.Equal(t, 1, len(st.Addresses))
		assert.Equal(t, daemonv1.ConnectionOptions_DNS_FULL, st.Dns.Mode)
		assert.True(t, st.Dns.IsConfigured)
		assert.Equal(t, []string{"fdee:be1d::53"}, st.Dns.Servers)
		assert.Equal(t, "", st.Dns.LocalServerListenAddress)
	}

	{
		st := &daemonv1.ConnectionStatus{}
		setConnectionStatusFromConnection(st, &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Dns: &userv1.DNS{
					Servers: []string{"100.64.0.53"},
				},
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				IgnoreDNS:      true,
				ConnectionType: cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0,
			},
		})

		assert.Equal(t, daemonv1.ConnectionOptions_QUICV0, st.TunnelMode)
		assert.Equal(t, daemonv1.ConnectionOptions_DNS_DISABLED, st.Dns.Mode)
		assert.False(t, st.Dns.IsConfigured)
	}

	{
		st := &daemonv1.ConnectionStatus{}
		setConnectionStatusFromConnection(st, &cliconfigv1.Connection{
			Connection:  &userv1.ConnectionState{},
			Preferences: &cliconfigv1.Connection_Preferences{},
		})

		assert.Equal(t, daemonv1.ConnectionOptions_DNS_DEFAULT, st.Dns.Mode)
		assert.False(t, st.Dns.IsConfigured)
	}
}

func TestCanonicalizeDomain(t *testing.T) {
	{
		ret, err := canonicalizeDomain(" Example.COM. ")
		assert.Nil(t, err)
		assert.Equal(t, "example.com", ret)
	}

	{
		ret, err := canonicalizeDomain("bücher.example")
		assert.Nil(t, err)
		assert.Equal(t, "xn--bcher-kva.example", ret)
	}

	for _, arg := range []string{
		"",
		" ",
		"localhost",
		"1.2.3.4",
		"example..com",
		"exa mple.com",
		"http://example.com",
	} {
		_, err := canonicalizeDomain(arg)
		assert.NotNil(t, err, "%s", arg)
		assert.True(t, grpcerr.IsInvalidArg(err), "%s", arg)
	}
}
