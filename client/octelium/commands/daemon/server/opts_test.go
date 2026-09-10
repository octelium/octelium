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

package server

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
	user := &principal{
		id:      "1000",
		name:    "usr1000",
		homeDir: "/home/usr1000",
	}
	root := &principal{
		id:   rootPrincipalID,
		name: "root",
	}

	{
		opts, err := getConnectOpts(nil, user)
		assert.Nil(t, err)
		assert.Equal(t, "", opts.L3Mode)
		assert.Equal(t, "", opts.TunnelMode)
		assert.Equal(t, "", opts.ImplementationMode)
		assert.False(t, opts.IgnoreDNS)
		assert.False(t, opts.UseFullDNS)
	}

	{
		opts, err := getConnectOpts(&daemonv1.ConnectionOptions{
			L3Mode:             daemonv1.ConnectionOptions_V4,
			TunnelMode:         daemonv1.ConnectionOptions_QUICV0,
			ImplementationMode: daemonv1.ConnectionOptions_GVISOR,
			Mtu:                1280,
			Dns: &daemonv1.ConnectionOptions_DNS{
				Mode: daemonv1.ConnectionOptions_DNS_FULL,
			},
		}, user)
		assert.Nil(t, err)
		assert.Equal(t, "v4", opts.L3Mode)
		assert.Equal(t, "quicv0", opts.TunnelMode)
		assert.Equal(t, "gvisor", opts.ImplementationMode)
		assert.Equal(t, int32(1280), opts.MTU)
		assert.True(t, opts.UseFullDNS)
		assert.False(t, opts.IgnoreDNS)
	}

	{
		opts, err := getConnectOpts(&daemonv1.ConnectionOptions{
			L3Mode:             daemonv1.ConnectionOptions_V6,
			TunnelMode:         daemonv1.ConnectionOptions_WIREGUARD,
			ImplementationMode: daemonv1.ConnectionOptions_KERNEL,
			Dns: &daemonv1.ConnectionOptions_DNS{
				Mode: daemonv1.ConnectionOptions_DNS_DISABLED,
			},
		}, user)
		assert.Nil(t, err)
		assert.Equal(t, "v6", opts.L3Mode)
		assert.Equal(t, "wg", opts.TunnelMode)
		assert.Equal(t, "kernel", opts.ImplementationMode)
		assert.True(t, opts.IgnoreDNS)
	}

	{
		opts, err := getConnectOpts(&daemonv1.ConnectionOptions{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				Serve: []*daemonv1.ConnectionOptions_ServiceReference{
					{
						Name: "svc1",
					},
					{
						Name:      "svc2",
						Namespace: "ns2",
					},
				},
				Publish: []*daemonv1.ConnectionOptions_PublishedService{
					{
						Service: &daemonv1.ConnectionOptions_ServiceReference{
							Name:      "svc3",
							Namespace: "ns3",
						},
						Port: 8080,
					},
					{
						Service: &daemonv1.ConnectionOptions_ServiceReference{
							Name: "svc4",
						},
						Address: "0.0.0.0",
						Port:    9090,
					},
				},
				EnableEmbeddedSSH:    true,
				EnableEmbeddedSOCKS5: true,
			},
		}, user)
		assert.Nil(t, err)
		assert.Equal(t, []string{"svc1", "svc2.ns2"}, opts.ServeServices)
		assert.Equal(t, 2, len(opts.PublishServices))
		assert.Equal(t, "svc3.ns3", opts.PublishServices[0].Name)
		assert.Equal(t, "localhost", opts.PublishServices[0].Address)
		assert.Equal(t, 8080, opts.PublishServices[0].Port)
		assert.Equal(t, "svc4", opts.PublishServices[1].Name)
		assert.Equal(t, "0.0.0.0", opts.PublishServices[1].Address)
		assert.Equal(t, 9090, opts.PublishServices[1].Port)
		assert.True(t, opts.UseESSH)
		assert.True(t, opts.UseESOCKS5)

		assert.Equal(t, "usr1000", opts.ESSHUser)
		assert.Equal(t, "/home/usr1000", opts.UserHome)
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				ServeAll: true,
				Serve: []*daemonv1.ConnectionOptions_ServiceReference{
					{
						Name: "svc1",
					},
				},
			},
		}, user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				Serve: []*daemonv1.ConnectionOptions_ServiceReference{
					{
						Namespace: "ns1",
					},
				},
			},
		}, user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				Publish: []*daemonv1.ConnectionOptions_PublishedService{
					{
						Service: &daemonv1.ConnectionOptions_ServiceReference{
							Name: "svc1",
						},
						Port: 0,
					},
				},
			},
		}, user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				Publish: []*daemonv1.ConnectionOptions_PublishedService{
					{
						Service: &daemonv1.ConnectionOptions_ServiceReference{
							Name: "svc1",
						},
						Address: "not-an-address",
						Port:    8080,
					},
				},
			},
		}, user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				Publish: []*daemonv1.ConnectionOptions_PublishedService{
					{
						Service: &daemonv1.ConnectionOptions_ServiceReference{
							Name: "svc1",
						},
						Port: 80,
					},
				},
			},
		}, user)
		assert.True(t, grpcerr.IsPermissionDenied(err))
	}

	{
		opts, err := getConnectOpts(&daemonv1.ConnectionOptions{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				Publish: []*daemonv1.ConnectionOptions_PublishedService{
					{
						Service: &daemonv1.ConnectionOptions_ServiceReference{
							Name: "svc1",
						},
						Port: 80,
					},
				},
			},
		}, root)
		assert.Nil(t, err)
		assert.Equal(t, 80, opts.PublishServices[0].Port)
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			Mtu: 128,
		}, user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			Mtu: 9000,
		}, user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			L3Mode: daemonv1.ConnectionOptions_L3Mode(100),
		}, user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			TunnelMode: daemonv1.ConnectionOptions_TunnelMode(100),
		}, user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			ImplementationMode: daemonv1.ConnectionOptions_ImplementationMode(100),
		}, user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			Dns: &daemonv1.ConnectionOptions_DNS{
				Mode: daemonv1.ConnectionOptions_DNS_Mode(100),
			},
		}, user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		_, err := getConnectOpts(&daemonv1.ConnectionOptions{
			ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
				EnableEmbeddedSSH: true,
			},
		}, &principal{id: "1001"})
		assert.True(t, grpcerr.IsFailedPrecondition(err))
	}
}

func TestGetLocalDNSListenAddr(t *testing.T) {
	const user = "1000"

	{
		addr, err := getLocalDNSListenAddr("127.0.0.53", user)
		assert.Nil(t, err)
		assert.Equal(t, "127.0.0.53:53", addr)
	}
	{
		addr, err := getLocalDNSListenAddr("127.0.0.53:5353", user)
		assert.Nil(t, err)
		assert.Equal(t, "127.0.0.53:5353", addr)
	}
	{
		addr, err := getLocalDNSListenAddr("127.0.0.53:53", user)
		assert.Nil(t, err)
		assert.Equal(t, "127.0.0.53:53", addr)
	}
	{
		_, err := getLocalDNSListenAddr("not-an-address", user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := getLocalDNSListenAddr("127.0.0.53:0", user)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := getLocalDNSListenAddr("127.0.0.53:443", user)
		assert.True(t, grpcerr.IsPermissionDenied(err))
	}
	{
		addr, err := getLocalDNSListenAddr("127.0.0.53:443", rootPrincipalID)
		assert.Nil(t, err)
		assert.Equal(t, "127.0.0.53:443", addr)
	}
}

func TestNormalizeConnectionOptions(t *testing.T) {
	{
		opts := normalizeConnectionOptions(nil)
		assert.Equal(t, daemonv1.ConnectionOptions_DNS_DEFAULT, opts.Dns.Mode)
		assert.False(t, opts.Dns.EnableLocalServer)
	}
	{
		opts := normalizeConnectionOptions(&daemonv1.ConnectionOptions{
			Dns: &daemonv1.ConnectionOptions_DNS{
				Mode: daemonv1.ConnectionOptions_DNS_FULL,
			},
		})
		assert.Equal(t, daemonv1.ConnectionOptions_DNS_FULL, opts.Dns.Mode)
		assert.True(t, opts.Dns.EnableLocalServer)
	}
}

func TestSetConnectionStatusFromConnection(t *testing.T) {
	{
		st := &daemonv1.ConnectionStatus{}
		setConnectionStatusFromConnection(st, nil)
		assert.Equal(t, daemonv1.ConnectionOptions_TUNNEL_MODE_UNSPECIFIED, st.TunnelMode)
		assert.Nil(t, st.Dns)
	}

	{
		st := &daemonv1.ConnectionStatus{}
		setConnectionStatusFromConnection(st, &cliconfigv1.Connection{
			Connection: &userv1.ConnectionState{
				Addresses: []*metav1.DualStackNetwork{
					{
						V4: "100.64.0.1/32",
						V6: "fd00::1/128",
					},
				},
				Dns: &userv1.DNS{
					Servers: []string{"100.64.0.53"},
				},
			},
			Preferences: &cliconfigv1.Connection_Preferences{
				DeviceName:     "octelium-abc123",
				Mtu:            1380,
				ConnectionType: cliconfigv1.Connection_Preferences_CONNECTION_TYPE_QUICV0,
				LinuxPrefs: &cliconfigv1.Connection_Preferences_Linux{
					ImplementationMode: cliconfigv1.Connection_Preferences_Linux_WG_NETSTACK,
				},
				LocalDNS: &cliconfigv1.Connection_Preferences_LocalDNS{
					IsEnabled:     true,
					ListenAddress: "127.0.0.53:53",
				},
			},
		})

		assert.Equal(t, "octelium-abc123", st.DeviceName)
		assert.Equal(t, int32(1380), st.Mtu)
		assert.Equal(t, daemonv1.ConnectionOptions_QUICV0, st.TunnelMode)
		assert.Equal(t, daemonv1.ConnectionOptions_GVISOR, st.ImplementationMode)
		assert.Equal(t, 1, len(st.Addresses))
		assert.Equal(t, "fd00::1/128", st.Addresses[0].V6)
		assert.Equal(t, daemonv1.ConnectionOptions_DNS_DEFAULT, st.Dns.Mode)
		assert.True(t, st.Dns.IsConfigured)
		assert.Equal(t, []string{"100.64.0.53"}, st.Dns.Servers)
		assert.Equal(t, "127.0.0.53:53", st.Dns.LocalServerListenAddress)
	}

	{
		st := &daemonv1.ConnectionStatus{}
		setConnectionStatusFromConnection(st, &cliconfigv1.Connection{
			Preferences: &cliconfigv1.Connection_Preferences{
				IgnoreDNS: true,
			},
		})

		assert.Equal(t, daemonv1.ConnectionOptions_DNS_DISABLED, st.Dns.Mode)
		assert.False(t, st.Dns.IsConfigured)
		assert.Equal(t, daemonv1.ConnectionOptions_WIREGUARD, st.TunnelMode)
	}
}
