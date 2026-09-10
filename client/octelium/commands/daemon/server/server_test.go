//go:build !windows
// +build !windows

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
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/client/octelium/commands/daemon/ipc"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

type testServer struct {
	srv  *Server
	c    daemonv1.MainServiceClient
	conn *grpc.ClientConn
	dir  string
}

func newTestServer(t *testing.T) *testServer {
	return newTestServerWithDir(t, t.TempDir())
}

func newTestServerWithDir(t *testing.T, dir string) *testServer {
	srv, err := New(&Opts{
		ListenAddress: path.Join(dir, "daemon.sock"),
		StateDir:      path.Join(dir, "state"),
	})
	assert.Nil(t, err)
	assert.Nil(t, srv.Run(context.Background()))

	conn, err := grpc.NewClient(fmt.Sprintf("passthrough:///%s", srv.opts.ListenAddress),
		grpc.WithTransportCredentials(ipc.NewTransportCredentials()),
		grpc.WithContextDialer(ipc.Dial))
	assert.Nil(t, err)

	ret := &testServer{
		srv:  srv,
		c:    daemonv1.NewMainServiceClient(conn),
		conn: conn,
		dir:  dir,
	}

	t.Cleanup(func() {
		ret.close()
	})

	return ret
}

func (s *testServer) close() {
	s.conn.Close()
	s.srv.Close()
}

func TestGetInfo(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	resp, err := srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	assert.Nil(t, err)

	assert.Equal(t, uint32(apiMajorVersion), resp.ApiMajorVersion)
	assert.Equal(t, uint32(apiMinorVersion), resp.ApiMinorVersion)
	assert.Equal(t, srv.srv.instanceID, resp.InstanceID)
	assert.Equal(t, fmt.Sprintf("%d", os.Getuid()), resp.Principal.Id)
}

func TestGetStatus(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
	assert.Nil(t, err)
	assert.Equal(t, 0, len(resp.Domains))
	assert.Equal(t, srv.srv.instanceID, resp.InstanceID)

	_, err = os.Stat(path.Join(srv.dir, "state", "users", fmt.Sprintf("%d", os.Getuid())))
	assert.Nil(t, err)
}

func TestUpdateDomainSettings(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	srv := newTestServerWithDir(t, dir)

	domain := "example.com"

	settings, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
		Settings: &daemonv1.DomainSettings{
			Domain:      domain,
			AutoConnect: true,
			ConnectionOptions: &daemonv1.ConnectionOptions{
				L3Mode:     daemonv1.ConnectionOptions_V6,
				TunnelMode: daemonv1.ConnectionOptions_QUICV0,
				Dns: &daemonv1.ConnectionOptions_DNS{
					Mode: daemonv1.ConnectionOptions_DNS_FULL,
				},
				ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
					Serve: []*daemonv1.ConnectionOptions_ServiceReference{
						{
							Name:      "svc1",
							Namespace: "ns1",
						},
					},
					Publish: []*daemonv1.ConnectionOptions_PublishedService{
						{
							Service: &daemonv1.ConnectionOptions_ServiceReference{
								Name: "svc2",
							},
							Port: 8080,
						},
					},
				},
			},
		},
	})
	assert.Nil(t, err)
	assert.Equal(t, domain, settings.Domain)
	assert.True(t, settings.AutoConnect)

	resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(resp.Domains))
	assert.Equal(t, domain, resp.Domains[0].Domain)
	assert.True(t, resp.Domains[0].Settings.AutoConnect)
	assert.Equal(t, daemonv1.ConnectionOptions_QUICV0,
		resp.Domains[0].Settings.ConnectionOptions.TunnelMode)
	assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT,
		resp.Domains[0].Authentication.State)
	assert.Equal(t, daemonv1.ConnectionStatus_DISCONNECTED,
		resp.Domains[0].Connection.State)

	srv.close()

	srv = newTestServerWithDir(t, dir)

	resp, err = srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(resp.Domains))
	assert.True(t, resp.Domains[0].Settings.AutoConnect)
	assert.Equal(t, daemonv1.ConnectionOptions_V6,
		resp.Domains[0].Settings.ConnectionOptions.L3Mode)
}

func TestUpdateDomainSettingsInvalid(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	{
		_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
			Settings: &daemonv1.DomainSettings{},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
			Settings: &daemonv1.DomainSettings{
				Domain: "not a domain/..",
			},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
			Settings: &daemonv1.DomainSettings{
				Domain: "example.com",
				ConnectionOptions: &daemonv1.ConnectionOptions{
					ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
						ServeAll: true,
						Serve: []*daemonv1.ConnectionOptions_ServiceReference{
							{
								Name: "svc1",
							},
						},
					},
				},
			},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	if os.Getuid() != 0 {
		_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
			Settings: &daemonv1.DomainSettings{
				Domain: "example.com",
				ConnectionOptions: &daemonv1.ConnectionOptions{
					ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
						Publish: []*daemonv1.ConnectionOptions_PublishedService{
							{
								Service: &daemonv1.ConnectionOptions_ServiceReference{
									Name: "svc1",
								},
								Port: 443,
							},
						},
					},
				},
			},
		})
		assert.True(t, grpcerr.IsPermissionDenied(err))
	}

	resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
	assert.Nil(t, err)
	assert.Equal(t, 0, len(resp.Domains))
}

func TestWatchStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := newTestServer(t)

	streamC, err := srv.c.WatchStatus(ctx, &daemonv1.WatchStatusRequest{})
	assert.Nil(t, err)

	resp, err := streamC.Recv()
	assert.Nil(t, err)
	assert.Equal(t, 0, len(resp.Domains))

	revision := resp.Revision

	_, err = srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
		Settings: &daemonv1.DomainSettings{
			Domain:      "example.com",
			AutoConnect: true,
		},
	})
	assert.Nil(t, err)

	resp, err = streamC.Recv()
	assert.Nil(t, err)
	assert.Greater(t, resp.Revision, revision)
	assert.Equal(t, 1, len(resp.Domains))
	assert.True(t, resp.Domains[0].Settings.AutoConnect)
}

func TestAuthenticateBrowser(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	domain := "example.com"

	op, err := srv.c.Authenticate(ctx, &daemonv1.AuthenticateRequest{
		Domain: domain,
		Type: &daemonv1.AuthenticateRequest_Browser_{
			Browser: &daemonv1.AuthenticateRequest_Browser{},
		},
	})
	assert.Nil(t, err)
	assert.Equal(t, daemonv1.Operation_AUTHENTICATE, op.Type)
	assert.Equal(t, daemonv1.Operation_WAITING_FOR_USER, op.State)
	assert.Equal(t, domain, op.Domain)

	loginURL, err := url.Parse(op.GetAction().GetOpenURL().GetUrl())
	assert.Nil(t, err)
	assert.Equal(t, "https", loginURL.Scheme)
	assert.Equal(t, domain, loginURL.Host)
	assert.Equal(t, "/login", loginURL.Path)
	assert.NotEmpty(t, loginURL.Query().Get("octelium_req"))

	{
		resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(resp.Domains))
		assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATING,
			resp.Domains[0].Authentication.State)
		assert.Equal(t, op.Id, resp.Domains[0].LastOperation.Id)
	}

	{
		_, err := srv.c.Authenticate(ctx, &daemonv1.AuthenticateRequest{
			Domain: domain,
			Type: &daemonv1.AuthenticateRequest_Browser_{
				Browser: &daemonv1.AuthenticateRequest_Browser{},
			},
		})
		assert.True(t, grpcerr.IsFailedPrecondition(err))
	}

	{
		getOp, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{
			Id: op.Id,
		})
		assert.Nil(t, err)
		assert.Equal(t, daemonv1.Operation_WAITING_FOR_USER, getOp.State)
	}

	{
		_, err := srv.c.CancelOperation(ctx, &daemonv1.CancelOperationRequest{
			Id: op.Id,
		})
		assert.Nil(t, err)
	}

	assert.Eventually(t, func() bool {
		getOp, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{
			Id: op.Id,
		})

		return err == nil && getOp.State == daemonv1.Operation_CANCELED
	}, 10*time.Second, 100*time.Millisecond)

	{
		resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		assert.Nil(t, err)
		assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT,
			resp.Domains[0].Authentication.State)
		assert.Nil(t, resp.Domains[0].LastError)
	}

	{
		newOp, err := srv.c.Authenticate(ctx, &daemonv1.AuthenticateRequest{
			Domain: domain,
			Type: &daemonv1.AuthenticateRequest_Browser_{
				Browser: &daemonv1.AuthenticateRequest_Browser{},
			},
		})
		assert.Nil(t, err)
		assert.NotEqual(t, op.Id, newOp.Id)
	}
}

func TestAuthenticateInvalid(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	{
		_, err := srv.c.Authenticate(ctx, &daemonv1.AuthenticateRequest{
			Domain: "example.com",
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.c.Authenticate(ctx, &daemonv1.AuthenticateRequest{
			Type: &daemonv1.AuthenticateRequest_Browser_{
				Browser: &daemonv1.AuthenticateRequest_Browser{},
			},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.c.Authenticate(ctx, &daemonv1.AuthenticateRequest{
			Domain: "example.com",
			Type: &daemonv1.AuthenticateRequest_AuthenticationToken_{
				AuthenticationToken: &daemonv1.AuthenticateRequest_AuthenticationToken{},
			},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.c.Authenticate(ctx, &daemonv1.AuthenticateRequest{
			Domain: "example.com",
			Type: &daemonv1.AuthenticateRequest_Assertion_{
				Assertion: &daemonv1.AuthenticateRequest_Assertion{},
			},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
}

func TestConnectUnauthenticated(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	domain := "example.com"

	{
		_, err := srv.c.Connect(ctx, &daemonv1.ConnectRequest{
			Domain: domain,
		})
		assert.True(t, grpcerr.IsNotFound(err))
	}

	_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
		Settings: &daemonv1.DomainSettings{
			Domain: domain,
		},
	})
	assert.Nil(t, err)

	{
		_, err := srv.c.Connect(ctx, &daemonv1.ConnectRequest{
			Domain: domain,
		})
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}
}

func TestUnknownDomain(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	{
		_, err := srv.c.Logout(ctx, &daemonv1.LogoutRequest{
			Domain: "example.com",
		})
		assert.True(t, grpcerr.IsNotFound(err))
	}
	{
		_, err := srv.c.GetAPICredential(ctx, &daemonv1.GetAPICredentialRequest{
			Domain: "example.com",
		})
		assert.True(t, grpcerr.IsNotFound(err))
	}
	{
		_, err := srv.c.DeleteDomain(ctx, &daemonv1.DeleteDomainRequest{
			Domain: "example.com",
		})
		assert.True(t, grpcerr.IsNotFound(err))
	}
	{
		_, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{
			Id: "8ffa1f5a-3b9f-4e3a-9a0e-6a1dcb2c4d7f",
		})
		assert.True(t, grpcerr.IsNotFound(err))
	}
}

func TestDisconnect(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	domain := "example.com"

	{
		_, err := srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{
			Domain: domain,
		})
		assert.True(t, grpcerr.IsNotFound(err))
	}

	_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
		Settings: &daemonv1.DomainSettings{
			Domain: domain,
		},
	})
	assert.Nil(t, err)

	op, err := srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{
		Domain: domain,
	})
	assert.Nil(t, err)
	assert.Equal(t, daemonv1.Operation_DISCONNECT, op.Type)
	assert.Equal(t, daemonv1.Operation_SUCCEEDED, op.State)
}

func TestLogoutAndDeleteDomain(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	domain := "example.com"

	_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
		Settings: &daemonv1.DomainSettings{
			Domain:      domain,
			AutoConnect: true,
		},
	})
	assert.Nil(t, err)

	op, err := srv.c.Logout(ctx, &daemonv1.LogoutRequest{
		Domain: domain,
	})
	assert.Nil(t, err)
	assert.Equal(t, daemonv1.Operation_LOGOUT, op.Type)

	assert.Eventually(t, func() bool {
		getOp, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{
			Id: op.Id,
		})

		return err == nil && getOp.State == daemonv1.Operation_SUCCEEDED
	}, 10*time.Second, 100*time.Millisecond)

	{
		resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(resp.Domains))
		assert.True(t, resp.Domains[0].Settings.AutoConnect)
		assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT,
			resp.Domains[0].Authentication.State)
	}

	_, err = srv.c.DeleteDomain(ctx, &daemonv1.DeleteDomainRequest{
		Domain: domain,
	})
	assert.Nil(t, err)

	{
		resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(resp.Domains))
	}
}
