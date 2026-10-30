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
	"net"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/apis/main/userv1"
	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/client/common/cliutils/vhome"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/client/octelium/commands/connect"
	"github.com/octelium/octelium/client/octelium/commands/daemon/ipc"
	"github.com/octelium/octelium/client/octelium/internal/testutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func newTestSocketPath(t *testing.T) string {
	dir, err := os.MkdirTemp("/tmp", "octelium-daemon-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.RemoveAll(dir)
	})

	return path.Join(dir, "daemon.sock")
}

func newTestServerWithDir(t *testing.T, dir string) *testServer {
	srv, err := New(&Opts{
		ListenAddress: newTestSocketPath(t),
		StateDir:      path.Join(dir, "state"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

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

func TestServerWithLongStateDir(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	srv := newTestServerWithDir(t, path.Join(t.TempDir(), strings.Repeat("a", 100)))

	resp, err := srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	if !assert.Nil(t, err) {
		return
	}
	assert.Equal(t, srv.srv.instanceID, resp.InstanceID)
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
		Domain: domain,
		Settings: &daemonv1.DomainSettings{
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
			Domain:   "not a domain/..",
			Settings: &daemonv1.DomainSettings{},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
			Domain:   "example",
			Settings: &daemonv1.DomainSettings{},
		})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}
	{
		_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
			Domain: "example.com",
			Settings: &daemonv1.DomainSettings{
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
			Domain: "example.com",
			Settings: &daemonv1.DomainSettings{
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
		Domain: "example.com",
		Settings: &daemonv1.DomainSettings{
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
	assert.True(t, op.Cancellable)
	assert.NotNil(t, op.GetAction().GetExpiresAt())

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
		Domain:   domain,
		Settings: &daemonv1.DomainSettings{},
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
		Domain:   domain,
		Settings: &daemonv1.DomainSettings{},
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
		Domain: domain,
		Settings: &daemonv1.DomainSettings{
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

	delOp, err := srv.c.DeleteDomain(ctx, &daemonv1.DeleteDomainRequest{
		Domain: domain,
	})
	assert.Nil(t, err)
	assert.Equal(t, daemonv1.Operation_DELETE, delOp.Type)
	assert.False(t, delOp.Cancellable)

	assert.Eventually(t, func() bool {
		getOp, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{
			Id: delOp.Id,
		})

		return err == nil && getOp.State == daemonv1.Operation_SUCCEEDED
	}, 10*time.Second, 100*time.Millisecond)

	{
		resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(resp.Domains))
	}

	{
		_, err := srv.c.DeleteDomain(ctx, &daemonv1.DeleteDomainRequest{
			Domain: domain,
		})
		assert.True(t, grpcerr.IsNotFound(err))
	}
}

func TestOwnerBinding(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("This test needs to run as a non-root OS user")
	}

	ctx := context.Background()
	dir := t.TempDir()

	srv, err := New(&Opts{
		ListenAddress: newTestSocketPath(t),
		StateDir:      path.Join(dir, "state"),
		OwnerID:       rootPrincipalID,
	})
	assert.Nil(t, err)
	assert.Nil(t, srv.Run(ctx))
	defer srv.Close()

	conn, err := grpc.NewClient(fmt.Sprintf("passthrough:///%s", srv.opts.ListenAddress),
		grpc.WithTransportCredentials(ipc.NewTransportCredentials()),
		grpc.WithContextDialer(ipc.Dial))
	assert.Nil(t, err)
	defer conn.Close()

	c := daemonv1.NewMainServiceClient(conn)

	{
		_, err := c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
		assert.True(t, grpcerr.IsPermissionDenied(err))
	}
	{
		_, err := c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		assert.True(t, grpcerr.IsPermissionDenied(err))
	}
}

func TestOwnerBindingFirstCaller(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	assert.Nil(t, srv.srv.principal)

	resp, err := srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	assert.Nil(t, err)
	assert.Equal(t, fmt.Sprintf("%d", os.Getuid()), resp.Principal.Id)

	p := srv.srv.principal
	assert.NotNil(t, p)

	_, err = srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
	assert.Nil(t, err)
	assert.Equal(t, p, srv.srv.principal)
}

func TestSingletonDaemon(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	_, err := srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	assert.Nil(t, err)

	other, err := New(&Opts{
		ListenAddress: srv.srv.opts.ListenAddress,
		StateDir:      path.Join(srv.dir, "state"),
	})
	assert.Nil(t, err)
	assert.NotNil(t, other.Run(ctx))

	_, err = srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	assert.Nil(t, err)
}

func TestDomainCanonicalization(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	settings, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
		Domain:   "EXAMPLE.Com.",
		Settings: &daemonv1.DomainSettings{},
	})
	assert.Nil(t, err)
	assert.Equal(t, "example.com", settings.Domain)

	_, err = srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
		Domain: "example.com",
		Settings: &daemonv1.DomainSettings{
			AutoConnect: true,
		},
	})
	assert.Nil(t, err)

	resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(resp.Domains))
	assert.Equal(t, "example.com", resp.Domains[0].Domain)
	assert.True(t, resp.Domains[0].Settings.AutoConnect)

	{
		op, err := srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{
			Domain: "Example.COM",
		})
		assert.Nil(t, err)
		assert.Equal(t, "example.com", op.Domain)
	}
}

func TestCancelOperation(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	domain := "example.com"

	_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
		Domain:   domain,
		Settings: &daemonv1.DomainSettings{},
	})
	assert.Nil(t, err)

	disconnectOp, err := srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{
		Domain: domain,
	})
	assert.Nil(t, err)
	assert.Equal(t, daemonv1.Operation_SUCCEEDED, disconnectOp.State)
	assert.False(t, disconnectOp.Cancellable)

	{
		op, err := srv.c.CancelOperation(ctx, &daemonv1.CancelOperationRequest{
			Id: disconnectOp.Id,
		})
		assert.Nil(t, err)
		assert.Equal(t, daemonv1.Operation_SUCCEEDED, op.State)
	}

	{
		_, err := srv.c.CancelOperation(ctx, &daemonv1.CancelOperationRequest{
			Id: "8ffa1f5a-3b9f-4e3a-9a0e-6a1dcb2c4d7f",
		})
		assert.True(t, grpcerr.IsNotFound(err))
	}

	authOp, err := srv.c.Authenticate(ctx, &daemonv1.AuthenticateRequest{
		Domain: domain,
		Type: &daemonv1.AuthenticateRequest_Browser_{
			Browser: &daemonv1.AuthenticateRequest_Browser{},
		},
	})
	assert.Nil(t, err)
	assert.True(t, authOp.Cancellable)

	logoutOp, err := srv.c.Logout(ctx, &daemonv1.LogoutRequest{
		Domain: domain,
	})
	assert.Nil(t, err)
	assert.Equal(t, daemonv1.Operation_LOGOUT, logoutOp.Type)
	assert.False(t, logoutOp.Cancellable)

	{
		op, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{
			Id: authOp.Id,
		})
		assert.Nil(t, err)
		assert.Equal(t, daemonv1.Operation_CANCELED, op.State)
		assert.Nil(t, op.Action)
	}

	assert.Eventually(t, func() bool {
		op, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{
			Id: logoutOp.Id,
		})

		return err == nil && op.State == daemonv1.Operation_SUCCEEDED
	}, 10*time.Second, 100*time.Millisecond)

	{
		d, err := srv.srv.principal.getDomain("other.example.com")
		assert.Nil(t, err)

		runningOp, err := d.beginOperation(daemonv1.Operation_DISCONNECT, nil)
		assert.Nil(t, err)

		_, err = srv.c.CancelOperation(ctx, &daemonv1.CancelOperationRequest{
			Id: runningOp.id,
		})
		assert.True(t, grpcerr.IsFailedPrecondition(err))

		op, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{
			Id: runningOp.id,
		})
		assert.Nil(t, err)
		assert.Equal(t, daemonv1.Operation_RUNNING, op.State)
		assert.False(t, op.Cancellable)
	}
}

func TestDeleteDomainWhileAuthenticating(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	domain := "example.com"

	authOp, err := srv.c.Authenticate(ctx, &daemonv1.AuthenticateRequest{
		Domain: domain,
		Type: &daemonv1.AuthenticateRequest_Browser_{
			Browser: &daemonv1.AuthenticateRequest_Browser{},
		},
	})
	assert.Nil(t, err)

	delOp, err := srv.c.DeleteDomain(ctx, &daemonv1.DeleteDomainRequest{
		Domain: domain,
	})
	assert.Nil(t, err)

	{
		op, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{
			Id: authOp.Id,
		})
		assert.Nil(t, err)
		assert.Equal(t, daemonv1.Operation_CANCELED, op.State)
	}

	{
		_, err := srv.c.Connect(ctx, &daemonv1.ConnectRequest{
			Domain: domain,
		})
		assert.NotNil(t, err)
	}

	assert.Eventually(t, func() bool {
		op, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{
			Id: delOp.Id,
		})

		return err == nil && op.State == daemonv1.Operation_SUCCEEDED
	}, 10*time.Second, 100*time.Millisecond)

	resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
	assert.Nil(t, err)
	assert.Equal(t, 0, len(resp.Domains))
}

func TestGetPrincipalDBDir(t *testing.T) {
	{
		srv, err := New(&Opts{
			StateDir: "/var/lib/octelium",
		})
		assert.Nil(t, err)

		ret, err := srv.getPrincipalDBDir(&ipc.Principal{
			ID:      "1000",
			HomeDir: "/home/usr1",
		})
		assert.Nil(t, err)
		assert.Equal(t, "/var/lib/octelium/users/1000", ret)
	}

	{
		t.Setenv("OCTELIUM_DAEMON_STATE_DIR", "")

		srv, err := New(&Opts{})
		assert.Nil(t, err)

		ret, err := srv.getPrincipalDBDir(&ipc.Principal{
			ID:      "1000",
			HomeDir: "/home/usr1",
		})
		assert.Nil(t, err)

		octeliumHome, err := vhome.GetOcteliumHomeFromUserHome("/home/usr1")
		assert.Nil(t, err)
		assert.Equal(t, octeliumHome, ret)

		_, err = srv.getPrincipalDBDir(&ipc.Principal{
			ID: "1000",
		})
		assert.NotNil(t, err)
	}
}

func TestReconcile(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	_, err := srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	assert.Nil(t, err)

	domain := "example.com"

	dbDir := path.Join(srv.dir, "state", "users", fmt.Sprintf("%d", os.Getuid()))

	setSessionToken := func() {
		dbC, err := db.Open(dbDir)
		assert.Nil(t, err)
		assert.Nil(t, dbC.SetSessionToken(domain, &authv1.SessionToken{
			AccessToken:           "at",
			RefreshToken:          "rt",
			ExpiresIn:             3600,
			RefreshTokenExpiresIn: 7200,
		}))
		assert.Nil(t, dbC.Close())
	}

	deleteDomain := func() {
		dbC, err := db.Open(dbDir)
		assert.Nil(t, err)
		assert.Nil(t, dbC.Delete(domain))
		assert.Nil(t, dbC.Close())
	}

	setSessionToken()

	{
		resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		assert.Nil(t, err)
		assert.Equal(t, 0, len(resp.Domains))
	}

	srv.srv.principal.reconcile()

	{
		resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(resp.Domains))
		assert.Equal(t, domain, resp.Domains[0].Domain)
		assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED,
			resp.Domains[0].Authentication.State)
	}

	deleteDomain()
	srv.srv.principal.reconcile()

	{
		resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		assert.Nil(t, err)
		assert.Equal(t, 1, len(resp.Domains))
		assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT,
			resp.Domains[0].Authentication.State)
	}

	setSessionToken()

	authOp, err := srv.c.Authenticate(ctx, &daemonv1.AuthenticateRequest{
		Domain: domain,
		Type: &daemonv1.AuthenticateRequest_Browser_{
			Browser: &daemonv1.AuthenticateRequest_Browser{},
		},
	})
	assert.Nil(t, err)

	srv.srv.principal.reconcile()

	{
		resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		assert.Nil(t, err)
		assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATING,
			resp.Domains[0].Authentication.State)
	}

	_, err = srv.c.CancelOperation(ctx, &daemonv1.CancelOperationRequest{
		Id: authOp.Id,
	})
	assert.Nil(t, err)
}

func TestReconcileAutoConnect(t *testing.T) {
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")

	ctx := context.Background()
	srv := newTestServer(t)

	_, err := srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	assert.Nil(t, err)

	p := srv.srv.principal

	_, err = srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
		Domain: "example.com",
		Settings: &daemonv1.DomainSettings{
			AutoConnect: true,
		},
	})
	assert.Nil(t, err)

	getState := func(domain string) *daemonv1.DomainState {
		resp, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
		assert.Nil(t, err)

		for _, itm := range resp.Domains {
			if itm.Domain == domain {
				return itm
			}
		}

		t.Fatalf("Could not find the domain %s", domain)
		return nil
	}

	{
		ds := getState("example.com")
		assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT, ds.Authentication.State)
		assert.Equal(t, daemonv1.ConnectionStatus_DISCONNECTED, ds.Connection.State)
		assert.Nil(t, ds.LastOperation)
	}

	dbDir := path.Join(srv.dir, "state", "users", fmt.Sprintf("%d", os.Getuid()))
	dbC, err := db.Open(dbDir)
	assert.Nil(t, err)

	for _, domain := range []string{"example.com", "other.com"} {
		assert.Nil(t, dbC.SetSessionToken(domain, &authv1.SessionToken{
			AccessToken:           "at",
			RefreshToken:          "rt",
			ExpiresIn:             3600,
			RefreshTokenExpiresIn: 7200,
		}))
	}
	assert.Nil(t, dbC.Close())

	p.reconcile()

	ds := getState("example.com")
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, ds.Authentication.State)
	assert.Equal(t, daemonv1.Operation_CONNECT, ds.LastOperation.GetType())
	assert.NotEqual(t, daemonv1.ConnectionStatus_DISCONNECTED, ds.Connection.State)

	{
		ds := getState("other.com")
		assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, ds.Authentication.State)
		assert.Equal(t, daemonv1.ConnectionStatus_DISCONNECTED, ds.Connection.State)
		assert.Nil(t, ds.LastOperation)
	}

	p.reconcile()

	assert.Equal(t, ds.LastOperation.Id, getState("example.com").LastOperation.GetId())
}

func TestReloadAuthenticationReadError(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	_, err := srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	assert.Nil(t, err)

	p := srv.srv.principal
	domain := "example.com"

	assert.Nil(t, p.dbC.SetSessionToken(domain, &authv1.SessionToken{
		AccessToken:           "at",
		RefreshToken:          "rt",
		ExpiresIn:             3600,
		RefreshTokenExpiresIn: 7200,
	}))

	d, err := p.getDomain(domain)
	assert.Nil(t, err)

	getAuthState := func() daemonv1.AuthenticationStatus_State {
		p.mu.Lock()
		defer p.mu.Unlock()
		return d.authState
	}

	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, getAuthState())

	dbPath := path.Join(srv.dir, "state", "users", fmt.Sprintf("%d", os.Getuid()), "octelium.db")
	stateBytes, err := os.ReadFile(dbPath)
	assert.Nil(t, err)

	assert.Nil(t, os.WriteFile(dbPath, []byte{0xff, 0xff, 0xff, 0xff}, 0600))

	_, err = p.dbC.Get(domain)
	assert.NotNil(t, err)
	assert.False(t, p.dbC.ErrorIsNotFound(err))

	p.update(func() {
		assert.False(t, d.reloadAuthentication())
	})
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, getAuthState())

	p.reconcile()
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, getAuthState())

	p.update(func() {
		d.authState = daemonv1.AuthenticationStatus_AUTHENTICATING
		assert.True(t, d.reloadAuthentication())
	})
	assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT, getAuthState())

	assert.Nil(t, os.WriteFile(dbPath, stateBytes, 0600))

	p.reconcile()
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, getAuthState())
}

func TestConnectEventHandlerAuthenticationRequired(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	_, err := srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	assert.Nil(t, err)

	p := srv.srv.principal
	domain := "example.com"

	assert.Nil(t, p.dbC.SetSessionToken(domain, &authv1.SessionToken{
		AccessToken:           "at",
		RefreshToken:          "rt",
		ExpiresIn:             3600,
		RefreshTokenExpiresIn: 7200,
	}))

	d, err := p.getDomain(domain)
	assert.Nil(t, err)

	op, err := d.beginOperation(daemonv1.Operation_CONNECT, func() {})
	assert.Nil(t, err)

	var isCanceled bool
	var stopErr error

	p.update(func() {
		d.connGen = 1
		d.connState = daemonv1.ConnectionStatus_CONNECTING
	})

	getState := func() (daemonv1.AuthenticationStatus_State, daemonv1.Error_Code) {
		p.mu.Lock()
		defer p.mu.Unlock()
		return d.authState, d.lastErr.GetCode()
	}

	handler := d.getConnectEventHandler(op, 1, &stopErr, func() {
		isCanceled = true
	})

	handler(&connect.Event{
		Type: connect.EventTypeConnecting,
		Err:  status.Error(codes.Unavailable, "unavailable"),
	})
	authState, errCode := getState()
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, authState)
	assert.Equal(t, daemonv1.Error_CLUSTER_UNREACHABLE, errCode)
	assert.False(t, isCanceled)
	assert.Nil(t, stopErr)

	assert.Nil(t, p.dbC.DeleteStaleSessionToken(domain, "rt"))

	handler(&connect.Event{
		Type: connect.EventTypeConnecting,
		Err:  errors.Wrap(authenticator.ErrAuthenticationRequired, "connect"),
	})
	authState, errCode = getState()
	assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT, authState)
	assert.Equal(t, daemonv1.Error_AUTHENTICATION_REQUIRED, errCode)
	assert.True(t, isCanceled)
	assert.ErrorIs(t, stopErr, authenticator.ErrAuthenticationRequired)
}

func TestConnectEventHandlerRenewAPICredential(t *testing.T) {
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "renewed")

	ctx := context.Background()
	srv := newTestServer(t)

	_, err := srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	assert.Nil(t, err)

	p := srv.srv.principal
	domain := "example.com"

	assert.Nil(t, p.dbC.SetSessionToken(domain, &authv1.SessionToken{
		AccessToken:           "at",
		RefreshToken:          "rt",
		ExpiresIn:             3600,
		RefreshTokenExpiresIn: 7200,
	}))

	d, err := p.getDomain(domain)
	assert.Nil(t, err)

	op, err := d.beginOperation(daemonv1.Operation_CONNECT, func() {})
	assert.Nil(t, err)

	var isCanceled bool
	var stopErr error

	p.update(func() {
		d.connGen = 1
		d.connState = daemonv1.ConnectionStatus_RECONNECTING
	})

	handler := d.getConnectEventHandler(op, 1, &stopErr, func() {
		isCanceled = true
	})

	getState := func() (daemonv1.AuthenticationStatus_State, *daemonv1.Error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		return d.authState, d.lastErr
	}

	failConnect := func() {
		handler(&connect.Event{
			Type: connect.EventTypeReconnecting,
			Err:  status.Error(codes.Unauthenticated, "Octelium: Unauthenticated"),
		})
	}

	failConnect()

	authState, lastErr := getState()
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, authState)
	assert.Nil(t, lastErr)
	assert.False(t, isCanceled)
	assert.Nil(t, stopErr)

	handler(&connect.Event{
		Type:       connect.EventTypeConnected,
		Connection: &cliconfigv1.Connection{},
	})

	for range maxConnectAuthFailures {
		failConnect()
		assert.False(t, isCanceled)
		assert.Nil(t, stopErr)
	}

	failConnect()

	authState, lastErr = getState()
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, authState)
	assert.Equal(t, daemonv1.Error_AUTHENTICATION_REQUIRED, lastErr.GetCode())
	assert.True(t, isCanceled)
	assert.True(t, grpcerr.IsUnauthenticated(stopErr))
}

func TestConnectEventHandlerRenewRejected(t *testing.T) {
	ctx := context.Background()
	srv := newTestServer(t)

	_, err := srv.c.GetInfo(ctx, &daemonv1.GetInfoRequest{})
	assert.Nil(t, err)

	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "unused")

	p := srv.srv.principal
	domain := "example.com"

	assert.Nil(t, p.dbC.SetSessionToken(domain, &authv1.SessionToken{
		AccessToken:           "at",
		RefreshToken:          "rt",
		ExpiresIn:             3600,
		RefreshTokenExpiresIn: 7200,
	}))

	d, err := p.getDomain(domain)
	assert.Nil(t, err)

	op, err := d.beginOperation(daemonv1.Operation_CONNECT, func() {})
	assert.Nil(t, err)

	var isCanceled bool
	var stopErr error

	p.update(func() {
		d.connGen = 1
		d.connState = daemonv1.ConnectionStatus_CONNECTING
	})

	handler := d.getConnectEventHandler(op, 1, &stopErr, func() {
		isCanceled = true
	})

	handler(&connect.Event{
		Type: connect.EventTypeConnecting,
		Err:  status.Error(codes.Unauthenticated, "Octelium: Unauthenticated"),
	})

	assert.True(t, isCanceled)
	assert.True(t, grpcerr.IsUnauthenticated(stopErr))
}

func TestGetAPICredentialRenew(t *testing.T) {
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "renewed")

	ctx := context.Background()
	srv := newTestServer(t)

	domain := "example.com"

	_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
		Domain:   domain,
		Settings: &daemonv1.DomainSettings{},
	})
	assert.Nil(t, err)

	{
		_, err := srv.c.GetAPICredential(ctx, &daemonv1.GetAPICredentialRequest{
			Domain: domain,
			Renew:  true,
		})
		assert.True(t, grpcerr.IsUnauthenticated(err))
	}

	assert.Nil(t, srv.srv.principal.dbC.SetSessionToken(domain, &authv1.SessionToken{
		AccessToken:           "at",
		RefreshToken:          "rt",
		ExpiresIn:             3600,
		RefreshTokenExpiresIn: 7200,
	}))
	srv.srv.principal.reconcile()

	{
		resp, err := srv.c.GetAPICredential(ctx, &daemonv1.GetAPICredentialRequest{
			Domain: domain,
			Renew:  true,
		})
		assert.Nil(t, err)
		assert.Equal(t, "renewed", resp.AccessToken)
	}
}

type testDaemonClusterAPI struct {
	userv1.UnimplementedMainServiceServer
	connectFn func(userv1.MainService_ConnectServer) error
}

func (s *testDaemonClusterAPI) Connect(stream userv1.MainService_ConnectServer) error {
	return s.connectFn(stream)
}

func startTestDaemonClusterAPI(t *testing.T, srv *testDaemonClusterAPI) {
	t.Helper()
	lis, err := net.Listen("unix", newTestSocketPath(t))
	require.NoError(t, err)
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", lis.Addr().String())
	t.Setenv("OCTELIUM_DEV", "false")
	t.Setenv("OCTELIUM_PRODUCTION", "true")
	grpcSrv := grpc.NewServer()
	userv1.RegisterMainServiceServer(grpcSrv, srv)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.Stop)
}

func testDaemonInitialState() *userv1.ConnectResponse {
	return &userv1.ConnectResponse{
		CreatedAt: timestamppb.Now(),
		Event: &userv1.ConnectResponse_State{State: &userv1.ConnectionState{
			L3Mode: userv1.ConnectionState_V4, X25519Key: make([]byte, 32),
			Addresses: []*metav1.DualStackNetwork{{V4: "100.64.0.2/32"}},
			Cidr:      &metav1.DualStackNetwork{V4: "100.64.0.0/16"},
		}},
	}
}

func authenticateTestDaemonDomain(t *testing.T, srv *testServer) {
	t.Helper()
	_, err := srv.c.GetInfo(t.Context(), &daemonv1.GetInfoRequest{})
	require.NoError(t, err)
	require.NoError(t, srv.srv.principal.dbC.SetSessionToken("example.com", &authv1.SessionToken{
		AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 3600, RefreshTokenExpiresIn: 7200,
	}))
	srv.srv.principal.reconcile()
}

func TestDaemonConnectRecoversStreamAndDisconnectsOverIPC(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	var attempts atomic.Int32
	drop := make(chan struct{})
	startTestDaemonClusterAPI(t, &testDaemonClusterAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(testDaemonInitialState()); err != nil {
			return err
		}
		if attempt == 1 {
			select {
			case <-drop:
				return status.Error(codes.Unavailable, "API server restart")
			case <-stream.Context().Done():
				return nil
			}
		}
		<-stream.Context().Done()
		return nil
	}})
	srv := newTestServer(t)
	authenticateTestDaemonDomain(t, srv)
	reserved, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := reserved.LocalAddr().String()
	require.NoError(t, reserved.Close())
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	op, err := srv.c.Connect(ctx, &daemonv1.ConnectRequest{
		Domain: "example.com", Options: &daemonv1.ConnectionOptions{
			L3Mode: daemonv1.ConnectionOptions_V4, ImplementationMode: daemonv1.ConnectionOptions_GVISOR,
			Dns: &daemonv1.ConnectionOptions_DNS{Mode: daemonv1.ConnectionOptions_DNS_DISABLED, LocalServerListenAddress: addr},
		},
	})
	require.NoError(t, err)
	waitState := func(want daemonv1.ConnectionStatus_State) *daemonv1.DomainState {
		t.Helper()
		var got *daemonv1.DomainState
		require.Eventually(t, func() bool {
			snapshot, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
			if err != nil || len(snapshot.Domains) != 1 {
				return false
			}
			got = snapshot.Domains[0]
			return got.Connection.State == want
		}, 8*time.Second, 10*time.Millisecond)
		return got
	}
	first := waitState(daemonv1.ConnectionStatus_CONNECTED)
	require.NotNil(t, first.Connection.ConnectedAt)
	assert.Equal(t, daemonv1.Operation_SUCCEEDED, first.LastOperation.State)
	close(drop)
	reconnecting := waitState(daemonv1.ConnectionStatus_RECONNECTING)
	assert.Equal(t, daemonv1.Error_CLUSTER_UNREACHABLE, reconnecting.LastError.Code)
	assert.True(t, reconnecting.LastError.Retryable)
	recovered := waitState(daemonv1.ConnectionStatus_CONNECTED)
	assert.Nil(t, recovered.LastError)
	assert.Equal(t, first.Connection.ConnectedAt.AsTime(), recovered.Connection.ConnectedAt.AsTime())
	assert.Equal(t, int32(2), attempts.Load())
	disconnect, err := srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		got, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{Id: disconnect.Id})
		return err == nil && got.State == daemonv1.Operation_SUCCEEDED
	}, 5*time.Second, 10*time.Millisecond)
	stopped := waitState(daemonv1.ConnectionStatus_DISCONNECTED)
	assert.Nil(t, stopped.Connection.ConnectedAt)
	assert.Nil(t, stopped.Connection.Options)
	assert.Nil(t, stopped.LastError)
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, stopped.Authentication.State)
	finished, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{Id: op.Id})
	require.NoError(t, err)
	assert.Equal(t, daemonv1.Operation_SUCCEEDED, finished.State)
	_, err = srv.srv.principal.dbC.GetConnectionCleanup("example.com")
	assert.True(t, srv.srv.principal.dbC.ErrorIsNotFound(err))
}

func TestDaemonConnectOutlivesRPCCancellation(t *testing.T) {
	received, stopped := make(chan struct{}), make(chan struct{})
	startTestDaemonClusterAPI(t, &testDaemonClusterAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		close(received)
		<-stream.Context().Done()
		close(stopped)
		return nil
	}})
	srv := newTestServer(t)
	authenticateTestDaemonDomain(t, srv)
	ctx, cancel := context.WithCancel(t.Context())
	op, err := srv.c.Connect(ctx, &daemonv1.ConnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	cancel()
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("canceling the completed Connect RPC must not cancel its background operation")
	}
	got, err := srv.c.GetOperation(t.Context(), &daemonv1.GetOperationRequest{Id: op.Id})
	require.NoError(t, err)
	assert.Equal(t, daemonv1.Operation_RUNNING, got.State)
	assert.True(t, got.Cancellable)
	_, err = srv.c.CancelOperation(t.Context(), &daemonv1.CancelOperationRequest{Id: op.Id})
	require.NoError(t, err)
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("canceling the operation must close its API stream")
	}
	require.Eventually(t, func() bool {
		state, err := srv.c.GetStatus(t.Context(), &daemonv1.GetStatusRequest{})
		return err == nil && len(state.Domains) == 1 && state.Domains[0].Connection.State == daemonv1.ConnectionStatus_DISCONNECTED
	}, time.Second, 10*time.Millisecond)
}

func TestDaemonWatchStatusBroadcastsAndReleasesCanceledWatchers(t *testing.T) {
	srv := newTestServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var streams []daemonv1.MainService_WatchStatusClient
	var cancels []context.CancelFunc
	for range 4 {
		watchCtx, cancel := context.WithCancel(ctx)
		cancels = append(cancels, cancel)
		stream, err := srv.c.WatchStatus(watchCtx, &daemonv1.WatchStatusRequest{})
		require.NoError(t, err)
		_, err = stream.Recv()
		require.NoError(t, err)
		streams = append(streams, stream)
	}
	_, err := srv.c.UpdateDomainSettings(ctx, &daemonv1.UpdateDomainSettingsRequest{
		Domain: "example.com", Settings: &daemonv1.DomainSettings{},
	})
	require.NoError(t, err)
	for i, stream := range streams {
		state, err := stream.Recv()
		require.NoError(t, err)
		require.Len(t, state.Domains, 1)
		assert.Equal(t, "example.com", state.Domains[0].Domain)
		cancels[i]()
		_, err = stream.Recv()
		assert.Equal(t, codes.Canceled, status.Code(err))
	}
	require.Eventually(t, func() bool {
		p := srv.srv.principal
		p.mu.Lock()
		defer p.mu.Unlock()
		return len(p.watchers) == 0
	}, time.Second, 10*time.Millisecond)
}

func TestDaemonStateUpdateFailureRecoversOverIPC(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	var attempts atomic.Int32
	ready := make(chan struct{})
	startTestDaemonClusterAPI(t, &testDaemonClusterAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
		attempt := attempts.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		initial := testDaemonInitialState()
		initial.CreatedAt = nil
		if attempt > 1 {
			initial.GetState().Addresses[0].V4 = "100.64.0.3/32"
		}
		if err := stream.Send(initial); err != nil {
			return err
		}
		if attempt == 1 {
			select {
			case <-ready:
			case <-stream.Context().Done():
				return nil
			}
			bad := testDaemonInitialState()
			bad.CreatedAt = nil
			bad.GetState().Addresses[0].V4 = "invalid"
			if err := stream.Send(bad); err != nil {
				return err
			}
		}
		<-stream.Context().Done()
		return nil
	}})
	srv := newTestServer(t)
	authenticateTestDaemonDomain(t, srv)
	reserved, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := reserved.LocalAddr().String()
	require.NoError(t, reserved.Close())
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	op, err := srv.c.Connect(ctx, &daemonv1.ConnectRequest{
		Domain: "example.com", Options: &daemonv1.ConnectionOptions{
			L3Mode: daemonv1.ConnectionOptions_V4, ImplementationMode: daemonv1.ConnectionOptions_GVISOR,
			Dns: &daemonv1.ConnectionOptions_DNS{Mode: daemonv1.ConnectionOptions_DNS_DISABLED, LocalServerListenAddress: addr},
		},
	})
	require.NoError(t, err)
	waitState := func(want daemonv1.ConnectionStatus_State) *daemonv1.DomainState {
		t.Helper()
		var got *daemonv1.DomainState
		require.Eventually(t, func() bool {
			snapshot, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
			if err != nil || len(snapshot.Domains) != 1 {
				return false
			}
			got = snapshot.Domains[0]
			return got.Connection.State == want
		}, 8*time.Second, 10*time.Millisecond)
		return got
	}
	first := waitState(daemonv1.ConnectionStatus_CONNECTED)
	require.NotNil(t, first.Connection.ConnectedAt)
	close(ready)
	reconnecting := waitState(daemonv1.ConnectionStatus_RECONNECTING)
	require.NotNil(t, reconnecting.LastError)
	assert.Equal(t, daemonv1.Error_CONNECTION_FAILED, reconnecting.LastError.Code)
	assert.True(t, reconnecting.LastError.Retryable)
	assert.Contains(t, reconnecting.LastError.Message, "Could not apply connection state")
	assert.NotContains(t, reconnecting.LastError.Message, "Abruptly disconnected by API Server")
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, reconnecting.Authentication.State)
	assert.Equal(t, daemonv1.Operation_SUCCEEDED, reconnecting.LastOperation.State)
	recovered := waitState(daemonv1.ConnectionStatus_CONNECTED)
	assert.Equal(t, int32(2), attempts.Load())
	assert.Nil(t, recovered.LastError)
	assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, recovered.Authentication.State)
	assert.Equal(t, first.Connection.ConnectedAt.AsTime(), recovered.Connection.ConnectedAt.AsTime())
	assert.Equal(t, daemonv1.ConnectionOptions_GVISOR, recovered.Connection.Options.ImplementationMode)
	disconnect, err := srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		got, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{Id: disconnect.Id})
		return err == nil && got.State == daemonv1.Operation_SUCCEEDED
	}, 5*time.Second, 10*time.Millisecond)
	waitState(daemonv1.ConnectionStatus_DISCONNECTED)
	finished, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{Id: op.Id})
	require.NoError(t, err)
	assert.Equal(t, daemonv1.Operation_SUCCEEDED, finished.State)
	_, err = srv.srv.principal.dbC.GetConnectionCleanup("example.com")
	assert.True(t, srv.srv.principal.dbC.ErrorIsNotFound(err))
}

type testDaemonPublishedServiceAPI struct {
	testDaemonClusterAPI
	getFn func(context.Context, *metav1.GetOptions) (*userv1.Service, error)
}

func (s *testDaemonPublishedServiceAPI) GetService(ctx context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
	return s.getFn(ctx, req)
}

func TestDaemonMissingPublicationLifecycleOverIPC(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	for _, scenario := range []string{"created-while-connected", "disconnect-during-lookup"} {
		t.Run(scenario, func(t *testing.T) {
			var calls, attempts atomic.Int32
			var available atomic.Bool
			lookupStarted, lookupCanceled := make(chan struct{}, 1), make(chan struct{}, 1)
			api := &testDaemonPublishedServiceAPI{
				testDaemonClusterAPI: testDaemonClusterAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
					attempts.Add(1)
					req, err := stream.Recv()
					if err != nil {
						return err
					}
					assert.Empty(t, req.GetInitialize().PublishedServices)
					if err := stream.Send(testDaemonInitialState()); err != nil {
						return err
					}
					<-stream.Context().Done()
					return stream.Context().Err()
				}},
				getFn: func(ctx context.Context, req *metav1.GetOptions) (*userv1.Service, error) {
					call := calls.Add(1)
					assert.Equal(t, "late.default", req.Name)
					_, ok := ctx.Deadline()
					assert.True(t, ok)
					if call > 1 && scenario == "disconnect-during-lookup" {
						lookupStarted <- struct{}{}
						<-ctx.Done()
						lookupCanceled <- struct{}{}
						return nil, status.FromContextError(ctx.Err()).Err()
					}
					if !available.Load() {
						return nil, status.Error(codes.NotFound, "Service not found")
					}
					return &userv1.Service{
						Metadata: &metav1.Metadata{Name: req.Name},
						Spec:     &userv1.Service_Spec{Type: userv1.Service_Spec_TCP, Port: 8080},
						Status:   &userv1.Service_Status{Namespace: "default"},
					}, nil
				},
			}
			lis, err := net.Listen("unix", newTestSocketPath(t))
			require.NoError(t, err)
			t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", lis.Addr().String())
			t.Setenv("OCTELIUM_DEV", "false")
			t.Setenv("OCTELIUM_PRODUCTION", "true")
			grpcSrv := grpc.NewServer()
			userv1.RegisterMainServiceServer(grpcSrv, api)
			go grpcSrv.Serve(lis)
			t.Cleanup(grpcSrv.Stop)
			srv := newTestServer(t)
			authenticateTestDaemonDomain(t, srv)
			reserved, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			addr := reserved.Addr().String()
			port := uint32(reserved.Addr().(*net.TCPAddr).Port)
			require.NoError(t, reserved.Close())
			dnsSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			dnsAddr := dnsSocket.LocalAddr().String()
			require.NoError(t, dnsSocket.Close())
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			op, err := srv.c.Connect(ctx, &daemonv1.ConnectRequest{
				Domain: "example.com", Options: &daemonv1.ConnectionOptions{
					L3Mode: daemonv1.ConnectionOptions_V4, ImplementationMode: daemonv1.ConnectionOptions_GVISOR,
					Dns: &daemonv1.ConnectionOptions_DNS{Mode: daemonv1.ConnectionOptions_DNS_DISABLED, LocalServerListenAddress: dnsAddr},
					ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
						Publish: []*daemonv1.ConnectionOptions_PublishedService{{
							Service: &daemonv1.ConnectionOptions_ServiceReference{Name: "late"}, Address: "127.0.0.1", Port: port,
						}},
					},
				},
			})
			require.NoError(t, err)
			var first *daemonv1.DomainState
			require.Eventually(t, func() bool {
				snapshot, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
				if err != nil || len(snapshot.Domains) != 1 {
					return false
				}
				first = snapshot.Domains[0]
				return first.Connection.State == daemonv1.ConnectionStatus_CONNECTED
			}, 5*time.Second, 10*time.Millisecond)
			assert.Equal(t, daemonv1.Operation_SUCCEEDED, first.LastOperation.State)
			assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, first.Authentication.State)
			assert.Nil(t, first.LastError)
			if scenario == "created-while-connected" {
				available.Store(true)
				require.Eventually(t, func() bool {
					probe, err := net.Listen("tcp", addr)
					if err == nil {
						probe.Close()
						return false
					}
					return errors.Is(err, syscall.EADDRINUSE)
				}, 8*time.Second, 20*time.Millisecond)
			} else {
				select {
				case <-lookupStarted:
				case <-time.After(8 * time.Second):
					t.Fatal("the pending publication was not retried")
				}
			}
			snapshot, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
			require.NoError(t, err)
			require.Len(t, snapshot.Domains, 1)
			current := snapshot.Domains[0]
			assert.Equal(t, daemonv1.ConnectionStatus_CONNECTED, current.Connection.State)
			assert.Equal(t, first.Connection.ConnectedAt.AsTime(), current.Connection.ConnectedAt.AsTime())
			assert.Nil(t, current.LastError)
			assert.Len(t, current.Connection.Options.ServiceOptions.Publish, 1)
			assert.Equal(t, int32(1), attempts.Load())
			started := time.Now()
			disconnect, err := srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				got, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{Id: disconnect.Id})
				return err == nil && got.State == daemonv1.Operation_SUCCEEDED
			}, 3*time.Second, 10*time.Millisecond)
			assert.Less(t, time.Since(started), 3*time.Second)
			if scenario == "disconnect-during-lookup" {
				select {
				case <-lookupCanceled:
				case <-time.After(time.Second):
					t.Error("disconnect did not cancel the pending Service RPC")
				}
			}
			finished, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{Id: op.Id})
			require.NoError(t, err)
			assert.Equal(t, daemonv1.Operation_SUCCEEDED, finished.State)
			_, err = srv.srv.principal.dbC.GetConnectionCleanup("example.com")
			assert.True(t, srv.srv.principal.dbC.ErrorIsNotFound(err))
			probe, err := net.Listen("tcp", addr)
			require.NoError(t, err)
			require.NoError(t, probe.Close())
		})
	}
}

func TestDaemonServedListenerRecoveryAndDisconnectOverIPC(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this test forces the Linux gVisor implementation")
	}
	for _, recoverListener := range []bool{false, true} {
		t.Run(fmt.Sprintf("recover-%t", recoverListener), func(t *testing.T) {
			peer := testutils.NewWGPeer(t)
			backend, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			done := make(chan struct{})
			go func() {
				defer close(done)
				buf := make([]byte, 1024)
				for {
					n, addr, err := backend.ReadFrom(buf)
					if err != nil {
						return
					}
					backend.WriteTo(buf[:n], addr)
				}
			}()
			t.Cleanup(func() { backend.Close(); <-done })
			blocker := peer.ReserveUDP("100.64.0.3", 22000)
			t.Cleanup(func() { blocker.Close() })
			addr := blocker.LocalAddr().String()
			port := uint32(blocker.LocalAddr().(*net.UDPAddr).Port)
			gatewayReady := make(chan struct{})
			var attempts atomic.Int32
			startTestDaemonClusterAPI(t, &testDaemonClusterAPI{connectFn: func(stream userv1.MainService_ConnectServer) error {
				attempts.Add(1)
				req, err := stream.Recv()
				if err != nil {
					return err
				}
				assert.True(t, req.GetInitialize().GetServiceOptions().GetServeAll())
				initial := testDaemonInitialState()
				initial.GetState().ServiceOptions = &userv1.ConnectionState_ServiceOptions{Services: []*userv1.HostedService{{
					Name: "served.default", Port: port, L4Type: userv1.HostedService_UDP,
					Address:  &metav1.DualStackIP{Ipv4: "100.64.0.3"},
					Upstream: &userv1.HostedService_Upstream{Host: "127.0.0.1", Port: int32(backend.LocalAddr().(*net.UDPAddr).Port)},
				}}}
				peer.Configure(initial.GetState())
				if err := stream.Send(initial); err != nil {
					return err
				}
				select {
				case <-gatewayReady:
				case <-stream.Context().Done():
					return nil
				}
				if err := peer.SendGateway(stream); err != nil {
					return err
				}
				for {
					select {
					case msg := <-peer.Updates:
						if err := stream.Send(msg); err != nil {
							return err
						}
					case <-stream.Context().Done():
						return nil
					}
				}
			}})
			srv := newTestServer(t)
			authenticateTestDaemonDomain(t, srv)
			dnsSocket, err := net.ListenPacket("udp", "127.0.0.1:0")
			require.NoError(t, err)
			dnsAddr := dnsSocket.LocalAddr().String()
			require.NoError(t, dnsSocket.Close())
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			_, err = srv.c.Connect(ctx, &daemonv1.ConnectRequest{Domain: "example.com", Options: &daemonv1.ConnectionOptions{
				L3Mode: daemonv1.ConnectionOptions_V4, ImplementationMode: daemonv1.ConnectionOptions_GVISOR,
				Dns:            &daemonv1.ConnectionOptions_DNS{Mode: daemonv1.ConnectionOptions_DNS_DISABLED, LocalServerListenAddress: dnsAddr},
				ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{ServeAll: true},
			}})
			require.NoError(t, err)
			var first *daemonv1.DomainState
			require.Eventually(t, func() bool {
				state, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
				if err != nil || len(state.Domains) != 1 {
					return false
				}
				first = state.Domains[0]
				return first.Connection.State == daemonv1.ConnectionStatus_CONNECTED
			}, 5*time.Second, 10*time.Millisecond)
			close(gatewayReady)
			if recoverListener {
				require.NoError(t, blocker.Close())
				require.Eventually(t, func() bool {
					return peer.RoundTrip(addr, []byte("served through daemon IPC"))
				}, 6*time.Second, 10*time.Millisecond)
			}
			state, err := srv.c.GetStatus(ctx, &daemonv1.GetStatusRequest{})
			require.NoError(t, err)
			require.Len(t, state.Domains, 1)
			current := state.Domains[0]
			assert.Equal(t, daemonv1.ConnectionStatus_CONNECTED, current.Connection.State)
			assert.Equal(t, first.Connection.ConnectedAt.AsTime(), current.Connection.ConnectedAt.AsTime())
			assert.Nil(t, current.LastError)
			assert.Equal(t, int32(1), attempts.Load())
			operation, err := srv.c.Disconnect(ctx, &daemonv1.DisconnectRequest{Domain: "example.com"})
			require.NoError(t, err)
			require.Eventually(t, func() bool {
				op, err := srv.c.GetOperation(ctx, &daemonv1.GetOperationRequest{Id: operation.Id})
				return err == nil && op.State == daemonv1.Operation_SUCCEEDED
			}, 3*time.Second, 10*time.Millisecond)
			if !recoverListener {
				require.NoError(t, blocker.Close())
			}
			assert.False(t, peer.RoundTrip(addr, []byte("served through daemon IPC")), "disconnect must stop forwarding and retrying the served listener")
		})
	}
}
