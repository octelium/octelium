//go:build linux

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
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/client/cliconfigv1"
	"github.com/octelium/octelium/apis/client/daemonv1"
	"github.com/octelium/octelium/apis/client/mobilev1"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/client/common/cliutils/deviceinfo"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/client/octelium/commands/connect"
	"github.com/octelium/octelium/pkg/common/clientlogin"
	"github.com/octelium/octelium/pkg/common/opkce"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func doCall(t *testing.T, c *Client, method string, req, resp pbutils.Message) error {
	reqBytes, err := pbutils.Marshal(req)
	assert.Nil(t, err)

	respBytes, err := c.Call(context.Background(), method, reqBytes)
	if err != nil {
		return err
	}

	assert.Nil(t, pbutils.Unmarshal(respBytes, resp))
	return nil
}

func getTestStatus(t *testing.T, c *Client) *daemonv1.GetStatusResponse {
	ret := &daemonv1.GetStatusResponse{}
	assert.Nil(t, doCall(t, c, "GetStatus", &daemonv1.GetStatusRequest{}, ret))
	return ret
}

func getTestDomainState(t *testing.T, c *Client, domain string) *daemonv1.DomainState {
	for _, d := range getTestStatus(t, c).Domains {
		if d.Domain == domain {
			return d
		}
	}

	return nil
}

func setTestSessionToken(t *testing.T, cfg *mobilev1.Config, domain string) {
	dbC, err := db.OpenWithOpts(&db.Opts{
		Path:          cfg.StateDir,
		EncryptionKey: cfg.StateKey,
	})
	assert.Nil(t, err)

	assert.Nil(t, dbC.SetSessionToken(domain, &authv1.SessionToken{
		AccessToken:           utilrand.GetRandomString(32),
		RefreshToken:          utilrand.GetRandomString(32),
		RefreshTokenExpiresIn: 3600,
	}))
}

func deleteTestSessionToken(t *testing.T, cfg *mobilev1.Config, domain string) {
	dbC, err := db.OpenWithOpts(&db.Opts{
		Path:          cfg.StateDir,
		EncryptionKey: cfg.StateKey,
	})
	assert.Nil(t, err)

	assert.Nil(t, dbC.DeleteSessionToken(domain))
}

func getLoginChallenge(t *testing.T, loginURL string) []byte {
	u, err := url.Parse(loginURL)
	assert.Nil(t, err)

	reqBytes, err := base64.RawURLEncoding.DecodeString(u.Query().Get("octelium_req"))
	assert.Nil(t, err)

	req := &authv1.ClientLoginRequest{}
	assert.Nil(t, pbutils.Unmarshal(reqBytes, req))

	return req.CodeChallenge
}

func getCallbackURL(t *testing.T, codeChallenge []byte) string {
	respBytes, err := pbutils.Marshal(&authv1.ClientLoginResponse{
		AuthenticationToken: utilrand.GetRandomString(32),
		CodeChallenge:       codeChallenge,
	})
	assert.Nil(t, err)

	return fmt.Sprintf("%s?octelium_response=%s",
		clientlogin.AppCallbackURL, base64.RawURLEncoding.EncodeToString(respBytes))
}

func TestNew(t *testing.T) {

	invalidFns := []func(cfg *mobilev1.Config) *mobilev1.Config{
		func(cfg *mobilev1.Config) *mobilev1.Config {
			return nil
		},
		func(cfg *mobilev1.Config) *mobilev1.Config {
			cfg.Platform = mobilev1.Config_PLATFORM_UNSPECIFIED
			return cfg
		},
		func(cfg *mobilev1.Config) *mobilev1.Config {
			cfg.Platform = mobilev1.Config_Platform(100)
			return cfg
		},
		func(cfg *mobilev1.Config) *mobilev1.Config {
			cfg.StateDir = ""
			return cfg
		},
		func(cfg *mobilev1.Config) *mobilev1.Config {
			cfg.StateKey = nil
			return cfg
		},
		func(cfg *mobilev1.Config) *mobilev1.Config {
			cfg.StateKey = utilrand.GetRandomBytesMust(16)
			return cfg
		},
		func(cfg *mobilev1.Config) *mobilev1.Config {
			cfg.LogLevel = mobilev1.Log_Level(100)
			return cfg
		},
		func(cfg *mobilev1.Config) *mobilev1.Config {
			cfg.Device = nil
			return cfg
		},
		func(cfg *mobilev1.Config) *mobilev1.Config {
			cfg.Device.Id = ""
			return cfg
		},
	}

	for i, fn := range invalidFns {
		_, err := New(fn(newTestConfig(t)), newFakeHost())
		assert.True(t, grpcerr.IsInvalidArg(err), "idx: %d", i)
	}

	{
		_, err := New(newTestConfig(t), nil)
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		cfg := newTestConfig(t)
		assert.Nil(t, os.WriteFile(filepath.Join(cfg.StateDir, "octelium.db"), []byte("invalid"), 0600))

		_, err := New(cfg, newFakeHost())
		assert.NotNil(t, err)
	}

	{
		cfg := newTestConfig(t)
		cfg.Platform = mobilev1.Config_IOS
		cfg.LogLevel = mobilev1.Log_DEBUG

		c, err := New(cfg, newFakeHost())
		assert.Nil(t, err)

		resp := &mobilev1.GetInfoResponse{}
		assert.Nil(t, doCall(t, c, "GetInfo", &mobilev1.GetInfoRequest{}, resp))
		assert.Equal(t, uint32(apiMajorVersion), resp.ApiMajorVersion)
		assert.Equal(t, uint32(apiMinorVersion), resp.ApiMinorVersion)
		assert.Equal(t, ldflags.SemVer, resp.Version)
		assert.Equal(t, c.instanceID, resp.InstanceID)
		assert.Equal(t, clientlogin.AppCallbackURL, resp.AuthenticationCallbackURL)

		assert.Nil(t, c.Close())
		assert.Nil(t, c.Close())
	}
}

func TestSetMemoryLimit(t *testing.T) {
	prev := debug.SetMemoryLimit(math.MaxInt64)
	t.Cleanup(func() {
		debug.SetMemoryLimit(prev)
	})

	t.Setenv("GOMEMLIMIT", "")

	setMemoryLimit(mobilev1.Config_ANDROID)
	assert.Equal(t, int64(math.MaxInt64), debug.SetMemoryLimit(-1))

	setMemoryLimit(mobilev1.Config_IOS)
	assert.Equal(t, int64(iosMemoryLimit), debug.SetMemoryLimit(-1))

	debug.SetMemoryLimit(math.MaxInt64)
	t.Setenv("GOMEMLIMIT", "64MiB")

	setMemoryLimit(mobilev1.Config_IOS)
	assert.Equal(t, int64(math.MaxInt64), debug.SetMemoryLimit(-1))
}

func TestCall(t *testing.T) {
	host := newFakeHost()
	c, _ := newTestClient(t, host)

	{
		_, err := c.Call(context.Background(), "Unknown", nil)
		assert.Equal(t, codes.Unimplemented, status.Code(err))
	}

	{
		_, err := c.Call(context.Background(), "GetStatus", []byte{0xff, 0xff, 0xff})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	{
		respBytes, err := c.Call(context.Background(), "GetStatus", nil)
		assert.Nil(t, err)

		resp := &daemonv1.GetStatusResponse{}
		assert.Nil(t, pbutils.Unmarshal(respBytes, resp))
		assert.Equal(t, c.instanceID, resp.InstanceID)
		assert.Equal(t, 0, len(resp.Domains))
	}

	for _, method := range []string{
		"GetOperation", "CancelOperation", "CompleteAuthentication",
	} {
		_, err := c.Call(context.Background(), method, nil)
		assert.True(t, grpcerr.IsInvalidArg(err), "%s", method)
	}

	for _, method := range []string{
		"Connect", "Disconnect", "Logout", "DeleteDomain", "GetAPICredential",
		"Authenticate", "UpdateDomainSettings",
	} {
		_, err := c.Call(context.Background(), method, nil)
		assert.True(t, grpcerr.IsInvalidArg(err), "%s", method)
	}

	for _, method := range []string{
		"Connect", "Disconnect", "Logout", "DeleteDomain", "GetAPICredential",
	} {
		_, err := c.Call(context.Background(), method, pbutils.MarshalMust(&daemonv1.ConnectRequest{
			Domain: "unknown.example.com",
		}))
		assert.True(t, grpcerr.IsNotFound(err), "%s", method)
	}

	{
		err := doCall(t, c, "GetOperation", &daemonv1.GetOperationRequest{
			Id: "unknown",
		}, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsNotFound(err))

		err = doCall(t, c, "CancelOperation", &daemonv1.CancelOperationRequest{
			Id: "unknown",
		}, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsNotFound(err))
	}

	assert.Nil(t, c.Close())

	_, err := c.Call(context.Background(), "GetStatus", nil)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestClientState(t *testing.T) {
	cfg := newTestConfig(t)
	setTestSessionToken(t, cfg, "example.com")

	host := newFakeHost()
	c, err := New(cfg, host)
	assert.Nil(t, err)
	t.Cleanup(func() {
		c.Close()
	})

	{
		d := getTestDomainState(t, c, "example.com")
		assert.NotNil(t, d)
		assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, d.Authentication.State)
		assert.True(t, d.Authentication.ExpiresAt.IsValid())
		assert.Equal(t, daemonv1.ConnectionStatus_DISCONNECTED, d.Connection.State)
		assert.Equal(t, "example.com", d.Settings.Domain)
	}

	{
		rawBytes, err := os.ReadFile(filepath.Join(cfg.StateDir, "octelium.db"))
		assert.Nil(t, err)
		assert.False(t, bytes.Contains(rawBytes, []byte("example.com")))
	}

	other, err := New(cfg, newFakeHost())
	assert.Nil(t, err)
	t.Cleanup(func() {
		other.Close()
	})

	{
		settings := &daemonv1.DomainSettings{}
		assert.Nil(t, doCall(t, c, "UpdateDomainSettings", &daemonv1.UpdateDomainSettingsRequest{
			Domain: "Other.Example.com",
			Settings: &daemonv1.DomainSettings{
				AutoConnect: true,
				ConnectionOptions: &daemonv1.ConnectionOptions{
					TunnelMode: daemonv1.ConnectionOptions_QUICV0,
				},
			},
		}, settings))
		assert.Equal(t, "other.example.com", settings.Domain)
		assert.True(t, settings.AutoConnect)

		d := getTestDomainState(t, other, "other.example.com")
		assert.NotNil(t, d)
		assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT, d.Authentication.State)
		assert.True(t, d.Settings.AutoConnect)
		assert.Equal(t, daemonv1.ConnectionOptions_QUICV0, d.Settings.ConnectionOptions.TunnelMode)
	}

	{
		deleteTestSessionToken(t, cfg, "example.com")

		d := getTestDomainState(t, other, "example.com")
		assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT, d.Authentication.State)

		setTestSessionToken(t, cfg, "example.com")

		d = getTestDomainState(t, other, "example.com")
		assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, d.Authentication.State)
	}

	assert.Eventually(t, func() bool {
		statuses := host.getStatusEvents()
		if len(statuses) == 0 {
			return false
		}

		for _, d := range statuses[len(statuses)-1].Domains {
			if d.Domain == "other.example.com" && d.Settings.AutoConnect {
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)
}

func TestUpdateDomainSettings(t *testing.T) {
	c, _ := newTestClient(t, newFakeHost())

	for _, req := range []*daemonv1.UpdateDomainSettingsRequest{
		{
			Domain: "example.com",
		},
		{
			Domain:   "invalid domain",
			Settings: &daemonv1.DomainSettings{},
		},
		{
			Domain: "example.com",
			Settings: &daemonv1.DomainSettings{
				ConnectionOptions: &daemonv1.ConnectionOptions{
					ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
						EnableEmbeddedSSH: true,
					},
				},
			},
		},
		{
			Domain: "example.com",
			Settings: &daemonv1.DomainSettings{
				ConnectionOptions: &daemonv1.ConnectionOptions{
					ImplementationMode: daemonv1.ConnectionOptions_KERNEL,
				},
			},
		},
	} {
		err := doCall(t, c, "UpdateDomainSettings", req, &daemonv1.DomainSettings{})
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", req)
	}

	assert.Equal(t, 0, len(getTestStatus(t, c).Domains))

	{
		settings := &daemonv1.DomainSettings{}
		assert.Nil(t, doCall(t, c, "UpdateDomainSettings", &daemonv1.UpdateDomainSettingsRequest{
			Domain: "example.com",
			Settings: &daemonv1.DomainSettings{
				Domain: "ignored.example.com",
				ConnectionOptions: &daemonv1.ConnectionOptions{
					L3Mode: daemonv1.ConnectionOptions_BOTH,
					Dns: &daemonv1.ConnectionOptions_DNS{
						Mode: daemonv1.ConnectionOptions_DNS_FULL,
					},
				},
			},
		}, settings))
		assert.Equal(t, "example.com", settings.Domain)

		d := getTestDomainState(t, c, "example.com")
		assert.True(t, pbutils.IsEqual(settings, d.Settings))
	}
}

func TestAuthenticateValidation(t *testing.T) {
	c, _ := newTestClient(t, newFakeHost())

	for _, req := range []*daemonv1.AuthenticateRequest{
		{
			Domain: "example.com",
		},
		{
			Domain: "",
			Type: &daemonv1.AuthenticateRequest_Browser_{
				Browser: &daemonv1.AuthenticateRequest_Browser{},
			},
		},
		{
			Domain: "example.com",
			Type: &daemonv1.AuthenticateRequest_AuthenticationToken_{
				AuthenticationToken: &daemonv1.AuthenticateRequest_AuthenticationToken{},
			},
		},
		{
			Domain: "example.com",
			Type: &daemonv1.AuthenticateRequest_Assertion_{
				Assertion: &daemonv1.AuthenticateRequest_Assertion{},
			},
		},
	} {
		err := doCall(t, c, "Authenticate", req, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsInvalidArg(err), "%+v", req)
	}
}

func TestAuthenticateBrowser(t *testing.T) {
	host := newFakeHost()
	c, _ := newTestClient(t, host)

	startAuth := func() *daemonv1.Operation {
		op := &daemonv1.Operation{}
		assert.Nil(t, doCall(t, c, "Authenticate", &daemonv1.AuthenticateRequest{
			Domain: "Example.COM",
			Type: &daemonv1.AuthenticateRequest_Browser_{
				Browser: &daemonv1.AuthenticateRequest_Browser{},
			},
		}, op))

		return op
	}

	op := startAuth()
	assert.Equal(t, "example.com", op.Domain)
	assert.Equal(t, daemonv1.Operation_AUTHENTICATE, op.Type)
	assert.Equal(t, daemonv1.Operation_WAITING_FOR_USER, op.State)
	assert.True(t, op.Cancellable)
	assert.True(t, op.Action.ExpiresAt.IsValid())

	{
		u, err := url.Parse(op.Action.GetOpenURL().Url)
		assert.Nil(t, err)
		assert.Equal(t, "https", u.Scheme)
		assert.Equal(t, "example.com", u.Host)
		assert.Equal(t, "/login", u.Path)

		reqBytes, err := base64.RawURLEncoding.DecodeString(u.Query().Get("octelium_req"))
		assert.Nil(t, err)

		req := &authv1.ClientLoginRequest{}
		assert.Nil(t, pbutils.Unmarshal(reqBytes, req))
		assert.Equal(t, authv1.ClientLoginRequest_APP, req.CallbackType)
		assert.Equal(t, opkce.ChallengeLen, len(req.CodeChallenge))
	}

	{
		d := getTestDomainState(t, c, "example.com")
		assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATING, d.Authentication.State)
		assert.Equal(t, op.Id, d.LastOperation.Id)
		assert.Equal(t, daemonv1.Operation_WAITING_FOR_USER, d.LastOperation.State)
	}

	{
		err := doCall(t, c, "Authenticate", &daemonv1.AuthenticateRequest{
			Domain: "example.com",
			Type: &daemonv1.AuthenticateRequest_Browser_{
				Browser: &daemonv1.AuthenticateRequest_Browser{},
			},
		}, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsFailedPrecondition(err))
	}

	{
		err := doCall(t, c, "CompleteAuthentication", &mobilev1.CompleteAuthenticationRequest{
			CallbackURL: clientlogin.AppCallbackURL,
		}, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsInvalidArg(err))

		err = doCall(t, c, "CompleteAuthentication", &mobilev1.CompleteAuthenticationRequest{
			OperationID: op.Id,
		}, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsInvalidArg(err))

		err = doCall(t, c, "CompleteAuthentication", &mobilev1.CompleteAuthenticationRequest{
			OperationID: "unknown",
			CallbackURL: clientlogin.AppCallbackURL,
		}, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsNotFound(err))

		for _, callbackURL := range []string{
			clientlogin.AppCallbackURL,
			"https://example.com/callback/success",
			getCallbackURL(t, utilrand.GetRandomBytesMust(opkce.ChallengeLen)),
		} {
			err = doCall(t, c, "CompleteAuthentication", &mobilev1.CompleteAuthenticationRequest{
				OperationID: op.Id,
				CallbackURL: callbackURL,
			}, &daemonv1.Operation{})
			assert.True(t, grpcerr.IsInvalidArg(err), "%s", callbackURL)
		}

		curOp := &daemonv1.Operation{}
		assert.Nil(t, doCall(t, c, "GetOperation", &daemonv1.GetOperationRequest{
			Id: op.Id,
		}, curOp))
		assert.Equal(t, daemonv1.Operation_WAITING_FOR_USER, curOp.State)
	}

	{
		canceledOp := &daemonv1.Operation{}
		assert.Nil(t, doCall(t, c, "CancelOperation", &daemonv1.CancelOperationRequest{
			Id: op.Id,
		}, canceledOp))
		assert.Equal(t, daemonv1.Operation_CANCELED, canceledOp.State)
		assert.Nil(t, canceledOp.Action)

		assert.Eventually(t, func() bool {
			d := getTestDomainState(t, c, "example.com")
			return d.Authentication.State == daemonv1.AuthenticationStatus_LOGGED_OUT
		}, 5*time.Second, 10*time.Millisecond)

		err := doCall(t, c, "CompleteAuthentication", &mobilev1.CompleteAuthenticationRequest{
			OperationID: op.Id,
			CallbackURL: getCallbackURL(t, getLoginChallenge(t, op.Action.GetOpenURL().Url)),
		}, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsFailedPrecondition(err))

		d := getTestDomainState(t, c, "example.com")
		assert.Nil(t, d.LastError)
	}

	op = startAuth()

	{
		callbackURL := getCallbackURL(t, getLoginChallenge(t, op.Action.GetOpenURL().Url))

		completedOp := &daemonv1.Operation{}
		assert.Nil(t, doCall(t, c, "CompleteAuthentication", &mobilev1.CompleteAuthenticationRequest{
			OperationID: op.Id,
			CallbackURL: callbackURL,
		}, completedOp))
		assert.Equal(t, op.Id, completedOp.Id)
		assert.Equal(t, daemonv1.Operation_RUNNING, completedOp.State)
		assert.Nil(t, completedOp.Action)

		err := doCall(t, c, "CompleteAuthentication", &mobilev1.CompleteAuthenticationRequest{
			OperationID: op.Id,
			CallbackURL: callbackURL,
		}, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsFailedPrecondition(err))

		canceledOp := &daemonv1.Operation{}
		assert.Nil(t, doCall(t, c, "CancelOperation", &daemonv1.CancelOperationRequest{
			Id: op.Id,
		}, canceledOp))
		assert.Equal(t, daemonv1.Operation_CANCELED, canceledOp.State)

		assert.Eventually(t, func() bool {
			d := getTestDomainState(t, c, "example.com")
			return d.Authentication.State == daemonv1.AuthenticationStatus_LOGGED_OUT
		}, 5*time.Second, 10*time.Millisecond)
	}

	assert.Eventually(t, func() bool {
		for _, st := range host.getStatusEvents() {
			for _, d := range st.Domains {
				if d.GetLastOperation().GetState() == daemonv1.Operation_WAITING_FOR_USER {
					return true
				}
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond)
}

func TestConnect(t *testing.T) {
	cfg := newTestConfig(t)
	setTestSessionToken(t, cfg, "a.example.invalid")
	setTestSessionToken(t, cfg, "b.example.invalid")

	host := newFakeHost()
	c, err := New(cfg, host)
	assert.Nil(t, err)
	t.Cleanup(func() {
		c.Close()
	})

	{
		assert.Nil(t, doCall(t, c, "UpdateDomainSettings", &daemonv1.UpdateDomainSettingsRequest{
			Domain:   "logged-out.example.invalid",
			Settings: &daemonv1.DomainSettings{},
		}, &daemonv1.DomainSettings{}))

		err := doCall(t, c, "Connect", &daemonv1.ConnectRequest{
			Domain: "logged-out.example.invalid",
		}, &daemonv1.Operation{})
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	}

	{
		err := doCall(t, c, "Connect", &daemonv1.ConnectRequest{
			Domain: "a.example.invalid",
			Options: &daemonv1.ConnectionOptions{
				ServiceOptions: &daemonv1.ConnectionOptions_ServiceOptions{
					ServeAll: true,
				},
			},
		}, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsInvalidArg(err))
	}

	opA := &daemonv1.Operation{}
	assert.Nil(t, doCall(t, c, "Connect", &daemonv1.ConnectRequest{
		Domain: "a.example.invalid",
	}, opA))
	assert.Equal(t, daemonv1.Operation_CONNECT, opA.Type)
	assert.Equal(t, daemonv1.Operation_RUNNING, opA.State)

	{
		d := getTestDomainState(t, c, "a.example.invalid")
		assert.Contains(t, []daemonv1.ConnectionStatus_State{
			daemonv1.ConnectionStatus_CONNECTING,
			daemonv1.ConnectionStatus_RECONNECTING,
		}, d.Connection.State)
		assert.Equal(t, daemonv1.ConnectionOptions_DNS_DEFAULT, d.Connection.Options.Dns.Mode)
	}

	{
		err := doCall(t, c, "Connect", &daemonv1.ConnectRequest{
			Domain: "a.example.invalid",
		}, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsFailedPrecondition(err))

		err = doCall(t, c, "Connect", &daemonv1.ConnectRequest{
			Domain: "b.example.invalid",
		}, &daemonv1.Operation{})
		assert.True(t, grpcerr.IsFailedPrecondition(err))
		assert.Contains(t, err.Error(), "a.example.invalid")
	}

	assert.Eventually(t, func() bool {
		d := getTestDomainState(t, c, "a.example.invalid")
		return d.LastError.GetCode() == daemonv1.Error_CONNECTION_FAILED ||
			d.LastError.GetCode() == daemonv1.Error_CLUSTER_UNREACHABLE
	}, 10*time.Second, 50*time.Millisecond)

	assert.Nil(t, doCall(t, c, "SetNetworkState", &mobilev1.SetNetworkStateRequest{
		IsAvailable: false,
	}, &mobilev1.SetNetworkStateResponse{}))
	assert.False(t, c.network.getIsAvailable())

	deleteTestSessionToken(t, cfg, "a.example.invalid")

	opDisconnect := &daemonv1.Operation{}
	assert.Nil(t, doCall(t, c, "Disconnect", &daemonv1.DisconnectRequest{
		Domain: "a.example.invalid",
	}, opDisconnect))
	assert.Equal(t, daemonv1.Operation_DISCONNECT, opDisconnect.Type)

	assert.Eventually(t, func() bool {
		curOp := &daemonv1.Operation{}
		assert.Nil(t, doCall(t, c, "GetOperation", &daemonv1.GetOperationRequest{
			Id: opDisconnect.Id,
		}, curOp))
		return curOp.State == daemonv1.Operation_SUCCEEDED
	}, 10*time.Second, 50*time.Millisecond)

	{
		d := getTestDomainState(t, c, "a.example.invalid")
		assert.Equal(t, daemonv1.ConnectionStatus_DISCONNECTED, d.Connection.State)
		assert.Nil(t, d.Connection.Options)

		curOp := &daemonv1.Operation{}
		assert.Nil(t, doCall(t, c, "GetOperation", &daemonv1.GetOperationRequest{
			Id: opA.Id,
		}, curOp))
		assert.Equal(t, daemonv1.Operation_CANCELED, curOp.State)
	}

	assert.Nil(t, doCall(t, c, "SetNetworkState", &mobilev1.SetNetworkStateRequest{
		IsAvailable: true,
		Id:          "wifi",
	}, &mobilev1.SetNetworkStateResponse{}))

	opB := &daemonv1.Operation{}
	assert.Nil(t, doCall(t, c, "Connect", &daemonv1.ConnectRequest{
		Domain: "b.example.invalid",
		Options: &daemonv1.ConnectionOptions{
			TunnelMode: daemonv1.ConnectionOptions_QUICV0,
		},
	}, opB))
	assert.Equal(t, daemonv1.Operation_RUNNING, opB.State)

	{
		d := getTestDomainState(t, c, "b.example.invalid")
		assert.Equal(t, daemonv1.ConnectionOptions_QUICV0, d.Connection.Options.TunnelMode)
	}

	assert.Nil(t, c.Close())

	c.mu.Lock()
	assert.Equal(t, "", c.tunnelDomain)
	assert.Equal(t, daemonv1.ConnectionStatus_DISCONNECTED, c.domains["b.example.invalid"].connState)
	c.mu.Unlock()
}

func TestConnectEventHandler(t *testing.T) {
	c, _ := newTestClient(t, newFakeHost())

	d, err := c.getDomain("example.com")
	assert.Nil(t, err)

	op, err := d.beginOperation(daemonv1.Operation_CONNECT, func() {})
	assert.Nil(t, err)

	var isCanceled bool
	var stopErr error

	c.update(func() {
		d.connGen = 2
		d.connState = daemonv1.ConnectionStatus_CONNECTING
	})

	handler := d.getConnectEventHandler(op, 2, &stopErr, func() {
		isCanceled = true
	})

	handler(&connect.Event{
		Type: connect.EventTypeConnecting,
		Err:  status.Error(codes.Unavailable, "unavailable"),
	})
	assert.Equal(t, daemonv1.Error_CLUSTER_UNREACHABLE, d.lastErr.Code)
	assert.False(t, isCanceled)
	assert.Nil(t, stopErr)

	handler(&connect.Event{
		Type: connect.EventTypeConnected,
		Connection: &cliconfigv1.Connection{
			Preferences: &cliconfigv1.Connection_Preferences{
				Mtu: 1280,
			},
		},
	})
	assert.Equal(t, daemonv1.ConnectionStatus_CONNECTED, d.connState)
	assert.Nil(t, d.lastErr)
	assert.True(t, d.connectedAt.IsValid())
	assert.Equal(t, daemonv1.Operation_SUCCEEDED, op.state)
	assert.NotNil(t, d.connCfg)

	c.mu.Lock()
	assert.NotNil(t, d.refreshCancelFn)
	c.mu.Unlock()
	d.stopRefreshLoop()

	handler(&connect.Event{
		Type: connect.EventTypeReconnecting,
	})
	assert.Equal(t, daemonv1.ConnectionStatus_RECONNECTING, d.connState)
	assert.Nil(t, d.connCfg)
	assert.Nil(t, d.lastErr)

	handler(&connect.Event{
		Type: connect.EventTypeReconnecting,
		Err:  authenticator.ErrAuthenticationRequired,
	})
	assert.Equal(t, daemonv1.Error_AUTHENTICATION_REQUIRED, d.lastErr.Code)
	assert.True(t, isCanceled)
	assert.ErrorIs(t, stopErr, authenticator.ErrAuthenticationRequired)

	staleHandler := d.getConnectEventHandler(op, 1, &stopErr, func() {})
	staleHandler(&connect.Event{
		Type: connect.EventTypeConnecting,
	})
	assert.Equal(t, daemonv1.ConnectionStatus_RECONNECTING, d.connState)
}

func TestLogoutAndDeleteDomain(t *testing.T) {
	c, _ := newTestClient(t, newFakeHost())

	assert.Nil(t, doCall(t, c, "UpdateDomainSettings", &daemonv1.UpdateDomainSettingsRequest{
		Domain:   "example.com",
		Settings: &daemonv1.DomainSettings{},
	}, &daemonv1.DomainSettings{}))

	waitOp := func(id string) *daemonv1.Operation {
		ret := &daemonv1.Operation{}
		assert.Eventually(t, func() bool {
			assert.Nil(t, doCall(t, c, "GetOperation", &daemonv1.GetOperationRequest{
				Id: id,
			}, ret))
			return ret.State == daemonv1.Operation_SUCCEEDED
		}, 10*time.Second, 20*time.Millisecond)
		return ret
	}

	{
		op := &daemonv1.Operation{}
		assert.Nil(t, doCall(t, c, "Logout", &daemonv1.LogoutRequest{
			Domain: "example.com",
		}, op))
		assert.Equal(t, daemonv1.Operation_LOGOUT, op.Type)
		waitOp(op.Id)

		d := getTestDomainState(t, c, "example.com")
		assert.Equal(t, daemonv1.AuthenticationStatus_LOGGED_OUT, d.Authentication.State)
	}

	{
		op := &daemonv1.Operation{}
		assert.Nil(t, doCall(t, c, "Disconnect", &daemonv1.DisconnectRequest{
			Domain: "example.com",
		}, op))
		waitOp(op.Id)
	}

	{
		err := doCall(t, c, "GetAPICredential", &daemonv1.GetAPICredentialRequest{
			Domain: "example.com",
		}, &daemonv1.GetAPICredentialResponse{})
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	}

	{
		op := &daemonv1.Operation{}
		assert.Nil(t, doCall(t, c, "DeleteDomain", &daemonv1.DeleteDomainRequest{
			Domain: "example.com",
		}, op))
		assert.Equal(t, daemonv1.Operation_DELETE, op.Type)
		waitOp(op.Id)

		assert.Nil(t, getTestDomainState(t, c, "example.com"))

		_, err := c.dbC.Get("example.com")
		assert.True(t, c.dbC.ErrorIsNotFound(err))
	}
}

func TestGetRefreshWait(t *testing.T) {
	cfg := newTestConfig(t)
	c, err := New(cfg, newFakeHost())
	assert.Nil(t, err)
	t.Cleanup(func() {
		c.Close()
	})

	d := c.newDomainCtl("example.com")

	assert.Equal(t, refreshMinInterval, d.getRefreshWait())

	setToken := func(expiresIn int64, setAt time.Time) {
		assert.Nil(t, c.dbC.SetSessionToken("example.com", &authv1.SessionToken{
			AccessToken:           "at",
			RefreshToken:          "rt",
			ExpiresIn:             expiresIn,
			RefreshTokenExpiresIn: 3600 * 24,
		}))
		itm, err := c.dbC.Get("example.com")
		assert.Nil(t, err)
		assert.True(t, itm.SessionTokenSetAt.IsValid())
		_ = setAt
	}

	setToken(0, time.Now())
	assert.Equal(t, refreshMaxInterval, d.getRefreshWait())

	setToken(3600, time.Now())
	wait := d.getRefreshWait()
	assert.LessOrEqual(t, wait, 30*time.Minute)
	assert.Greater(t, wait, 29*time.Minute)

	setToken(60, time.Now())
	assert.Equal(t, refreshMinInterval, d.getRefreshWait())

	setToken(3600*24, time.Now())
	assert.Equal(t, refreshMaxInterval, d.getRefreshWait())
}

func TestWithCtxDeviceInfo(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.Device.Id = "3f2a8c1e-7b4d-4e6a-9c2f-1d5e8b7a6c43"
	cfg.Device.SerialNumber = "1234"

	c, err := New(cfg, newFakeHost())
	assert.Nil(t, err)
	t.Cleanup(func() {
		c.Close()
	})

	info, err := deviceinfo.GetDeviceInfo(c.opCtx())
	assert.Nil(t, err)
	assert.Equal(t, deviceinfo.HashID(cfg.Device.Id), info.ID)
	assert.True(t, regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(info.ID))
	assert.Equal(t, "phone", info.Hostname)
	assert.Equal(t, "1234", info.SerialNumber)
}

func TestGetAPICredential(t *testing.T) {
	const domain = "a.example.invalid"

	newClient := func(t *testing.T, expiresIn int64) *Client {
		cfg := newTestConfig(t)

		dbC, err := db.OpenWithOpts(&db.Opts{
			Path:          cfg.StateDir,
			EncryptionKey: cfg.StateKey,
		})
		assert.Nil(t, err)
		assert.Nil(t, dbC.SetSessionToken(domain, &authv1.SessionToken{
			AccessToken:           "access-token",
			RefreshToken:          utilrand.GetRandomString(32),
			ExpiresIn:             expiresIn,
			RefreshTokenExpiresIn: 3600,
		}))

		c, err := New(cfg, newFakeHost())
		assert.Nil(t, err)
		t.Cleanup(func() {
			c.Close()
		})

		return c
	}

	getCredential := func(c *Client) (*daemonv1.GetAPICredentialResponse, error) {
		ret := &daemonv1.GetAPICredentialResponse{}
		if err := doCall(t, c, "GetAPICredential", &daemonv1.GetAPICredentialRequest{
			Domain: domain,
		}, ret); err != nil {
			return nil, err
		}

		return ret, nil
	}

	{
		c := newClient(t, 7200)
		c.network.set(false, "")

		resp, err := getCredential(c)
		assert.Nil(t, err)
		assert.Equal(t, "access-token", resp.AccessToken)
	}

	{
		c := newClient(t, 60)
		c.network.set(false, "")

		_, err := getCredential(c)
		assert.Equal(t, codes.Unavailable, status.Code(err))
		assert.Nil(t, getTestDomainState(t, c, domain).LastError)
	}

	{
		c := newClient(t, 60)
		c.credentialTimeout = 200 * time.Millisecond

		startedAt := time.Now()
		_, err := getCredential(c)
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err), "%+v", err)
		assert.Less(t, time.Since(startedAt), 10*time.Second)
		assert.NotNil(t, getTestDomainState(t, c, domain).LastError)
	}
}

func TestCloseWaitsForOperations(t *testing.T) {
	cfg := newTestConfig(t)
	setTestSessionToken(t, cfg, "a.example.invalid")

	c, err := New(cfg, newFakeHost())
	assert.Nil(t, err)

	authOp := &daemonv1.Operation{}
	assert.Nil(t, doCall(t, c, "Authenticate", &daemonv1.AuthenticateRequest{
		Domain: "b.example.invalid",
		Type: &daemonv1.AuthenticateRequest_AuthenticationToken_{
			AuthenticationToken: &daemonv1.AuthenticateRequest_AuthenticationToken{
				AuthenticationToken: utilrand.GetRandomString(32),
			},
		},
	}, authOp))

	logoutOp := &daemonv1.Operation{}
	assert.Nil(t, doCall(t, c, "Logout", &daemonv1.LogoutRequest{
		Domain: "a.example.invalid",
	}, logoutOp))

	startedAt := time.Now()
	assert.Nil(t, c.Close())
	assert.Less(t, time.Since(startedAt), 5*time.Second)

	c.mu.Lock()
	assert.True(t, c.ops[authOp.Id].isDone())
	assert.True(t, c.ops[logoutOp.Id].isDone())
	c.mu.Unlock()

	_, err = c.dbC.GetSessionToken("a.example.invalid")
	assert.True(t, c.dbC.ErrorIsNotFound(err))

	_, err = c.Call(context.Background(), "GetStatus", nil)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestCloseCancelsInFlightCall(t *testing.T) {
	cfg := newTestConfig(t)

	c, err := New(cfg, newFakeHost())
	assert.Nil(t, err)

	assert.True(t, c.beginWork())
	callDoneCh := make(chan error, 1)
	go func() {
		defer c.wg.Done()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		stop := context.AfterFunc(c.ctx, cancel)
		defer stop()

		<-ctx.Done()
		callDoneCh <- ctx.Err()
	}()

	closeDoneCh := make(chan struct{})
	go func() {
		c.Close()
		close(closeDoneCh)
	}()

	select {
	case err := <-callDoneCh:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("The in-flight call was not canceled")
	}

	select {
	case <-closeDoneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}

	assert.False(t, c.beginWork())
}

func TestFinishAuthenticateSuperseded(t *testing.T) {
	cfg := newTestConfig(t)
	setTestSessionToken(t, cfg, "example.com")

	c, err := New(cfg, newFakeHost())
	assert.Nil(t, err)
	t.Cleanup(func() {
		c.Close()
	})

	d, err := c.getDomain("example.com")
	assert.Nil(t, err)

	startAuth := func() *operation {
		op, err := d.beginSupersedingOperation(daemonv1.Operation_AUTHENTICATE, func() {})
		assert.Nil(t, err)

		c.update(func() {
			d.authState = daemonv1.AuthenticationStatus_AUTHENTICATING
			d.lastErr = nil
		})

		return op
	}

	{
		authOp := startAuth()

		logoutOp, err := d.beginSupersedingOperation(daemonv1.Operation_LOGOUT, nil)
		assert.Nil(t, err)
		assert.Equal(t, daemonv1.Operation_CANCELED, authOp.state)

		c.update(func() {
			d.authState = daemonv1.AuthenticationStatus_LOGGING_OUT
		})

		d.finishAuthenticate(authOp, errors.Errorf("could not authenticate"))

		assert.Equal(t, daemonv1.AuthenticationStatus_LOGGING_OUT, d.authState)
		assert.Nil(t, d.lastErr)

		c.update(func() {
			logoutOp.setState(daemonv1.Operation_SUCCEEDED)
		})
	}

	{
		authOp := startAuth()

		disconnectOp, err := d.beginSupersedingOperation(daemonv1.Operation_DISCONNECT, nil)
		assert.Nil(t, err)

		d.finishAuthenticate(authOp, context.Canceled)

		assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, d.authState)
		assert.Nil(t, d.lastErr)
		assert.Equal(t, daemonv1.Operation_CANCELED, authOp.state)

		c.update(func() {
			disconnectOp.setState(daemonv1.Operation_SUCCEEDED)
		})
	}

	{
		authOp := startAuth()

		_, err := c.cancelOperation(authOp.id)
		assert.Nil(t, err)

		newAuthOp := startAuth()
		assert.Equal(t, daemonv1.Operation_RUNNING, newAuthOp.state)

		d.finishAuthenticate(authOp, errors.Errorf("could not authenticate"))

		assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATING, d.authState)
		assert.Nil(t, d.lastErr)
		assert.Equal(t, daemonv1.Operation_RUNNING, newAuthOp.state)

		d.finishAuthenticate(newAuthOp, errors.Errorf("could not authenticate"))

		assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, d.authState)
		assert.Equal(t, daemonv1.Error_AUTHENTICATION_FAILED, d.lastErr.GetCode())
		assert.Equal(t, daemonv1.Operation_FAILED, newAuthOp.state)
	}

	{
		authOp := startAuth()

		_, err := c.cancelOperation(authOp.id)
		assert.Nil(t, err)

		d.finishAuthenticate(authOp, context.Canceled)

		assert.Equal(t, daemonv1.AuthenticationStatus_AUTHENTICATED, d.authState)
		assert.Nil(t, d.lastErr)
	}
}

func TestClientLogs(t *testing.T) {
	hostA := newFakeHost()
	cA, err := New(newTestConfig(t), hostA)
	assert.Nil(t, err)

	hostB := newFakeHost()
	cB, err := New(newTestConfig(t), hostB)
	assert.Nil(t, err)
	t.Cleanup(func() {
		cB.Close()
	})

	hasLog := func(host *fakeHost, msg string) bool {
		for _, log := range host.getLogEvents() {
			if log.Message == msg {
				return true
			}
		}
		return false
	}

	zap.L().Info("first message")

	assert.Eventually(t, func() bool {
		return hasLog(hostA, "first message") && hasLog(hostB, "first message")
	}, 5*time.Second, 10*time.Millisecond)

	assert.Nil(t, cA.Close())

	zap.L().Info("second message")

	assert.Eventually(t, func() bool {
		return hasLog(hostB, "second message")
	}, 5*time.Second, 10*time.Millisecond)
	assert.False(t, hasLog(hostA, "second message"))
}
