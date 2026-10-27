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

package auth

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/common/commands/auth/authcommon"
	"github.com/octelium/octelium/client/common/db"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/grpc/status"
)

func TestCmds(t *testing.T) {
	AddSubcommands()
	assert.True(t, Cmd.HasSubCommands())
}

func executeAuthCommand(t *testing.T, ctx context.Context, args ...string) (string, error) {
	t.Helper()
	AddSubcommands()
	var restoreFlags func(*cobra.Command)
	restoreFlags = func(cmd *cobra.Command) {
		previousContext := cmd.Context()
		cmd.SetContext(ctx)
		t.Cleanup(func() { cmd.SetContext(previousContext) })
		cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
			value, changed := flag.Value.String(), flag.Changed
			t.Cleanup(func() { flag.Value.Set(value); flag.Changed = changed })
		})
		for _, child := range cmd.Commands() {
			restoreFlags(child)
		}
	}
	restoreFlags(Cmd)
	root := &cobra.Command{Use: "test", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().String("domain", "example.invalid", "")
	root.AddCommand(Cmd)
	root.SetArgs(append([]string{"auth"}, args...))
	file, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	require.NoError(t, err)
	previous := os.Stdout
	os.Stdout = file
	defer func() { os.Stdout = previous; file.Close() }()
	err = root.ExecuteContext(ctx)
	_, seekErr := file.Seek(0, io.SeekStart)
	require.NoError(t, seekErr)
	out, readErr := io.ReadAll(file)
	require.NoError(t, readErr)
	return string(out), err
}

func newAuthCommandContext(t *testing.T, handler grpc.UnaryServerInterceptor) context.Context {
	t.Helper()
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	t.Setenv("OCTELIUM_INSECURE_TLS", "true")
	certSrv := httptest.NewTLSServer(nil)
	cert := certSrv.TLS.Certificates[0]
	certSrv.Close()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	previous := resolver.Get("dns")
	r := manual.NewBuilderWithScheme("dns")
	r.InitialState(resolver.State{Addresses: []resolver.Address{{Addr: lis.Addr().String()}}})
	resolver.Register(r)
	t.Cleanup(func() { resolver.Register(previous) })
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})), grpc.UnaryInterceptor(handler))
	authv1.RegisterMainServiceServer(srv, &authv1.UnimplementedMainServiceServer{})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	d, err := db.Open("mem")
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	require.NoError(t, d.SetSessionToken("example.invalid", &authv1.SessionToken{RefreshToken: "refresh"}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return cliutils.WithDB(ctx, d)
}

func TestAuthCommandsE2E(t *testing.T) {
	for _, itm := range []struct {
		name string
		args []string
		err  string
	}{
		{"list json", []string{"get", "authn", "--out=json"}, ""},
		{"list yaml", []string{"get", "authn", "--out=yaml"}, ""},
		{"list table", []string{"get", "authn", "--out="}, ""},
		{"empty list", []string{"get", "authn", "--out="}, ""},
		{"list invalid output", []string{"get", "authn", "--out=xml"}, "Invalid output format"},
		{"delete", []string{"delete", "authn", "totp-one"}, ""},
		{"create unknown", []string{"create", "authn", "--type=unknown"}, "Unknown Authenticator type"},
		{"create totp", []string{"create", "authn", "--type=totp", "--display-name=Phone"}, "Cannot Register TOTP"},
		{"already registered", []string{"create", "authn", "--type=totp", "--display-name=Phone"}, ""},
		{"registration denied", []string{"create", "authn", "--type=totp", "--display-name=Phone"}, "registration denied"},
		{"unknown registration challenge", []string{"create", "authn", "--type=totp", "--display-name=Phone"}, "Unknown authenticator challenge"},
		{"authenticate unknown challenge", []string{"authn", "totp-one"}, "Unknown authenticator challenge"},
		{"not registered", []string{"authn", "totp-one"}, "Authenticator is not registered"},
		{"already authenticated", []string{"authn", "totp-one"}, ""},
		{"authentication denied", []string{"authn", "totp-one"}, "authentication denied"},
	} {
		t.Run(itm.name, func(t *testing.T) {
			ctx := newAuthCommandContext(t, func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				md, _ := metadata.FromIncomingContext(ctx)
				assert.Equal(t, []string{"refresh"}, md.Get("x-octelium-refresh-token"))
				authn := &authv1.Authenticator{Metadata: &metav1.Metadata{Name: "totp-one", Uid: "uid"}, Spec: &authv1.Authenticator_Spec{DisplayName: "Phone"}, Status: &authv1.Authenticator_Status{Type: authv1.Authenticator_Status_TOTP, IsRegistered: true}}
				if itm.name == "not registered" {
					authn.Status.IsRegistered = false
				}
				switch info.FullMethod[strings.LastIndex(info.FullMethod, "/")+1:] {
				case "ListAuthenticator":
					if itm.name == "empty list" {
						return &authv1.AuthenticatorList{}, nil
					}
					return &authv1.AuthenticatorList{Items: []*authv1.Authenticator{authn}}, nil
				case "DeleteAuthenticator":
					assert.Equal(t, "totp-one", req.(*metav1.DeleteOptions).Name)
					return &metav1.OperationResult{}, nil
				case "CreateAuthenticator":
					arg := req.(*authv1.CreateAuthenticatorRequest)
					assert.Equal(t, "Phone", arg.DisplayName)
					assert.Equal(t, authv1.Authenticator_Status_TOTP, arg.Type)
					return authn, nil
				case "RegisterAuthenticatorBegin":
					assert.Equal(t, "uid", req.(*authv1.RegisterAuthenticatorBeginRequest).AuthenticatorRef.Uid)
					if itm.name == "already registered" {
						return nil, status.Error(codes.AlreadyExists, "registered")
					}
					if itm.name == "registration denied" {
						return nil, status.Error(codes.PermissionDenied, "registration denied")
					}
					if itm.name == "unknown registration challenge" {
						return &authv1.RegisterAuthenticatorBeginResponse{ChallengeRequest: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest{}}, nil
					}
					return &authv1.RegisterAuthenticatorBeginResponse{ChallengeRequest: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest{Type: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_Totp{Totp: &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest_TOTP{}}}}, nil
				case "GetAuthenticator":
					assert.Equal(t, "totp-one", req.(*metav1.GetOptions).Name)
					return authn, nil
				case "AuthenticateAuthenticatorBegin":
					assert.Equal(t, "uid", req.(*authv1.AuthenticateAuthenticatorBeginRequest).AuthenticatorRef.Uid)
					if itm.name == "already authenticated" {
						return nil, status.Error(codes.AlreadyExists, "authenticated")
					}
					if itm.name == "authentication denied" {
						return nil, status.Error(codes.PermissionDenied, "authentication denied")
					}
					return &authv1.AuthenticateAuthenticatorBeginResponse{ChallengeRequest: &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest{}}, nil
				}
				return handler(ctx, req)
			})
			out, err := executeAuthCommand(t, ctx, itm.args...)
			if itm.err != "" {
				assert.ErrorContains(t, err, itm.err)
			} else {
				require.NoError(t, err)
			}
			if strings.HasPrefix(itm.name, "list") && itm.err == "" {
				assert.Contains(t, out, "totp-one")
				assert.Contains(t, out, "Phone")
				assert.Contains(t, out, "TOTP")
			}
		})
	}
}

func TestAuthCommandServerErrors(t *testing.T) {
	for _, args := range [][]string{
		{"get", "authn"}, {"delete", "authn", "totp-one"},
		{"create", "authn", "--type=totp"}, {"authn", "totp-one"},
	} {
		t.Run(strings.Join(args, "/"), func(t *testing.T) {
			ctx := newAuthCommandContext(t, func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
				return nil, status.Error(codes.PermissionDenied, "denied")
			})
			_, err := executeAuthCommand(t, ctx, args...)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
		})
	}
}

func TestAuthCommandValidation(t *testing.T) {
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "proxy.sock")
	_, err := executeAuthCommand(t, context.Background(), "get", "authn")
	assert.ErrorContains(t, err, "proxy mode")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	for _, args := range [][]string{{"authn"}, {"delete", "authn"}, {"get", "authn", "extra"}, {"create", "authn", "extra"}} {
		_, err := executeAuthCommand(t, context.Background(), args...)
		assert.Error(t, err)
	}
}

func TestAuthenticatorChallengeValidation(t *testing.T) {
	ctx := context.Background()
	ret, err := authcommon.Authenticate(ctx, &authv1.AuthenticateAuthenticatorBeginResponse_ChallengeRequest{})
	assert.Nil(t, ret)
	assert.ErrorContains(t, err, "Unknown authenticator challenge")
	ret, err = authcommon.Register(ctx, &authv1.RegisterAuthenticatorBeginResponse_ChallengeRequest{})
	assert.Nil(t, ret)
	assert.ErrorContains(t, err, "Unknown authenticator challenge")
	preChallenge, err := authcommon.GetPreChallenge(ctx, &authv1.Authenticator{Status: &authv1.Authenticator_Status{Type: authv1.Authenticator_Status_TOTP}})
	assert.NoError(t, err)
	assert.Nil(t, preChallenge)
}
