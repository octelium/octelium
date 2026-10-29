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

package commands

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/authenticator"
	"github.com/octelium/octelium/client/common/cliutils"
	creategroup "github.com/octelium/octelium/client/octeliumctl/commands/create/group"
	createservice "github.com/octelium/octelium/client/octeliumctl/commands/create/service"
	createuser "github.com/octelium/octelium/client/octeliumctl/commands/create/user"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestCmds(t *testing.T) {
	InitCmds()
	assert.True(t, Cmd.HasSubCommands())
	assert.False(t, Cmd.Runnable())
}

var testCommandsOnce sync.Once

func cloneTestCommand(src *cobra.Command, restore *[]func()) *cobra.Command {
	ret := &cobra.Command{
		Use: src.Use, Short: src.Short, Long: src.Long, Example: src.Example,
		Aliases: slices.Clone(src.Aliases), Args: src.Args, RunE: src.RunE,
		PersistentPreRunE: src.PersistentPreRunE, PersistentPostRunE: src.PersistentPostRunE,
		SilenceErrors: true, SilenceUsage: true,
	}
	for _, itm := range []struct{ src, dst *pflag.FlagSet }{
		{src.LocalNonPersistentFlags(), ret.Flags()},
		{src.PersistentFlags(), ret.PersistentFlags()},
	} {
		itm.src.VisitAll(func(flag *pflag.Flag) {
			if value, ok := flag.Value.(pflag.SliceValue); ok {
				previous := slices.Clone(value.GetSlice())
				*restore = append(*restore, func() { value.Replace(previous) })
				value.Replace(nil)
			} else {
				previous := flag.Value.String()
				*restore = append(*restore, func() { flag.Value.Set(previous) })
				flag.Value.Set(flag.DefValue)
			}
			copied := *flag
			copied.Changed = false
			itm.dst.AddFlag(&copied)
		})
	}
	seen := make(map[string]bool)
	for _, child := range src.Commands() {
		if !seen[child.Name()] {
			ret.AddCommand(cloneTestCommand(child, restore))
			seen[child.Name()] = true
		}
	}
	return ret
}

func executeTestCommand(t *testing.T, ctx context.Context, extra *cobra.Command, args ...string) (string, error) {
	t.Helper()
	testCommandsOnce.Do(InitCmds)
	var restore []func()
	defer func() {
		for i := len(restore) - 1; i >= 0; i-- {
			restore[i]()
		}
	}()
	root := cloneTestCommand(Cmd, &restore)
	if extra != nil {
		create, _, err := root.Find([]string{"create"})
		require.NoError(t, err)
		create.AddCommand(cloneTestCommand(extra, &restore))
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "output"))
	require.NoError(t, err)
	previousStdout, previousColor, previousNoColor, previousLogger := os.Stdout, color.Output, color.NoColor, zap.L()
	os.Stdout, color.Output, color.NoColor = f, f, true
	defer func() {
		os.Stdout, color.Output, color.NoColor = previousStdout, previousColor, previousNoColor
		zap.ReplaceGlobals(previousLogger)
		f.Close()
	}()
	root.SetOut(f)
	root.SetErr(f)
	root.SetArgs(append([]string{"--domain=example.invalid", "--homedir=mem"}, args...))
	err = root.ExecuteContext(ctx)
	if cliutils.GetDB() != nil {
		cliutils.CloseDB()
	}
	_, seekErr := f.Seek(0, io.SeekStart)
	require.NoError(t, seekErr)
	out, readErr := io.ReadAll(f)
	require.NoError(t, readErr)
	return string(out), err
}

func newTestCoreServer(t *testing.T, handler func(context.Context, string, proto.Message) (proto.Message, error)) context.Context {
	t.Helper()
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "test-access")
	t.Setenv("OCTELIUM_LOGOUT", "")
	t.Setenv("OCTELIUM_PRODUCTION", "true")
	t.Setenv("OCTELIUM_DEV", "false")
	t.Setenv("OCTELIUM_INSECURE_TLS", "true")
	t.Setenv("DEBIAN_FRONTEND", "noninteractive")
	certServer := httptest.NewTLSServer(nil)
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	for _, scheme := range []string{"dns", "passthrough"} {
		previous := resolver.Get(scheme)
		r := manual.NewBuilderWithScheme(scheme)
		r.InitialState(resolver.State{Addresses: []resolver.Address{{Addr: lis.Addr().String()}}})
		resolver.Register(r)
		t.Cleanup(func() { resolver.Register(previous) })
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			assert.Equal(t, []string{"test-access"}, md.Get("x-octelium-auth"))
			return handler(ctx, info.FullMethod[strings.LastIndex(info.FullMethod, "/")+1:], req.(proto.Message))
		}))
	corev1.RegisterMainServiceServer(srv, &corev1.UnimplementedMainServiceServer{})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func testCoreResource(t *testing.T, kind, name string) umetav1.ResourceObjectI {
	t.Helper()
	ret, err := ucorev1.NewObject(kind)
	require.NoError(t, err)
	require.NoError(t, pbutils.UnmarshalFromMap(map[string]any{
		"kind": kind, "metadata": map[string]any{"name": name, "uid": name + "-uid", "createdAt": time.Now().Add(-time.Hour).Format(time.RFC3339Nano)},
	}, ret))
	if svc, ok := ret.(*corev1.Service); ok {
		svc.Status = &corev1.Service_Status{PrimaryHostname: name}
	}
	return ret
}

func testCoreList(t *testing.T, kind string, items []umetav1.ResourceObjectI, meta *metav1.ListResponseMeta) proto.Message {
	t.Helper()
	ret, err := ucorev1.NewObjectList(kind)
	require.NoError(t, err)
	msg := ret.ProtoReflect()
	fd := msg.Descriptor().Fields().ByName("items")
	for _, itm := range items {
		msg.Mutable(fd).List().Append(protoreflect.ValueOfMessage(itm.ProtoReflect()))
	}
	if meta != nil {
		msg.Set(msg.Descriptor().Fields().ByName("listResponseMeta"), protoreflect.ValueOfMessage(meta.ProtoReflect()))
	}
	return ret
}

func TestGetResourceCommandsE2E(t *testing.T) {
	for _, kind := range []string{"User", "Group", "Namespace", "Service", "Credential", "Device", "Session", "Secret", "Config", "Policy", "IdentityProvider", "Region", "Gateway", "Authenticator"} {
		t.Run(kind, func(t *testing.T) {
			item := testCoreResource(t, kind, "sample")
			var calls atomic.Int32
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				calls.Add(1)
				if method == "Get"+kind {
					assert.Equal(t, "sample", req.(*metav1.GetOptions).Name)
					return item, nil
				}
				assert.Equal(t, "List"+kind, method)
				want, err := ucorev1.NewObjectListOptions(kind)
				assert.NoError(t, err)
				assert.NoError(t, pbutils.UnmarshalFromMap(map[string]any{"common": map[string]any{
					"page": 1, "itemsPerPage": 2, "orderBy": map[string]any{"type": "NAME", "mode": "DESC"},
				}}, want))
				assert.True(t, pbutils.IsEqual(want, req), "%s: %s", method, req)
				return testCoreList(t, kind, []umetav1.ResourceObjectI{item}, &metav1.ListResponseMeta{Page: 1, TotalCount: 6, HasMore: true}), nil
			})
			for _, named := range []bool{false, true} {
				for _, format := range []string{"", "json", "yaml", "yml"} {
					args := []string{"get", strings.ToLower(kind)}
					if named {
						args = append(args, "sample")
					} else {
						args = append(args, "--page=2", "--items-per-page=2", "--order-by-name", "--order-reverse")
					}
					args = append(args, "--out="+format)
					out, err := executeTestCommand(t, ctx, nil, args...)
					require.NoError(t, err)
					assert.Contains(t, out, "sample")
					if format == "" {
						if !named {
							assert.Contains(t, out, "--page 3")
						}
						continue
					}
					var ret proto.Message
					if named {
						ret, err = ucorev1.NewObject(kind)
					} else {
						ret, err = ucorev1.NewObjectList(kind)
					}
					require.NoError(t, err)
					if format == "json" {
						require.NoError(t, pbutils.UnmarshalJSON([]byte(out), ret))
					} else {
						require.NoError(t, pbutils.UnmarshalYAML([]byte(out), ret))
					}
					if named {
						assert.True(t, pbutils.IsEqual(item, ret))
					}
				}
			}
			assert.Equal(t, int32(8), calls.Load())
		})
	}
}

func TestGetResourceErrorsAndEmptyLists(t *testing.T) {
	for _, kind := range []string{"User", "Group", "Namespace", "Service", "Credential", "Device", "Session", "Secret", "Config", "Policy", "IdentityProvider", "Region", "Gateway", "Authenticator"} {
		t.Run(kind, func(t *testing.T) {
			var fail atomic.Bool
			var calls atomic.Int32
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				calls.Add(1)
				if fail.Load() {
					return nil, status.Error(codes.PermissionDenied, "denied")
				}
				assert.Equal(t, "List"+kind, method)
				return testCoreList(t, kind, nil, nil), nil
			})
			out, err := executeTestCommand(t, ctx, nil, "get", strings.ToLower(kind))
			require.NoError(t, err)
			assert.Contains(t, out, "No ")
			assert.Contains(t, out, "found")
			fail.Store(true)
			for _, args := range [][]string{{"get", strings.ToLower(kind)}, {"get", strings.ToLower(kind), "sample"}} {
				_, err := executeTestCommand(t, ctx, nil, args...)
				assert.Equal(t, codes.PermissionDenied, status.Code(err))
			}
			before := calls.Load()
			_, err = executeTestCommand(t, ctx, nil, "get", strings.ToLower(kind), "--out=xml")
			assert.ErrorContains(t, err, "Invalid output format")
			assert.Equal(t, before, calls.Load())
		})
	}
}

func TestDeleteResourceCommandsE2E(t *testing.T) {
	for _, itm := range []struct{ kind, alias string }{
		{"User", "usr"}, {"Group", "grp"}, {"Namespace", "ns"}, {"Service", "svc"},
		{"Credential", "cred"}, {"Device", "dev"}, {"Session", "sess"}, {"Secret", "sec"},
		{"Config", "cfg"}, {"Policy", "pol"}, {"IdentityProvider", "idp"}, {"Authenticator", "authn"},
	} {
		t.Run(itm.kind, func(t *testing.T) {
			var fail atomic.Bool
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				assert.Equal(t, "Delete"+itm.kind, method)
				name := "sample"
				if itm.kind == "Service" {
					name = "sample.default"
				}
				assert.Equal(t, name, req.(*metav1.DeleteOptions).Name)
				if fail.Load() {
					return nil, status.Error(codes.NotFound, "missing")
				}
				return &metav1.OperationResult{}, nil
			})
			for _, args := range [][]string{{"delete", strings.ToLower(itm.kind), "sample"}, {"del", itm.alias, "sample"}, {"rm", itm.alias, "sample"}} {
				out, err := executeTestCommand(t, ctx, nil, args...)
				require.NoError(t, err)
				assert.Contains(t, out, "successfully deleted")
				assert.Contains(t, out, "sample")
			}
			fail.Store(true)
			_, err := executeTestCommand(t, ctx, nil, "delete", itm.alias, "sample")
			assert.Equal(t, codes.NotFound, status.Code(err))
		})
	}
}

func TestResourceListFilters(t *testing.T) {
	for _, itm := range []struct{ kind, flag, field string }{
		{"Service", "namespace", "namespaceRef"}, {"Session", "user", "userRef"},
		{"Credential", "user", "userRef"}, {"Device", "user", "userRef"}, {"Authenticator", "user", "userRef"},
	} {
		t.Run(itm.kind, func(t *testing.T) {
			for _, filter := range []string{"", "filtered"} {
				ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
					assert.Equal(t, "List"+itm.kind, method)
					want, err := ucorev1.NewObjectListOptions(itm.kind)
					assert.NoError(t, err)
					data := map[string]any{"common": map[string]any{}}
					if filter != "" {
						data[itm.field] = map[string]any{"name": filter}
					}
					assert.NoError(t, pbutils.UnmarshalFromMap(data, want))
					assert.True(t, pbutils.IsEqual(want, req), "%s", req)
					return testCoreList(t, itm.kind, nil, nil), nil
				})
				_, err := executeTestCommand(t, ctx, nil, "get", strings.ToLower(itm.kind), "--"+itm.flag+"="+filter)
				require.NoError(t, err)
			}
		})
	}
}

func TestGetClusterConfigE2E(t *testing.T) {
	item := testCoreResource(t, "ClusterConfig", "default")
	var fail atomic.Bool
	ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
		assert.Equal(t, "GetClusterConfig", method)
		assert.IsType(t, &corev1.GetClusterConfigRequest{}, req)
		if fail.Load() {
			return nil, status.Error(codes.PermissionDenied, "denied")
		}
		return item, nil
	})
	for _, alias := range []string{"clusterconfig", "cc", "clustercfg", "cluster-config"} {
		for _, format := range []string{"json", "yaml", "yml", ""} {
			out, err := executeTestCommand(t, ctx, nil, "get", alias, "--out="+format)
			require.NoError(t, err)
			ret := &corev1.ClusterConfig{}
			if format == "json" {
				require.NoError(t, pbutils.UnmarshalJSON([]byte(out), ret))
			} else {
				require.NoError(t, pbutils.UnmarshalYAML([]byte(out), ret))
			}
			assert.True(t, pbutils.IsEqual(item, ret))
		}
	}
	fail.Store(true)
	_, err := executeTestCommand(t, ctx, nil, "get", "cc")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = executeTestCommand(t, ctx, nil, "get", "cc", "--out=xml")
	assert.ErrorContains(t, err, "Invalid output format")
}

func TestCreateSimpleResourcesE2E(t *testing.T) {
	for _, itm := range []struct {
		name  string
		extra *cobra.Command
		args  []string
		want  proto.Message
	}{
		{"namespace", nil, []string{"create", "ns", "sample"}, &corev1.Namespace{Metadata: &metav1.Metadata{Name: "sample"}, Spec: &corev1.Namespace_Spec{}}},
		{"group", creategroup.Cmd, []string{"create", "grp", "sample"}, &corev1.Group{Metadata: &metav1.Metadata{Name: "sample"}, Spec: &corev1.Group_Spec{}}},
		{"human", createuser.Cmd, []string{"create", "usr", "sample"}, &corev1.User{Metadata: &metav1.Metadata{Name: "sample"}, Spec: &corev1.User_Spec{Type: corev1.User_Spec_HUMAN}}},
		{"workload", createuser.Cmd, []string{"create", "user", "sample", "--type=WORKLOAD"}, &corev1.User{Metadata: &metav1.Metadata{Name: "sample"}, Spec: &corev1.User_Spec{Type: corev1.User_Spec_WORKLOAD}}},
		{"service", createservice.Cmd, []string{"create", "svc", "sample.production", "--upstream=https://upstream.example"}, &corev1.Service{Metadata: &metav1.Metadata{Name: "sample.production"}, Spec: &corev1.Service_Spec{Config: &corev1.Service_Spec_Config{Upstream: &corev1.Service_Spec_Config_Upstream{Type: &corev1.Service_Spec_Config_Upstream_Url{Url: "https://upstream.example"}}}}}},
	} {
		t.Run(itm.name, func(t *testing.T) {
			var fail atomic.Bool
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				assert.Equal(t, "Create"+string(itm.want.ProtoReflect().Descriptor().Name()), method)
				assert.True(t, pbutils.IsEqual(itm.want, req), "%s", req)
				if fail.Load() {
					return nil, status.Error(codes.AlreadyExists, "exists")
				}
				return req, nil
			})
			out, err := executeTestCommand(t, ctx, itm.extra, itm.args...)
			require.NoError(t, err)
			assert.Contains(t, out, "successfully created")
			fail.Store(true)
			_, err = executeTestCommand(t, ctx, itm.extra, itm.args...)
			assert.Equal(t, codes.AlreadyExists, status.Code(err))
		})
	}
}

func TestCreateAndUpdateDataSourcesE2E(t *testing.T) {
	for _, operation := range []string{"create", "update"} {
		for _, kind := range []string{"Secret", "Config"} {
			for _, source := range []string{"value", "file", "from-env", "stdin"} {
				t.Run(operation+"/"+kind+"/"+source, func(t *testing.T) {
					value := []byte("new-value\n")
					var methods []string
					var mu sync.Mutex
					ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
						mu.Lock()
						methods = append(methods, method)
						mu.Unlock()
						if method == "Get"+kind {
							assert.Equal(t, "sample", req.(*metav1.GetOptions).Name)
							return testCoreResource(t, kind, "sample"), nil
						}
						assert.Equal(t, strings.ToUpper(operation[:1])+operation[1:]+kind, method)
						var data []byte
						switch itm := req.(type) {
						case *corev1.Secret:
							data = itm.GetData().GetValueBytes()
						case *corev1.Config:
							data = itm.GetData().GetValueBytes()
						}
						assert.Equal(t, value, data)
						item := req.(umetav1.ResourceObjectI)
						assert.Equal(t, "sample", item.GetMetadata().GetName())
						if operation == "update" {
							assert.Equal(t, "sample-uid", item.GetMetadata().GetUid())
						}
						return req, nil
					})
					args := []string{operation, strings.ToLower(kind), "sample"}
					switch source {
					case "value":
						args = append(args, "--value="+string(value))
					case "file", "stdin":
						value = []byte{0, 1, 0xff, '\n'}
						path := filepath.Join(t.TempDir(), "value")
						require.NoError(t, os.WriteFile(path, value, 0600))
						if source == "stdin" {
							f, err := os.Open(path)
							require.NoError(t, err)
							previous := os.Stdin
							os.Stdin = f
							defer func() { os.Stdin = previous; f.Close() }()
							args = append(args, "--file=-")
						} else {
							args = append(args, "--file="+path)
						}
					case "from-env":
						t.Setenv("OCTELIUMCTL_TEST_VALUE", string(value))
						args = append(args, "--from-env=OCTELIUMCTL_TEST_VALUE")
					}
					out, err := executeTestCommand(t, ctx, nil, args...)
					require.NoError(t, err)
					assert.Contains(t, out, "successfully "+operation+"d")
					mu.Lock()
					defer mu.Unlock()
					if operation == "create" {
						assert.Equal(t, []string{"Create" + kind}, methods)
					} else {
						assert.Equal(t, []string{"Get" + kind, "Update" + kind}, methods)
					}
				})
			}
		}
	}
}

func TestCommandValidationBeforeRPC(t *testing.T) {
	var calls atomic.Int32
	ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
		calls.Add(1)
		return nil, status.Error(codes.PermissionDenied, "unexpected RPC")
	})
	for _, itm := range []struct {
		args []string
		want string
	}{
		{[]string{"create", "ns"}, "accepts 1 arg"},
		{[]string{"delete", "user"}, "accepts 1 arg"},
		{[]string{"delete", "user", "one", "two"}, "accepts 1 arg"},
		{[]string{"get", "user", "one", "two"}, "accepts at most 1 arg"},
		{[]string{"get", "cc", "extra"}, "unknown command"},
		{[]string{"update", "dev", "sample"}, "must set either"},
		{[]string{"update", "authn", "sample"}, "must set either"},
		{[]string{"update", "session", "sample"}, "must set at least one"},
		{[]string{"update", "cred", "sample"}, "must set at least one"},
		{[]string{"update", "dev", "sample", "--approve", "--reject"}, "none of the others can be"},
		{[]string{"update", "authn", "sample", "--approve", "--reject"}, "none of the others can be"},
		{[]string{"update", "sess", "sample", "--approve", "--reject"}, "none of the others can be"},
		{[]string{"update", "cred", "sample", "--enable", "--disable"}, "none of the others can be"},
		{[]string{"create", "credential"}, "User must be set"},
		{[]string{"create", "cred", "--type=unknown", "--user=alice"}, "Invalid Credential type"},
		{[]string{"create", "cred", "--session-type=unknown", "--user=alice"}, "Invalid Session type"},
		{[]string{"create", "cred", "--out=xml", "--user=alice"}, "Invalid output format"},
		{[]string{"create", "secret", "sample", "--type=unknown"}, "Invalid Secret type"},
		{[]string{"update", "secret", "sample", "--type=unknown"}, "Invalid Secret type"},
		{[]string{"get", "user", "--domain="}, "Cluster domain is not set"},
	} {
		t.Run(strings.Join(itm.args, "/"), func(t *testing.T) {
			t.Setenv("OCTELIUM_DOMAIN", "")
			_, err := executeTestCommand(t, ctx, nil, itm.args...)
			assert.ErrorContains(t, err, itm.want)
		})
	}
	assert.Zero(t, calls.Load())
}

func TestCommandsRequireAuthentication(t *testing.T) {
	ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
		t.Errorf("unexpected RPC: %s", method)
		return nil, status.Error(codes.PermissionDenied, "unexpected RPC")
	})
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_ASSERTION", "")
	ctx = authenticator.WithNonInteractive(ctx)
	for _, args := range [][]string{
		{"get", "user"}, {"delete", "user", "sample"}, {"create", "ns", "sample"},
		{"create", "secret", "sample", "--value=value"}, {"create", "config", "sample", "--value=value"},
		{"create", "cred", "--user=alice"}, {"update", "secret", "sample", "--value=value"},
		{"update", "config", "sample", "--value=value"}, {"update", "dev", "sample", "--approve"},
		{"update", "authn", "sample", "--approve"}, {"update", "sess", "sample", "--approve"},
		{"update", "cred", "sample", "--disable"},
	} {
		_, err := executeTestCommand(t, ctx, nil, args...)
		assert.ErrorIs(t, err, authenticator.ErrAuthenticationRequired)
	}
}

func TestCreateCredentialsE2E(t *testing.T) {
	for _, itm := range []struct{ arg, typ, tokenField, label string }{
		{"", "AUTH_TOKEN", "authenticationToken", "Authentication Token"},
		{"access", "ACCESS_TOKEN", "accessToken", "Access Token"},
		{"access-token", "ACCESS_TOKEN", "accessToken", "Access Token"},
		{"oauth2", "OAUTH2", "oauth2Credentials", "Client Secret"},
	} {
		for _, format := range []string{"", "json", "yaml"} {
			t.Run(itm.typ+"/"+itm.arg+"/"+format, func(t *testing.T) {
				var calls []string
				var mu sync.Mutex
				response := &corev1.CredentialToken{}
				data := map[string]any{itm.tokenField: map[string]any{itm.tokenField: "generated-token"}}
				if itm.arg == "oauth2" {
					data = map[string]any{"oauth2Credentials": map[string]any{"clientID": "client-id", "clientSecret": "client-secret"}}
				}
				require.NoError(t, pbutils.UnmarshalFromMap(data, response))
				started := time.Now()
				ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
					mu.Lock()
					calls = append(calls, method)
					mu.Unlock()
					if method == "GenerateCredentialToken" {
						assert.Equal(t, "credential-uid", req.(*corev1.GenerateCredentialTokenRequest).CredentialRef.Uid)
						return response, nil
					}
					assert.Equal(t, "CreateCredential", method)
					cred := req.(*corev1.Credential)
					assert.Equal(t, "alice", cred.Spec.User)
					assert.Equal(t, itm.typ, cred.Spec.Type.String())
					assert.Equal(t, uint32(5), cred.Spec.MaxAuthentications)
					assert.Equal(t, []string{"one", "two"}, cred.Spec.Authorization.Policies)
					assert.WithinDuration(t, started.Add(2*time.Hour), cred.Spec.ExpiresAt.AsTime(), 10*time.Second)
					if itm.arg == "oauth2" {
						assert.Equal(t, corev1.Session_Status_CLIENTLESS, cred.Spec.SessionType)
					} else {
						assert.Equal(t, corev1.Session_Status_CLIENT, cred.Spec.SessionType)
					}
					nameType := strings.ReplaceAll(strings.ToLower(itm.typ), "_", "-")
					assert.Regexp(t, "^alice-"+nameType+"-[a-z0-9]{4}$", cred.Metadata.Name)
					cred.Metadata.Uid = "credential-uid"
					return cred, nil
				})
				out, err := executeTestCommand(t, ctx, nil, "create", "cred", "--user=alice", "--type="+itm.arg,
					"--expire-in=2hours", "--one-time", "--max-authn=5", "--policy=one", "--policy=two", "--out="+format)
				require.NoError(t, err)
				if format == "" {
					assert.Contains(t, out, itm.label)
				} else {
					ret := &corev1.CredentialToken{}
					if format == "json" {
						assert.True(t, json.Valid([]byte(out)))
						require.NoError(t, pbutils.UnmarshalJSON([]byte(out), ret))
					} else {
						require.NoError(t, pbutils.UnmarshalYAML([]byte(out), ret))
					}
					assert.True(t, pbutils.IsEqual(response, ret))
					assert.NotContains(t, out, "successfully created")
				}
				mu.Lock()
				defer mu.Unlock()
				assert.Equal(t, []string{"CreateCredential", "GenerateCredentialToken"}, calls)
			})
		}
	}
}

func TestCredentialLimitsAndRotation(t *testing.T) {
	for _, itm := range []struct {
		args    []string
		maximum uint32
		session corev1.Session_Status_Type
	}{
		{[]string{"--user=alice", "named"}, 0, corev1.Session_Status_CLIENT},
		{[]string{"--user=alice", "named", "--one-time", "--session-type=clientless"}, 1, corev1.Session_Status_CLIENTLESS},
	} {
		ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
			if method == "CreateCredential" {
				cred := req.(*corev1.Credential)
				assert.Equal(t, "named", cred.Metadata.Name)
				assert.Equal(t, itm.maximum, cred.Spec.MaxAuthentications)
				assert.Equal(t, itm.session, cred.Spec.SessionType)
				assert.Nil(t, cred.Spec.ExpiresAt)
				assert.Nil(t, cred.Spec.Authorization)
				return cred, nil
			}
			assert.Equal(t, "GenerateCredentialToken", method)
			assert.Equal(t, "named", req.(*corev1.GenerateCredentialTokenRequest).CredentialRef.Name)
			return &corev1.CredentialToken{}, nil
		})
		_, err := executeTestCommand(t, ctx, nil, append([]string{"create", "cred"}, itm.args...)...)
		require.NoError(t, err)
	}
	var calls atomic.Int32
	ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
		calls.Add(1)
		assert.Equal(t, "GenerateCredentialToken", method)
		assert.Equal(t, "existing", req.(*corev1.GenerateCredentialTokenRequest).CredentialRef.Name)
		return &corev1.CredentialToken{}, nil
	})
	_, err := executeTestCommand(t, ctx, nil, "create", "cred", "existing", "--rotate")
	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load())
	_, err = executeTestCommand(t, ctx, nil, "create", "cred", "--rotate")
	assert.ErrorContains(t, err, "Credential name must be set")
	_, err = executeTestCommand(t, ctx, nil, "create", "cred", "--user=alice", "--expire-in=invalid")
	assert.Error(t, err)
	assert.Equal(t, int32(1), calls.Load())
}

func TestCredentialCreationRPCErrors(t *testing.T) {
	for _, failMethod := range []string{"CreateCredential", "GenerateCredentialToken"} {
		t.Run(failMethod, func(t *testing.T) {
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				if method == failMethod {
					return nil, status.Error(codes.PermissionDenied, "denied")
				}
				return req, nil
			})
			out, err := executeTestCommand(t, ctx, nil, "create", "cred", "named", "--user=alice")
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.NotContains(t, out, "Authentication Token:")
		})
	}
}

func TestUpdateApprovalCommandsE2E(t *testing.T) {
	for _, kind := range []string{"Device", "Authenticator", "Session"} {
		for _, action := range []string{"approve", "reject"} {
			t.Run(kind+"/"+action, func(t *testing.T) {
				item := testCoreResource(t, kind, "sample")
				require.NoError(t, pbutils.UnmarshalFromMap(map[string]any{
					"kind": kind, "metadata": map[string]any{"name": "sample", "uid": "sample-uid"},
					"spec": map[string]any{"state": "PENDING"},
				}, item))
				var calls []string
				var mu sync.Mutex
				ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
					mu.Lock()
					calls = append(calls, method)
					mu.Unlock()
					if method == "Get"+kind {
						assert.Equal(t, "sample", req.(*metav1.GetOptions).Name)
						return item, nil
					}
					assert.Equal(t, "Update"+kind, method)
					got := req.(umetav1.ResourceObjectI)
					assert.Equal(t, "sample-uid", got.GetMetadata().GetUid())
					data, err := pbutils.ConvertToMap(got)
					assert.NoError(t, err)
					want := "ACTIVE"
					if action == "reject" {
						want = "REJECTED"
					}
					assert.Equal(t, want, data["spec"].(map[string]any)["state"])
					return got, nil
				})
				out, err := executeTestCommand(t, ctx, nil, "update", strings.ToLower(kind), "sample", "--"+action)
				require.NoError(t, err)
				assert.Contains(t, out, "successfully updated")
				mu.Lock()
				defer mu.Unlock()
				assert.Equal(t, []string{"Get" + kind, "Update" + kind}, calls)
			})
		}
	}
}

func TestUpdateCredentialFieldsE2E(t *testing.T) {
	for _, itm := range []struct {
		name     string
		flags    []string
		disabled bool
		maximum  uint32
		policies []string
	}{
		{"disable", []string{"--disable"}, true, 10, []string{"existing"}},
		{"enable", []string{"--enable"}, false, 10, []string{"existing"}},
		{"zero limit", []string{"--max-authn=0"}, true, 0, []string{"existing"}},
		{"policies", []string{"--policy=one", "--policy=two"}, true, 10, []string{"one", "two"}},
		{"clear policies", []string{"--policy="}, true, 10, nil},
		{"combined", []string{"--enable", "--max-authn=3", "--policy=new", "--expire-in=2hours"}, false, 3, []string{"new"}},
	} {
		t.Run(itm.name, func(t *testing.T) {
			started := time.Now()
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				if method == "GetCredential" {
					return &corev1.Credential{Metadata: &metav1.Metadata{Name: "sample", Uid: "uid"}, Spec: &corev1.Credential_Spec{User: "alice", IsDisabled: true, MaxAuthentications: 10, Authorization: &corev1.Credential_Spec_Authorization{Policies: []string{"existing"}}}}, nil
				}
				assert.Equal(t, "UpdateCredential", method)
				cred := req.(*corev1.Credential)
				assert.Equal(t, "uid", cred.Metadata.Uid)
				assert.Equal(t, "alice", cred.Spec.User)
				assert.Equal(t, itm.disabled, cred.Spec.IsDisabled)
				assert.Equal(t, itm.maximum, cred.Spec.MaxAuthentications)
				assert.Equal(t, itm.policies, cred.Spec.GetAuthorization().GetPolicies())
				if itm.name == "combined" {
					assert.WithinDuration(t, started.Add(2*time.Hour), cred.Spec.ExpiresAt.AsTime(), 10*time.Second)
				} else {
					assert.Nil(t, cred.Spec.ExpiresAt)
				}
				return cred, nil
			})
			_, err := executeTestCommand(t, ctx, nil, append([]string{"update", "cred", "sample"}, itm.flags...)...)
			require.NoError(t, err)
		})
	}
}

func TestUpdateRPCErrors(t *testing.T) {
	for _, itm := range []struct {
		kind  string
		flags []string
	}{
		{"Device", []string{"--approve"}}, {"Authenticator", []string{"--approve"}},
		{"Session", []string{"--expire-in=1day"}}, {"Credential", []string{"--disable"}},
		{"Secret", []string{"--value=new"}}, {"Config", []string{"--value=new"}},
	} {
		for _, stage := range []string{"Get", "Update"} {
			t.Run(stage+itm.kind, func(t *testing.T) {
				ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
					if method == stage+itm.kind {
						return nil, status.Error(codes.PermissionDenied, "denied")
					}
					item := testCoreResource(t, itm.kind, "sample")
					assert.NoError(t, pbutils.UnmarshalFromMap(map[string]any{"spec": map[string]any{}}, item))
					return item, nil
				})
				out, err := executeTestCommand(t, ctx, nil, append([]string{"update", strings.ToLower(itm.kind), "sample"}, itm.flags...)...)
				assert.Equal(t, codes.PermissionDenied, status.Code(err))
				assert.NotContains(t, out, "successfully updated")
			})
		}
	}
}

func TestSecretCertificateCommandsE2E(t *testing.T) {
	for _, operation := range []string{"create", "update"} {
		t.Run(operation, func(t *testing.T) {
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				if method == "GetSecret" {
					return testCoreResource(t, "Secret", "sample"), nil
				}
				assert.Equal(t, strings.ToUpper(operation[:1])+operation[1:]+"Secret", method)
				secret := req.(*corev1.Secret)
				chain, key, err := ucorev1.ToSecret(secret).GetCertificateChainAndKey()
				assert.NoError(t, err)
				assert.Equal(t, "test-certificate", string(chain))
				assert.Equal(t, "test-private-key", string(key))
				return secret, nil
			})
			cert, key := filepath.Join(t.TempDir(), "cert"), filepath.Join(t.TempDir(), "key")
			require.NoError(t, os.WriteFile(cert, []byte("test-certificate"), 0600))
			require.NoError(t, os.WriteFile(key, []byte("test-private-key"), 0600))
			for _, typ := range []string{"value", "cert"} {
				_, err := executeTestCommand(t, ctx, nil, operation, "secret", "sample", "--type="+typ, "--cert="+cert, "--cert-key="+key)
				require.NoError(t, err)
			}
		})
	}
}

func TestSecretCertificateAndValueErrors(t *testing.T) {
	for _, operation := range []string{"create", "update"} {
		for _, kind := range []string{"Secret", "Config"} {
			t.Run(operation+kind, func(t *testing.T) {
				var writes atomic.Int32
				ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
					if method == "Get"+kind {
						return testCoreResource(t, kind, "sample"), nil
					}
					writes.Add(1)
					return req, nil
				})
				missing := filepath.Join(t.TempDir(), "missing")
				flags := [][]string{{"--value=one", "--file=" + missing}, {"--from-env=OCTELIUMCTL_UNSET_VALUE"}, {"--file=" + missing}, {}}
				if kind == "Secret" {
					flags = append(flags, []string{"--type=cert"}, []string{"--cert=" + missing}, []string{"--cert-key=" + missing},
						[]string{"--cert=" + missing, "--cert-key=" + missing, "--value=value"}, []string{"--cert=" + missing, "--cert-key=" + missing})
					cert := filepath.Join(t.TempDir(), "cert")
					require.NoError(t, os.WriteFile(cert, []byte("cert"), 0600))
					flags = append(flags, []string{"--cert=" + cert, "--cert-key=" + missing})
				}
				for _, flag := range flags {
					_, err := executeTestCommand(t, ctx, nil, append([]string{operation, strings.ToLower(kind), "sample"}, flag...)...)
					assert.Error(t, err, "flags: %v", flag)
				}
				assert.Zero(t, writes.Load())
			})
		}
	}
}

func TestUnregisteredCreateCommandValidation(t *testing.T) {
	t.Setenv("OCTELIUM_DOMAIN", "")
	ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
		t.Errorf("unexpected RPC: %s", method)
		return nil, status.Error(codes.PermissionDenied, "unexpected RPC")
	})
	_, err := executeTestCommand(t, ctx, createuser.Cmd, "create", "user", "sample", "--type=unknown")
	assert.ErrorContains(t, err, "Invalid User type")
	_, err = executeTestCommand(t, ctx, createservice.Cmd, "create", "svc", "invalid.service.name")
	assert.ErrorContains(t, err, "Could not parse Service")
	_, err = executeTestCommand(t, ctx, nil, "delete", "svc", "invalid.service.name")
	assert.ErrorContains(t, err, "Could not parse Service")
	for _, extra := range []*cobra.Command{createuser.Cmd, creategroup.Cmd, createservice.Cmd} {
		_, err = executeTestCommand(t, ctx, extra, "create", extra.Name(), "sample", "--domain=")
		assert.ErrorContains(t, err, "Cluster domain is not set", fmt.Sprintf("command: %s", extra.Name()))
	}
}

func TestApplyResourcesE2E(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		for _, prune := range []bool{false, true} {
			t.Run(fmt.Sprintf("dryRun=%t/prune=%t", dryRun, prune), func(t *testing.T) {
				var mu sync.Mutex
				var mutations []string
				current := map[string]umetav1.ResourceObjectI{
					"Namespace/old":    testCoreResource(t, "Namespace", "old"),
					"Namespace/system": &corev1.Namespace{Kind: "Namespace", Metadata: &metav1.Metadata{Name: "system", IsSystem: true}},
					"User/alice":       &corev1.User{Kind: "User", Metadata: &metav1.Metadata{Name: "alice", Uid: "alice-uid"}, Spec: &corev1.User_Spec{Type: corev1.User_Spec_HUMAN}},
					"Service/old.old":  testCoreResource(t, "Service", "old.old"),
				}
				var listPages []uint32
				ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
					mu.Lock()
					defer mu.Unlock()
					if strings.HasPrefix(method, "List") {
						kind := strings.TrimPrefix(method, "List")
						var items []umetav1.ResourceObjectI
						for _, item := range current {
							if item.GetKind() == kind {
								items = append(items, item)
							}
						}
						slices.SortFunc(items, func(a, b umetav1.ResourceObjectI) int {
							return strings.Compare(a.GetMetadata().Name, b.GetMetadata().Name)
						})
						msg := req.ProtoReflect()
						common := msg.Get(msg.Descriptor().Fields().ByName("common")).Message()
						page := uint32(common.Get(common.Descriptor().Fields().ByName("page")).Uint())
						if kind == "Namespace" {
							listPages = append(listPages, page)
						}
						if int(page) >= len(items) {
							return testCoreList(t, kind, nil, nil), nil
						}
						return testCoreList(t, kind, items[page:page+1], &metav1.ListResponseMeta{HasMore: int(page)+1 < len(items)}), nil
					}
					if strings.HasPrefix(method, "Delete") {
						uid := req.(*metav1.DeleteOptions).Uid
						for key, item := range current {
							if item.GetMetadata().Uid == uid {
								mutations = append(mutations, method+" "+item.GetMetadata().Name)
								delete(current, key)
							}
						}
						return &metav1.OperationResult{}, nil
					}
					item := req.(umetav1.ResourceObjectI)
					mutations = append(mutations, method+" "+item.GetMetadata().Name)
					current[item.GetKind()+"/"+item.GetMetadata().Name] = item
					return item, nil
				})
				dir := t.TempDir()
				ns := filepath.Join(dir, "namespace.yaml")
				resources := filepath.Join(dir, "resources.yml")
				require.NoError(t, os.WriteFile(ns, []byte("kind: Namespace\nmetadata: {name: new}\n"), 0600))
				require.NoError(t, os.WriteFile(resources, []byte("kind: User\nmetadata: {name: alice}\nspec: {type: WORKLOAD}\n---\nkind: Service\nmetadata: {name: api.new}\nspec: {port: 443}\n---\nkind: Secret\nmetadata: {name: excluded}\ndata: {value: secret-value}\n"), 0600))
				args := []string{"apply", ns, resources, "--include=Namespace", "--include=User", "--include=Service", fmt.Sprintf("--dry-run=%t", dryRun), fmt.Sprintf("--prune=%t", prune)}
				out, err := executeTestCommand(t, ctx, nil, args...)
				require.NoError(t, err)
				assert.Contains(t, out, "2 resources created")
				assert.Contains(t, out, "1 resources updated")
				assert.Contains(t, out, "Skipping the Secret `excluded`")
				assert.NotContains(t, out, "secret-value")
				if prune {
					assert.Contains(t, out, "2 resources deleted")
				}
				if dryRun {
					assert.Contains(t, out, "(dry run)")
				}
				mu.Lock()
				assert.Equal(t, []uint32{0, 1}, listPages)
				assert.Contains(t, current, "Namespace/system")
				if dryRun {
					assert.Empty(t, mutations)
				} else {
					want := []string{"CreateNamespace new", "UpdateUser alice", "CreateService api.new"}
					if prune {
						want = append(want, "DeleteService old.old", "DeleteNamespace old")
					}
					assert.Equal(t, want, mutations)
				}
				mu.Unlock()
				if !dryRun {
					out, err = executeTestCommand(t, ctx, nil, args...)
					require.NoError(t, err)
					assert.Contains(t, out, "No applied changes")
				}
			})
		}
	}
}

func TestApplyClusterConfigAndSecretsE2E(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		t.Run(fmt.Sprintf("dryRun=%t", dryRun), func(t *testing.T) {
			var writes atomic.Int32
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				switch method {
				case "ListSecret":
					return &corev1.SecretList{}, nil
				case "CreateSecret":
					writes.Add(1)
					assert.Equal(t, "secret-value", req.(*corev1.Secret).GetData().GetValue())
					return req, nil
				case "GetClusterConfig":
					return &corev1.ClusterConfig{Metadata: &metav1.Metadata{Name: "default", DisplayName: "old"}, Spec: &corev1.ClusterConfig_Spec{}}, nil
				case "UpdateClusterConfig":
					writes.Add(1)
					assert.Equal(t, "new", req.(*corev1.ClusterConfig).Metadata.DisplayName)
					return req, nil
				default:
					t.Errorf("unexpected RPC: %s", method)
					return nil, status.Error(codes.PermissionDenied, "unexpected RPC")
				}
			})
			path := filepath.Join(t.TempDir(), "resources.yaml")
			require.NoError(t, os.WriteFile(path, []byte("kind: ClusterConfig\nmetadata: {name: default, displayName: new}\nspec: {}\n---\nkind: Secret\nmetadata: {name: sample}\ndata: {value: secret-value}\n"), 0600))
			out, err := executeTestCommand(t, ctx, nil, "apply", path, "--include=Secret", "--include-secret", fmt.Sprintf("--dry-run=%t", dryRun))
			require.NoError(t, err)
			assert.Contains(t, out, "ClusterConfig updated")
			assert.Contains(t, out, "1 resources created")
			if dryRun {
				assert.Zero(t, writes.Load())
			} else {
				assert.Equal(t, int32(2), writes.Load())
			}
		})
	}
}

func TestApplyAbortsOnRPCErrors(t *testing.T) {
	for _, stage := range []string{"ListUser", "CreateUser", "DeleteUser", "GetClusterConfig", "UpdateClusterConfig"} {
		t.Run(stage, func(t *testing.T) {
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				if method == stage {
					return nil, status.Error(codes.PermissionDenied, "denied")
				}
				switch method {
				case "ListUser":
					if stage == "DeleteUser" {
						return testCoreList(t, "User", []umetav1.ResourceObjectI{testCoreResource(t, "User", "old")}, nil), nil
					}
					return &corev1.UserList{}, nil
				case "GetClusterConfig":
					return &corev1.ClusterConfig{Metadata: &metav1.Metadata{Name: "default"}}, nil
				default:
					return req, nil
				}
			})
			path := filepath.Join(t.TempDir(), "resources.yaml")
			require.NoError(t, os.WriteFile(path, []byte("kind: User\nmetadata: {name: alice}\n---\nkind: ClusterConfig\nmetadata: {name: default, displayName: changed}\n"), 0600))
			_, err := executeTestCommand(t, ctx, nil, "apply", path, "--include=User", "--prune")
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
		})
	}
}

func TestApplyInputValidation(t *testing.T) {
	var calls atomic.Int32
	ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
		calls.Add(1)
		return nil, status.Error(codes.PermissionDenied, "unexpected RPC")
	})
	duplicate := filepath.Join(t.TempDir(), "duplicate.yaml")
	require.NoError(t, os.WriteFile(duplicate, []byte("kind: ClusterConfig\nmetadata: {name: default}\n---\nkind: ClusterConfig\nmetadata: {name: default}\n"), 0600))
	for _, args := range [][]string{
		{"apply"}, {"apply", t.TempDir()}, {"apply", filepath.Join(t.TempDir(), "missing")},
		{"apply", duplicate}, {"apply", duplicate, "--include=Device"}, {"apply", duplicate, "--exclude=Unknown"},
	} {
		_, err := executeTestCommand(t, ctx, nil, args...)
		assert.Error(t, err, "args: %v", args)
	}
	assert.Zero(t, calls.Load())
}

func TestValidateCommandE2E(t *testing.T) {
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	t.Setenv("OCTELIUM_DOMAIN", "")
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.yaml")
	invalid := filepath.Join(t.TempDir(), "invalid.yaml")
	require.NoError(t, os.WriteFile(valid, []byte("kind: User\nmetadata: {name: alice}\nspec: {type: HUMAN}\n"), 0600))
	require.NoError(t, os.WriteFile(invalid, []byte("kind: Service\nmetadata: {name: api}\nspec: {port: invalid}\n---\nkind: Device\nmetadata: {name: device}\n"), 0600))
	out, err := executeTestCommand(t, context.Background(), nil, "--domain=", "validate", dir)
	require.NoError(t, err)
	assert.Contains(t, out, "All 1 Resources are valid")
	out, err = executeTestCommand(t, context.Background(), nil, "validate", valid, invalid)
	assert.ErrorContains(t, err, "Validation failed with 2 errors")
	assert.Contains(t, out, "Invalid Service `api`")
	assert.Contains(t, out, "Device `device` cannot be applied")
	for _, args := range [][]string{{"validate"}, {"validate", t.TempDir()}, {"validate", filepath.Join(t.TempDir(), "missing")}} {
		_, err := executeTestCommand(t, context.Background(), nil, args...)
		assert.Error(t, err)
	}
	f, err := os.Open(valid)
	require.NoError(t, err)
	previous := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = previous; f.Close() }()
	out, err = executeTestCommand(t, context.Background(), nil, "validate", "-")
	require.NoError(t, err)
	assert.Contains(t, out, "All 1 Resources are valid")
}

func TestResourceCommandHelpAndAliases(t *testing.T) {
	testCommandsOnce.Do(InitCmds)
	var restore []func()
	defer func() {
		for i := len(restore) - 1; i >= 0; i-- {
			restore[i]()
		}
	}()
	root := cloneTestCommand(Cmd, &restore)
	for _, operation := range []string{"create", "get", "update", "delete"} {
		group, _, err := root.Find([]string{operation})
		require.NoError(t, err)
		require.Equal(t, operation, group.Name())
		seen := make(map[string]string)
		for _, cmd := range group.Commands() {
			t.Run(operation+"/"+cmd.Name(), func(t *testing.T) {
				assert.NotEmpty(t, cmd.Short)
				assert.NotEmpty(t, strings.TrimSpace(cmd.Example))
				assert.NotNil(t, cmd.Args)
				for _, name := range append([]string{cmd.Name()}, cmd.Aliases...) {
					if previous, ok := seen[name]; ok {
						t.Errorf("%s belongs to both %s and %s", name, previous, cmd.Name())
					}
					seen[name] = cmd.Name()
					found, remaining, err := root.Find([]string{operation, name})
					require.NoError(t, err)
					assert.Empty(t, remaining)
					assert.Same(t, cmd, found)
				}
				var out strings.Builder
				cmd.SetOut(&out)
				require.NoError(t, cmd.Help())
				assert.Contains(t, out.String(), cmd.Short)
				assert.Contains(t, out.String(), "octeliumctl "+operation+" "+cmd.Name())
				for _, line := range strings.Split(cmd.Example, "\n") {
					line = strings.TrimSpace(line)
					if !strings.HasPrefix(line, "octeliumctl ") {
						continue
					}
					args := strings.Fields(line)[1:]
					found, _, err := root.Find(args)
					require.NoError(t, err, "example: %s", line)
					assert.Same(t, cmd, found, "example: %s", line)
					require.NoError(t, cmd.ParseFlags(args[2:]), "example: %s", line)
					require.NoError(t, cmd.ValidateArgs(cmd.Flags().Args()), "example: %s", line)
				}
			})
		}
	}
}

func TestResourceTableDetails(t *testing.T) {
	for _, itm := range []struct {
		kind string
		data map[string]any
		want []string
	}{
		{"Service", map[string]any{"spec": map[string]any{"mode": "HTTP", "port": 8080, "isPublic": true, "isAnonymous": true, "isTLS": true}, "status": map[string]any{
			"primaryHostname": "api.production", "port": 8080, "namespaceRef": map[string]any{"name": "production"}, "addresses": []any{
				map[string]any{"dualStackIP": map[string]any{"ipv4": "10.20.30.40", "ipv6": "fd00::123"}},
				map[string]any{"dualStackIP": map[string]any{"ipv6": "fd00::456"}},
			},
		}}, []string{"api.production", "10.20.30.40", "fd00::123", "fd00::456", "8080", "True"}},
		{"User", map[string]any{"spec": map[string]any{"type": "WORKLOAD", "email": "alice@example.com", "groups": []any{"engineering", "production"}, "isDisabled": true}}, []string{"WORKLOAD", "alice@example.com", "engineering", "production", "True"}},
		{"Authenticator", map[string]any{"spec": map[string]any{"state": "ACTIVE"}, "status": map[string]any{"type": "TOTP", "isRegistered": true, "successfulAuthentications": 3, "totalAuthenticationAttempts": 4, "userRef": map[string]any{"name": "alice"}}}, []string{"TOTP", "3/4", "alice", "True"}},
		{"Session", map[string]any{"status": map[string]any{"type": "CLIENTLESS", "isBrowser": true, "isConnected": true}}, []string{"CLIENTLESS", "Browser", "True"}},
		{"Policy", map[string]any{"spec": map[string]any{"rules": []any{map[string]any{"effect": "ALLOW"}}, "isDisabled": true}}, []string{"True", "1"}},
		{"Region", map[string]any{"status": map[string]any{"ingressAddresses": []any{"203.0.113.1", "2001:db8::1"}}}, []string{"203.0.113.1", "2001:db8::1"}},
	} {
		t.Run(itm.kind, func(t *testing.T) {
			item := testCoreResource(t, itm.kind, "sample")
			itm.data["metadata"] = map[string]any{"name": "sample"}
			require.NoError(t, pbutils.UnmarshalFromMap(itm.data, item))
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) { return item, nil })
			out, err := executeTestCommand(t, ctx, nil, "get", strings.ToLower(itm.kind), "sample")
			require.NoError(t, err)
			for _, want := range itm.want {
				assert.Contains(t, out, want)
			}
		})
	}
}

func TestSessionExpirationUpdates(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(fmt.Sprintf("valid=%t", valid), func(t *testing.T) {
			started := time.Now()
			var writes atomic.Int32
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				if method == "GetSession" {
					return &corev1.Session{Metadata: &metav1.Metadata{Name: "sample", Uid: "uid"}, Spec: &corev1.Session_Spec{State: corev1.Session_Spec_PENDING}}, nil
				}
				writes.Add(1)
				sess := req.(*corev1.Session)
				assert.Equal(t, corev1.Session_Spec_PENDING, sess.Spec.State)
				assert.Equal(t, "uid", sess.Metadata.Uid)
				assert.WithinDuration(t, started.Add(time.Hour), sess.Spec.ExpiresAt.AsTime(), 10*time.Second)
				return sess, nil
			})
			duration := "invalid"
			if valid {
				duration = "1hour"
			}
			_, err := executeTestCommand(t, ctx, nil, "update", "sess", "sample", "--expire-in="+duration)
			if valid {
				require.NoError(t, err)
				assert.Equal(t, int32(1), writes.Load())
			} else {
				assert.Error(t, err)
				assert.Zero(t, writes.Load())
			}
		})
	}
	ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
		assert.Equal(t, "GetCredential", method)
		return &corev1.Credential{Spec: &corev1.Credential_Spec{}}, nil
	})
	_, err := executeTestCommand(t, ctx, nil, "update", "cred", "sample", "--expire-in=invalid")
	assert.Error(t, err)
}

func TestResourceCommandDomainAndAuthenticationErrors(t *testing.T) {
	ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
		t.Errorf("unexpected RPC: %s", method)
		return nil, status.Error(codes.PermissionDenied, "unexpected RPC")
	})
	t.Setenv("OCTELIUM_DOMAIN", "")
	t.Setenv("OCTELIUM_AUTH_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_ASSERTION", "")
	var cases []struct {
		args  []string
		extra *cobra.Command
	}
	for _, kind := range []string{"user", "group", "namespace", "service", "credential", "device", "session", "secret", "config", "policy", "identityprovider", "region", "gateway", "authenticator", "clusterconfig"} {
		cases = append(cases, struct {
			args  []string
			extra *cobra.Command
		}{args: []string{"get", kind}})
		if kind != "region" && kind != "gateway" && kind != "clusterconfig" {
			cases = append(cases, struct {
				args  []string
				extra *cobra.Command
			}{args: []string{"delete", kind, "sample"}})
		}
	}
	for _, args := range [][]string{
		{"create", "ns", "sample"}, {"create", "secret", "sample", "--value=value"}, {"create", "config", "sample", "--value=value"}, {"create", "cred", "--user=alice"},
		{"update", "secret", "sample", "--value=value"}, {"update", "config", "sample", "--value=value"}, {"update", "cred", "sample", "--disable"},
		{"update", "sess", "sample", "--approve"}, {"update", "dev", "sample", "--approve"}, {"update", "authn", "sample", "--approve"},
	} {
		cases = append(cases, struct {
			args  []string
			extra *cobra.Command
		}{args: args})
	}
	for _, extra := range []*cobra.Command{createuser.Cmd, creategroup.Cmd, createservice.Cmd} {
		cases = append(cases, struct {
			args  []string
			extra *cobra.Command
		}{args: []string{"create", extra.Name(), "sample"}, extra: extra})
	}
	for _, itm := range cases {
		t.Run(strings.Join(itm.args, "/"), func(t *testing.T) {
			_, err := executeTestCommand(t, ctx, itm.extra, append(slices.Clone(itm.args), "--domain=")...)
			assert.ErrorContains(t, err, "Cluster domain is not set")
			t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
			_, err = executeTestCommand(t, authenticator.WithNonInteractive(ctx), itm.extra, itm.args...)
			assert.ErrorIs(t, err, authenticator.ErrAuthenticationRequired)
		})
	}
}

func TestCreateDataRPCErrors(t *testing.T) {
	for _, kind := range []string{"Secret", "Config"} {
		t.Run(kind, func(t *testing.T) {
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				assert.Equal(t, "Create"+kind, method)
				return nil, status.Error(codes.PermissionDenied, "denied")
			})
			out, err := executeTestCommand(t, ctx, nil, "create", strings.ToLower(kind), "sample", "--value=value")
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
			assert.NotContains(t, out, "successfully created")
		})
	}
}

func TestGetOutputSerializationErrors(t *testing.T) {
	for _, kind := range []string{"User", "Group", "Namespace", "Service", "Credential", "Device", "Session", "Secret", "Config", "Policy", "IdentityProvider", "Region", "Gateway", "Authenticator", "ClusterConfig"} {
		t.Run(kind, func(t *testing.T) {
			item := testCoreResource(t, kind, "sample")
			item.GetMetadata().CreatedAt.Seconds = 253402300800
			ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				if strings.HasPrefix(method, "List") {
					return testCoreList(t, kind, []umetav1.ResourceObjectI{item}, nil), nil
				}
				return item, nil
			})
			for _, named := range []bool{false, true} {
				if kind == "ClusterConfig" && named {
					continue
				}
				for _, format := range []string{"json", "yaml"} {
					args := []string{"get", strings.ToLower(kind), "--out=" + format}
					if named {
						args = append(args, "sample")
					}
					out, err := executeTestCommand(t, ctx, nil, args...)
					assert.ErrorContains(t, err, "Timestamp")
					assert.Empty(t, out)
				}
			}
		})
	}
}

func TestApplyDomainAndAuthenticationErrors(t *testing.T) {
	ctx := newTestCoreServer(t, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
		t.Errorf("unexpected RPC: %s", method)
		return nil, status.Error(codes.PermissionDenied, "unexpected RPC")
	})
	t.Setenv("OCTELIUM_DOMAIN", "")
	path := filepath.Join(t.TempDir(), "resource.yaml")
	require.NoError(t, os.WriteFile(path, []byte("kind: User\nmetadata: {name: alice}\n"), 0600))
	_, err := executeTestCommand(t, ctx, nil, "apply", path, "--domain=")
	assert.ErrorContains(t, err, "Cluster domain is not set")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_ASSERTION", "")
	_, err = executeTestCommand(t, authenticator.WithNonInteractive(ctx), nil, "apply", path)
	assert.ErrorIs(t, err, authenticator.ErrAuthenticationRequired)
}
