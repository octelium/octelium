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

package cliutils

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/db"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestPreRunPreservesContext(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("homedir", t.TempDir(), "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd.SetContext(ctx)

	assert.NoError(t, PreRun(cmd, nil))
	assert.Equal(t, ctx, cmd.Context())
	assert.NoError(t, CloseDB())
}

func TestIsKubernetes(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	assert.False(t, IsKubernetes())

	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	assert.True(t, IsKubernetes())
}

func TestIsContainerRuntime(t *testing.T) {
	{
		t.Setenv("OCTELIUM_CONTAINER_MODE", "true")
		assert.True(t, IsContainerRuntime())
	}

	{
		t.Setenv("OCTELIUM_CONTAINER_MODE", "")
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		t.Setenv("container", "")
		assert.Equal(t, IsLinux() && isContainerFile(), IsContainerRuntime())
	}

	{
		t.Setenv("OCTELIUM_CONTAINER_MODE", "")
		t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
		assert.Equal(t, IsLinux(), IsContainerRuntime())
	}

	{
		t.Setenv("OCTELIUM_CONTAINER_MODE", "")
		t.Setenv("KUBERNETES_SERVICE_HOST", "")
		t.Setenv("container", "podman")
		assert.Equal(t, IsLinux(), IsContainerRuntime())
	}
}

func TestIsOS(t *testing.T) {
	assert.Equal(t, runtime.GOOS == "linux", IsLinux())
	assert.Equal(t, runtime.GOOS == "darwin", IsDarwin())
	assert.Equal(t, runtime.GOOS == "windows", IsWindows())
	assert.Equal(t, runtime.GOOS == "android", IsAndroid())
	assert.Equal(t, runtime.GOOS == "ios", IsIOS())
}

func TestGetCLIInfo(t *testing.T) {
	for _, itm := range []struct {
		name string
		flag string
		env  string
		want string
	}{
		{"flag", "flag.example", "env.example", "flag.example"},
		{"environment", "", "env.example", "env.example"},
		{"missing", "", "", ""},
	} {
		t.Run(itm.name, func(t *testing.T) {
			t.Setenv("OCTELIUM_DOMAIN", itm.env)
			cmd := &cobra.Command{}
			cmd.Flags().String("domain", itm.flag, "")
			args := []string{"first", "second"}
			ret, err := GetCLIInfo(cmd, args)
			if itm.want == "" {
				assert.ErrorContains(t, err, "Cluster domain is not set")
				assert.Nil(t, ret)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, itm.want, ret.Domain)
			assert.Equal(t, args, ret.Args())
			assert.Equal(t, "first", ret.FirstArg())
		})
	}
	t.Setenv("OCTELIUM_DOMAIN", "env.example")
	ret, err := GetCLIInfo(&cobra.Command{}, nil)
	require.NoError(t, err)
	assert.Empty(t, ret.FirstArg())
	assert.Empty(t, ret.Args())
}

func TestServiceNamespace(t *testing.T) {
	for _, itm := range []struct {
		arg       string
		service   string
		namespace string
		fullName  string
	}{
		{"api", "api", "default", "api.default"},
		{"api.production", "api", "production", "api.production"},
	} {
		ret, err := ParseServiceNamespace(itm.arg)
		require.NoError(t, err)
		assert.Equal(t, itm.service, ret.Service)
		assert.Equal(t, itm.namespace, ret.Namespace)
		assert.Equal(t, itm.fullName, ret.String())
		assert.Equal(t, itm.fullName, GetServiceFullNameFromName(itm.arg))
	}
	ret, err := ParseServiceNamespace("api.production.example")
	assert.Error(t, err)
	assert.Nil(t, ret)
	assert.Empty(t, GetServiceFullNameFromName("api.production.example"))
	assert.Empty(t, GetServiceFullNameFromName(""))
	assert.Equal(t, "True", PrintBoolean(true))
	assert.Empty(t, PrintBoolean(false))
}

func TestGetCommonListOptions(t *testing.T) {
	assert.Nil(t, GetCommonListOptions(nil))
	assert.Equal(t, &metav1.CommonListOptions{}, GetCommonListOptions(&cobra.Command{}))
	for _, itm := range []struct {
		page    uint32
		byName  bool
		reverse bool
	}{
		{0, false, false}, {1, true, false}, {3, false, true}, {7, true, true},
	} {
		cmd := &cobra.Command{}
		cmd.Flags().Uint32("page", itm.page, "")
		cmd.Flags().Uint32("items-per-page", 25, "")
		cmd.Flags().Bool("order-by-name", itm.byName, "")
		cmd.Flags().Bool("order-reverse", itm.reverse, "")
		ret := GetCommonListOptions(cmd)
		page := itm.page
		if page > 0 {
			page--
		}
		assert.Equal(t, page, ret.Page)
		assert.Equal(t, uint32(25), ret.ItemsPerPage)
		if itm.byName || itm.reverse {
			require.NotNil(t, ret.OrderBy)
			if itm.byName {
				assert.Equal(t, metav1.CommonListOptions_OrderBy_NAME, ret.OrderBy.Type)
			}
			if itm.reverse {
				assert.Equal(t, metav1.CommonListOptions_OrderBy_DESC, ret.OrderBy.Mode)
			}
		} else {
			assert.Nil(t, ret.OrderBy)
		}
	}
	cmd := &cobra.Command{}
	cmd.Flags().String("page", "invalid", "")
	assert.Zero(t, GetCommonListOptions(cmd).Page)
}

func TestDBContextAndRefreshToken(t *testing.T) {
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	prev := dbC
	t.Cleanup(func() { dbC = prev })
	require.NoError(t, OpenDB("mem"))
	t.Cleanup(func() { assert.NoError(t, CloseDB()) })
	assert.Same(t, GetDB(), GetDBFromCtx(context.Background()))
	assert.Same(t, GetDB(), GetDBFromCtx(WithDB(context.Background(), nil)))
	other, err := db.Open("mem")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, other.Close()) })
	ctx := WithDB(context.Background(), other)
	assert.Same(t, other, GetDBFromCtx(ctx))
	_, err = GetRefreshToken(ctx, "example.com")
	assert.ErrorIs(t, err, db.ErrNotFound)
	require.NoError(t, other.SetSessionToken("example.com", &authv1.SessionToken{RefreshToken: "refresh"}))
	ret, err := GetRefreshToken(ctx, "example.com")
	require.NoError(t, err)
	assert.Equal(t, "refresh", ret)
}

func TestAgeAndExpiration(t *testing.T) {
	arg := time.Now().Add(-2*time.Hour - 5*time.Minute).Format(time.RFC3339Nano)
	ret, err := GetAgeFromTimestamp(arg)
	require.NoError(t, err)
	assert.Equal(t, "125m", ret)
	assert.Equal(t, ret, GetAgeFromTimestampMust(arg))
	_, err = GetAgeFromTimestamp("invalid")
	assert.Error(t, err)
	assert.Empty(t, GetAgeFromTimestampMust("invalid"))
	assert.Empty(t, GetResourceAge(nil))
	assert.Empty(t, GetResourceAge(&corev1.User{}))
	assert.Equal(t, ret, GetResourceAge(&corev1.User{Metadata: &metav1.Metadata{
		CreatedAt: pbutils.Timestamp(time.Now().Add(-2*time.Hour - 5*time.Minute)),
	}}))
	assert.Empty(t, PrintExpiresAt(nil))
	assert.Equal(t, "125m", PrintExpiresAt(pbutils.Timestamp(time.Now().Add(2*time.Hour+5*time.Minute+30*time.Second))))
}

func TestVersionAndGenesisImage(t *testing.T) {
	ret := GetOcteliumCommonVersion()
	assert.Equal(t, runtime.Version(), ret.GoVersion)
	assert.Equal(t, ldflags.SemVer, ret.ReleaseVersion)
	assert.Equal(t, ldflags.GitCommit, ret.GitCommit)
	assert.Equal(t, "v1", ret.APIVersion)
	assert.Equal(t, ldflags.GetImage("octelium-genesis", "1.2.3"), GetGenesisImage("1.2.3"))
	assert.Equal(t, ldflags.GetImage("custom-genesis", "1.2.3"), GetGenesisImageWithPackage("custom", "1.2.3"))
}

func TestOpenFileByDefaultAppCmd(t *testing.T) {
	arg := "https://example.com/login?token=value"
	cmd, err := OpenFileByDefaultAppCmd(arg)
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		assert.Error(t, err)
		assert.Nil(t, cmd)
		return
	}
	require.NoError(t, err)
	switch runtime.GOOS {
	case "linux":
		assert.Equal(t, []string{"xdg-open", arg}, cmd.Args)
	case "darwin":
		assert.Equal(t, []string{"open", arg}, cmd.Args)
	case "windows":
		assert.Equal(t, []string{"rundll32", "url.dll,FileProtocolHandler", arg}, cmd.Args)
	}
}

func TestGrpcErrFormatting(t *testing.T) {
	err := errors.New("plain error")
	assert.Same(t, err, GrpcErr(err))
	assert.EqualError(t, GrpcErr(status.Error(codes.PermissionDenied, "denied")), "gRPC error PermissionDenied: denied")
	assert.EqualError(t, GrpcErr(&ExitError{Err: status.Error(codes.NotFound, "missing"), Code: 2}), "gRPC error NotFound: missing")
}

func TestSpinnerLifecycle(t *testing.T) {
	var out bytes.Buffer
	s := NewSpinner(&out)
	s.Stop()
	s.SetPrefix("Loading")
	s.SetSuffix("resources")
	s.Start()
	s.Start()
	s.SetPrefix("Loaded")
	s.Stop()
	s.Stop()
	assert.Contains(t, out.String(), "Loaded")
	assert.Contains(t, out.String(), "resources")
	assert.Contains(t, out.String(), "✓")
	assert.False(t, s.running)
}

func TestQuietOutput(t *testing.T) {
	prevOut, prevQuiet := color.Output, isQuiet.Load()
	var out bytes.Buffer
	color.Output = &out
	t.Cleanup(func() {
		color.Output = prevOut
		SetQuiet(prevQuiet)
	})
	for _, fn := range []func(string, ...interface{}){LineInfo, LineNotify, LineError, LineWarn} {
		out.Reset()
		SetQuiet(true)
		fn("message %d", 42)
		assert.Empty(t, out.String())
		SetQuiet(false)
		fn("message %d", 42)
		assert.Contains(t, out.String(), "message 42")
	}
}

func TestPrintListMeta(t *testing.T) {
	prev := color.Output
	var out bytes.Buffer
	color.Output = &out
	t.Cleanup(func() { color.Output = prev })
	PrintListMeta(1, nil)
	PrintListMeta(1, &metav1.ListResponseMeta{})
	PrintListMeta(10, &metav1.ListResponseMeta{TotalCount: 10})
	assert.Empty(t, out.String())
	PrintListMeta(10, &metav1.ListResponseMeta{TotalCount: 30, Page: 1, HasMore: true})
	assert.Contains(t, out.String(), "page 2")
	assert.Contains(t, out.String(), "--page 3")
	out.Reset()
	PrintListMeta(10, &metav1.ListResponseMeta{TotalCount: 30, Page: 2})
	assert.Contains(t, out.String(), "Showing 10 out of 30 (page 3)")
	assert.NotContains(t, out.String(), "--page")
}

func TestPreRunAndPostRun(t *testing.T) {
	prev := dbC
	t.Cleanup(func() { dbC = prev })
	t.Setenv("OCTELIUM_HOME", t.TempDir())
	t.Setenv("OCTELIUM_LOGOUT", "")
	cmd := &cobra.Command{}
	require.NoError(t, PreRun(cmd, nil))
	require.NotNil(t, cmd.Context())
	require.NotNil(t, GetDB())
	assert.NoError(t, PostRun(cmd, nil))
	path := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(path, []byte("file"), 0600))
	cmd.Flags().String("homedir", filepath.Join(path, "home"), "")
	assert.Error(t, PreRun(cmd, nil))
}

func TestOpenDBDefault(t *testing.T) {
	prev := dbC
	t.Cleanup(func() { dbC = prev })
	t.Setenv("OCTELIUM_HOME", t.TempDir())
	require.NoError(t, openDBDefault())
	assert.NotNil(t, GetDB())
	assert.NoError(t, CloseDB())
}

func TestIsSuggestedWorkloadHost(t *testing.T) {
	t.Setenv("OCTELIUM_CONTAINER_MODE", "true")
	assert.True(t, IsSuggestedWorkloadHost())
	t.Setenv("OCTELIUM_CONTAINER_MODE", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "cluster")
	assert.True(t, IsSuggestedWorkloadHost())
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	for _, key := range []string{"container", "CI", "AWS_LAMBDA_FUNCTION_NAME", "AWS_EXECUTION_ENV"} {
		t.Setenv(key, "")
	}
	assert.Equal(t, isContainerFile(), IsSuggestedWorkloadHost())
	for key, value := range map[string]string{"container": "podman", "AWS_LAMBDA_FUNCTION_NAME": "function", "AWS_EXECUTION_ENV": "AWS_Lambda_go"} {
		t.Setenv(key, value)
		assert.True(t, IsSuggestedWorkloadHost())
		t.Setenv(key, "")
	}
}
