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

package upgrade

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/cliutils"
	"github.com/octelium/octelium/client/octops/commands/install"
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
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakek8s "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type releaseHTTPResponse struct {
	code int
	body string
}

var releaseResponse atomic.Value
var releaseRequests = make(chan *http.Request, 64)

func TestMain(m *testing.M) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"raw.githubusercontent.com"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		panic(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	releaseResponse.Store(releaseHTTPResponse{http.StatusOK, "v1.2.3"})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "raw.githubusercontent.com:443" {
			http.Error(w, "unexpected target", http.StatusBadGateway)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		req, err := http.ReadRequest(bufio.NewReader(tlsConn))
		if err != nil {
			return
		}
		defer req.Body.Close()
		releaseRequests <- req
		response := releaseResponse.Load().(releaseHTTPResponse)
		fmt.Fprintf(tlsConn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", response.code, http.StatusText(response.code), len(response.body), response.body)
	}))
	if err := os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1"); err != nil {
		panic(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) {
		panic("could not load test certificate")
	}
	x509.SetFallbackRoots(roots)
	for key, value := range map[string]string{"HTTPS_PROXY": proxy.URL, "https_proxy": proxy.URL, "NO_PROXY": "", "no_proxy": ""} {
		if err := os.Setenv(key, value); err != nil {
			panic(err)
		}
	}
	code := m.Run()
	proxy.Close()
	os.Exit(code)
}

type testRegionClient struct {
	corev1.MainServiceClient
	get func(context.Context, *metav1.GetOptions) (*corev1.Region, error)
}

func (c *testRegionClient) GetRegion(ctx context.Context, req *metav1.GetOptions, opts ...grpc.CallOption) (*corev1.Region, error) {
	return c.get(ctx, req)
}

func TestClusterVersion(t *testing.T) {
	for _, value := range []string{"v1.2.3", "1.2.3-rc.1+build", "development", ""} {
		t.Run(value, func(t *testing.T) {
			key := struct{}{}
			ctx := context.WithValue(context.Background(), key, "request-context")
			c := &testRegionClient{get: func(gotCtx context.Context, req *metav1.GetOptions) (*corev1.Region, error) {
				assert.Equal(t, "request-context", gotCtx.Value(key))
				assert.Equal(t, "default", req.Name)
				return &corev1.Region{Status: &corev1.Region_Status{Version: value}}, nil
			}}
			got, err := getDefaultRegionVersion(ctx, c)
			require.NoError(t, err)
			assert.Equal(t, value, got)
			version, err := getCurrentClusterVersion(ctx, c)
			if value == "development" || value == "" {
				assert.Error(t, err)
				assert.Nil(t, version)
			} else {
				require.NoError(t, err)
				assert.Equal(t, strings.TrimPrefix(value, "v"), version.String())
			}
		})
	}
	want := status.Error(codes.PermissionDenied, "region denied")
	c := &testRegionClient{get: func(context.Context, *metav1.GetOptions) (*corev1.Region, error) { return nil, want }}
	_, err := getDefaultRegionVersion(context.Background(), c)
	assert.ErrorIs(t, err, want)
	_, err = getCurrentClusterVersion(context.Background(), c)
	assert.ErrorIs(t, err, want)
}

func TestLatestVersion(t *testing.T) {
	t.Setenv("OCTELIUM_PRODUCTION", "true")
	t.Setenv("OCTELIUM_DEV", "false")
	for _, tc := range []struct {
		code       int
		body, want string
	}{
		{200, "v1.2.3", "1.2.3"}, {200, "1.2.3-rc.1+build", "1.2.3-rc.1+build"},
		{200, "not a version", ""}, {200, "", ""}, {404, "v1.2.3", ""}, {503, "v1.2.3", ""},
	} {
		t.Run(fmt.Sprintf("%d/%s", tc.code, tc.body), func(t *testing.T) {
			releaseResponse.Store(releaseHTTPResponse{tc.code, tc.body})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			version, err := getLatestVersion(ctx)
			if tc.want == "" {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, version.String())
			}
			select {
			case req := <-releaseRequests:
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "/octelium/octelium/refs/heads/main/unsorted/latest_release", req.URL.Path)
				assert.Equal(t, "raw.githubusercontent.com", req.Host)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := getLatestVersion(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestCheckUpgradeE2E(t *testing.T) {
	previousArgs := cmdArgs
	t.Cleanup(func() { cmdArgs = previousArgs })
	cmdArgs = args{CheckMode: true}
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "test-access")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_INSECURE_TLS", "true")
	t.Setenv("OCTELIUM_PRODUCTION", "true")
	t.Setenv("OCTELIUM_DEV", "false")
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
	var current atomic.Value
	current.Store("1.2.3")
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{cert}})),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			assert.Equal(t, []string{"test-access"}, md.Get("x-octelium-auth"))
			assert.True(t, strings.HasSuffix(info.FullMethod, "/GetRegion"))
			assert.Equal(t, "default", req.(*metav1.GetOptions).Name)
			return &corev1.Region{Status: &corev1.Region_Status{Version: current.Load().(string)}}, nil
		}))
	corev1.RegisterMainServiceServer(srv, &corev1.UnimplementedMainServiceServer{})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	for _, tc := range []struct {
		current, latest, want string
		code                  int
		failed                bool
	}{
		{"1.2.3", "v1.2.3", "No Cluster upgrade is needed", 200, false},
		{"2.0.0", "v1.2.3", "No Cluster upgrade is needed", 200, false},
		{"1.0.0", "v1.2.3", "Cluster can be upgraded", 200, false},
		{"1.2.3-rc.1", "v1.2.3", "Cluster can be upgraded", 200, false},
		{"development", "v1.2.3", "", 200, true},
		{"1.0.0", "not semver", "", 200, true},
		{"1.0.0", "v1.2.3", "", 503, true},
	} {
		t.Run(tc.current+"/"+tc.latest+fmt.Sprint(tc.code), func(t *testing.T) {
			cmdArgs = args{}
			current.Store(tc.current)
			releaseResponse.Store(releaseHTTPResponse{tc.code, tc.latest})
			f, err := os.Create(filepath.Join(t.TempDir(), "output"))
			require.NoError(t, err)
			previousOutput, previousNoColor := color.Output, color.NoColor
			color.Output, color.NoColor = f, true
			defer func() { color.Output, color.NoColor = previousOutput, previousNoColor; f.Close() }()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := &cobra.Command{Use: Cmd.Use, Args: Cmd.Args, RunE: Cmd.RunE, SilenceErrors: true, SilenceUsage: true}
			Cmd.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
				copied := *flag
				copied.Changed = false
				cmd.PersistentFlags().AddFlag(&copied)
			})
			cmd.SetArgs([]string{"example.invalid", "--check", "--kubeconfig=" + filepath.Join(t.TempDir(), "missing")})
			err = cmd.ExecuteContext(ctx)
			if tc.failed {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				_, err = f.Seek(0, io.SeekStart)
				require.NoError(t, err)
				out, err := io.ReadAll(f)
				require.NoError(t, err)
				assert.Contains(t, string(out), tc.want)
				assert.Contains(t, string(out), "Current Cluster Version: "+tc.current)
			}
			select {
			case <-releaseRequests:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

func TestCheckUpgradeAuthenticationError(t *testing.T) {
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_AUTH_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_ASSERTION", "unsupported-type")
	require.NoError(t, cliutils.OpenDB("mem"))
	d := cliutils.GetDB()
	t.Cleanup(func() { d.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assert.Error(t, doCheck(ctx, "example.invalid"))
}

func TestGenesisUpgradeJobs(t *testing.T) {
	ctx := context.Background()
	c := fakek8s.NewSimpleClientset(&k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-installation", Namespace: "octelium"}, Data: map[string]string{"installation.json": `{"spiffe":{"enable":true,"trustDomain":"test.local"}}`}})
	for range 2 {
		require.NoError(t, createGenesis(ctx, c, "example.com", "1.2.3"))
	}
	jobs, err := c.BatchV1().Jobs("octelium").List(ctx, k8smetav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, jobs.Items, 2)
	assert.NotEqual(t, jobs.Items[0].Name, jobs.Items[1].Name)
	for _, job := range jobs.Items {
		assert.Regexp(t, `^octelium-genesis-upgrade-[a-z0-9]{6}$`, job.Name)
		assert.Equal(t, "octelium-nocturne", job.Spec.Template.Spec.ServiceAccountName)
		assert.Equal(t, "csi.spiffe.io", job.Spec.Template.Spec.Volumes[0].CSI.Driver)
		assert.Equal(t, []string{"upgrade"}, job.Spec.Template.Spec.Containers[0].Args)
	}
	want := k8serr.NewForbidden(schema.GroupResource{Group: "batch", Resource: "jobs"}, "test", fmt.Errorf("not permitted"))
	c.PrependReactor("create", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) { return true, nil, want })
	assert.ErrorIs(t, createGenesis(ctx, c, "example.com", "1.2.3"), want)
	job := getGenesisJob("example.com", "1.2.3", &install.SPIFFEOpts{CSIDriver: "custom.csi"})
	assert.Equal(t, "custom.csi", job.Spec.Template.Spec.Volumes[0].CSI.Driver)
}
