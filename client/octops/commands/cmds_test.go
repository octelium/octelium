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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/client/common/cliutils"
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
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smeta "k8s.io/apimachinery/pkg/api/meta"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	k8stesting "k8s.io/client-go/testing"
)

func TestCmds(t *testing.T) {
	InitCmds()
	assert.True(t, Cmd.HasSubCommands())
	assert.False(t, Cmd.Runnable())
}

var testCommandsOnce sync.Once

func cloneTestCommand(src *cobra.Command, restore *[]func()) *cobra.Command {
	ret := &cobra.Command{Use: src.Use, Short: src.Short, Long: src.Long, Example: src.Example,
		Aliases: slices.Clone(src.Aliases), Args: src.Args, RunE: src.RunE,
		PersistentPreRunE: src.PersistentPreRunE, PersistentPostRunE: src.PersistentPostRunE,
		SilenceErrors: true, SilenceUsage: true}
	for _, itm := range []struct{ src, dst *pflag.FlagSet }{
		{src.LocalNonPersistentFlags(), ret.Flags()}, {src.PersistentFlags(), ret.PersistentFlags()},
	} {
		itm.src.VisitAll(func(flag *pflag.Flag) {
			previous := flag.Value.String()
			*restore = append(*restore, func() { flag.Value.Set(previous) })
			flag.Value.Set(flag.DefValue)
			copied := *flag
			copied.Changed = false
			itm.dst.AddFlag(&copied)
		})
	}
	seen := map[string]bool{}
	for _, child := range src.Commands() {
		if !seen[child.Name()] {
			ret.AddCommand(cloneTestCommand(child, restore))
			seen[child.Name()] = true
		}
	}
	return ret
}

func executeTestCommand(t *testing.T, ctx context.Context, args ...string) (string, error) {
	t.Helper()
	t.Setenv("OCTELIUM_HOME", "mem")
	t.Setenv("OCTELIUM_LOGOUT", "")
	t.Setenv("DEBIAN_FRONTEND", "noninteractive")
	t.Setenv("OCTELIUM_SKIP_MESSAGES", "true")
	testCommandsOnce.Do(InitCmds)
	var restore []func()
	defer func() {
		for i := len(restore) - 1; i >= 0; i-- {
			restore[i]()
		}
	}()
	root := cloneTestCommand(Cmd, &restore)
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
	root.SetArgs(args)
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

func newTestKubernetes(t *testing.T, objects ...runtime.Object) (*fake.Clientset, string) {
	t.Helper()
	c := fake.NewSimpleClientset(objects...)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		gv := schema.GroupVersion{Version: "v1"}
		if len(parts) < 3 {
			http.NotFound(w, r)
			return
		}
		if parts[0] == "apis" {
			gv = schema.GroupVersion{Group: parts[1], Version: parts[2]}
			parts = parts[3:]
		} else {
			parts = parts[2:]
		}
		namespace := ""
		if len(parts) >= 3 && parts[0] == "namespaces" {
			namespace, parts = parts[1], parts[2:]
		}
		resource, name := parts[0], ""
		if len(parts) > 1 {
			name = parts[1]
		}
		kind := map[string]string{"secrets": "Secret", "configmaps": "ConfigMap", "jobs": "Job", "serviceaccounts": "ServiceAccount", "clusterroles": "ClusterRole", "clusterrolebindings": "ClusterRoleBinding", "namespaces": "Namespace"}[resource]
		if kind == "" {
			http.NotFound(w, r)
			return
		}
		gvr, gvk := gv.WithResource(resource), gv.WithKind(kind)
		obj, err := scheme.Scheme.New(gvk)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var action k8stesting.Action
		switch r.Method {
		case http.MethodGet:
			action = k8stesting.NewGetAction(gvr, namespace, name)
		case http.MethodPost, http.MethodPut:
			data, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				http.Error(w, readErr.Error(), http.StatusBadRequest)
				return
			}
			decoded, _, decodeErr := scheme.Codecs.UniversalDeserializer().Decode(data, &gvk, obj)
			if decodeErr != nil {
				http.Error(w, decodeErr.Error(), http.StatusBadRequest)
				return
			}
			obj = decoded
			accessor, accessErr := k8smeta.Accessor(obj)
			if accessErr != nil {
				http.Error(w, accessErr.Error(), http.StatusBadRequest)
				return
			}
			accessor.SetNamespace(namespace)
			if r.Method == http.MethodPost {
				action = k8stesting.NewCreateAction(gvr, namespace, obj)
			} else {
				action = k8stesting.NewUpdateAction(gvr, namespace, obj)
			}
		case http.MethodDelete:
			action = k8stesting.NewDeleteAction(gvr, namespace, name)
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		result, err := c.Invokes(action, obj)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			response := k8smetav1.Status{TypeMeta: k8smetav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Code: http.StatusInternalServerError, Message: err.Error()}
			if statusErr, ok := err.(k8serr.APIStatus); ok {
				response = statusErr.Status()
				response.APIVersion, response.Kind = "v1", "Status"
			}
			w.WriteHeader(int(response.Code))
			json.NewEncoder(w).Encode(&response)
			return
		}
		if r.Method == http.MethodDelete {
			json.NewEncoder(w).Encode(&k8smetav1.Status{TypeMeta: k8smetav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Success"})
			return
		}
		result.GetObjectKind().SetGroupVersionKind(gvk)
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
		}
		json.NewEncoder(w).Encode(result)
	}))
	t.Cleanup(server.Close)
	config := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(config, []byte(fmt.Sprintf("apiVersion: v1\nkind: Config\ncurrent-context: local\nclusters:\n- name: test\n  cluster: {server: %s}\ncontexts:\n- name: local\n  context: {cluster: test}\n", server.URL)), 0600))
	return c, config
}

func newTestBootstrap(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bootstrap.yaml")
	require.NoError(t, os.WriteFile(path, []byte("spec:\n  primaryStorage:\n    postgresql: {host: postgres, username: installer, passwordFromSecret: {name: postgres-auth, namespace: storage, key: custom}}\n  secondaryStorage:\n    redis: {host: redis, password: redis-secret}\n  spiffe: {enable: true, trustDomain: test.local, csiDriver: {name: custom.csi}}\n  cni: {multusConfDir: /opt/multus/conf}\n  ingress: {frontProxy: {enable: true}}\n"), 0600))
	return path
}

func TestInitCommandE2E(t *testing.T) {
	for _, externalIP := range []string{"", "not-an-ip", " 203.0.113.10 ", "2001:db8::1"} {
		for _, stdin := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stdin=%t", externalIP, stdin), func(t *testing.T) {
				t.Setenv("OCTELIUM_REGION_EXTERNAL_IP", externalIP)
				path := filepath.Join(t.TempDir(), "credentials", "token")
				t.Setenv("OCTELIUM_AUTH_TOKEN_SAVE_PATH", path)
				c, config := newTestKubernetes(t)
				c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
					assert.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "init-token", Namespace: "octelium"}, Data: map[string][]byte{"data": []byte("admin-token")}}))
					return false, nil, nil
				})
				bootstrap := newTestBootstrap(t)
				if stdin {
					file, err := os.Open(bootstrap)
					require.NoError(t, err)
					previous := os.Stdin
					os.Stdin = file
					t.Cleanup(func() { os.Stdin = previous; file.Close() })
					bootstrap = "-"
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				_, err := executeTestCommand(t, ctx, "init", "example.com", "--bootstrap="+bootstrap, "--kubeconfig="+config, "--kubecontext=local", "--version=1.2.3")
				require.NoError(t, err)
				secret, err := c.CoreV1().Secrets("default").Get(ctx, "octelium-init", k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, "example.com", string(secret.Data["domain"]))
				region, bs := &corev1.Region{}, &cbootstrapv1.Config{}
				require.NoError(t, pbutils.Unmarshal(secret.Data["region"], region))
				require.NoError(t, pbutils.Unmarshal(secret.Data["bootstrap"], bs))
				assert.Equal(t, "default", region.Metadata.Name)
				assert.Equal(t, "Region", region.Kind)
				if externalIP == "" || externalIP == "not-an-ip" {
					assert.Empty(t, region.Metadata.SystemLabels)
					assert.NotNil(t, region.Spec)
				} else {
					var ips []string
					require.NoError(t, json.Unmarshal([]byte(region.Metadata.SystemLabels["external-ips"]), &ips))
					assert.Equal(t, []string{strings.TrimSpace(externalIP)}, ips)
				}
				assert.Equal(t, "postgres-auth", bs.Spec.PrimaryStorage.GetPostgresql().GetPasswordFromSecret().Name)
				assert.Equal(t, "/opt/multus/conf", bs.Spec.Cni.GetMultusConfDir())
				assert.True(t, bs.Spec.Ingress.FrontProxy.Enable)
				job, err := c.BatchV1().Jobs("default").Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, []string{"init"}, job.Spec.Template.Spec.Containers[0].Args)
				assert.Contains(t, job.Spec.Template.Spec.Containers[0].Image, "octelium-genesis:1.2.3")
				assert.Equal(t, "custom.csi", job.Spec.Template.Spec.Volumes[0].CSI.Driver)
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, "admin-token", string(data))
				info, err := os.Stat(path)
				require.NoError(t, err)
				if goruntime.GOOS != "windows" {
					assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
				}
			})
		}
	}
}

func TestUpgradeAndPackageCommandsE2E(t *testing.T) {
	for _, spiffe := range []bool{false, true} {
		for _, args := range [][]string{
			{"upgrade", "example.com"},
			{"upgrade", "example.com", "--version=1.2.3"},
			{"install-package", "example.com", "--package=octeliumee"},
			{"install-package", "example.com", "--package=cordium", "--version=1.2.3"},
			{"install-package", "example.com", "--package=octeliumee", "--upgrade", "--version=1.2.3"},
			{"install-package", "example.com", "--package=cordium", "--upgrade"},
		} {
			t.Run(fmt.Sprintf("%s/spiffe=%t", strings.Join(args, " "), spiffe), func(t *testing.T) {
				t.Setenv("OCTELIUM_DEV", "false")
				t.Setenv("OCTELIUM_PRODUCTION", "true")
				c, config := newTestKubernetes(t)
				if spiffe {
					require.NoError(t, c.Tracker().Add(&k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-installation", Namespace: "octelium"}, Data: map[string]string{"installation.json": `{"spiffe":{"enable":true,"trustDomain":"test.local","csiDriver":{"name":"custom.csi"}}}`}}))
				}
				out, err := executeTestCommand(t, context.Background(), append(slices.Clone(args), "--kubeconfig="+config)...)
				require.NoError(t, err)
				assert.Contains(t, out, "started")
				jobs, err := c.BatchV1().Jobs("octelium").List(context.Background(), k8smetav1.ListOptions{})
				require.NoError(t, err)
				require.Len(t, jobs.Items, 1)
				job := jobs.Items[0]
				assert.Equal(t, job.Labels, job.Spec.Template.Labels)
				assert.Equal(t, "octelium-nocturne", job.Spec.Template.Spec.ServiceAccountName)
				command, pkg, version := "upgrade", "octelium", "latest"
				if args[0] == "install-package" {
					command = "init"
				}
				for _, arg := range args[2:] {
					if arg == "--upgrade" {
						command = "upgrade"
					}
					if strings.HasPrefix(arg, "--package=") {
						pkg = strings.TrimPrefix(arg, "--package=")
					}
					if strings.HasPrefix(arg, "--version=") {
						version = strings.TrimPrefix(arg, "--version=")
					}
				}
				container := job.Spec.Template.Spec.Containers[0]
				assert.Equal(t, []string{command}, container.Args)
				assert.Equal(t, pkg+"-genesis", container.Name)
				assert.Contains(t, container.Image, pkg+"-genesis:"+version)
				assert.Regexp(t, `^octelium-genesis-[a-z0-9-]+-[a-z0-9]{6}$`, job.Name)
				assert.Contains(t, container.Env, k8scorev1.EnvVar{Name: "OCTELIUM_DOMAIN", Value: "example.com"})
				assert.Contains(t, container.Env, k8scorev1.EnvVar{Name: "OCTELIUM_REGION_NAME", Value: "default"})
				if spiffe {
					require.Len(t, job.Spec.Template.Spec.Volumes, 1)
					assert.Equal(t, "custom.csi", job.Spec.Template.Spec.Volumes[0].CSI.Driver)
					assert.Contains(t, container.Env, k8scorev1.EnvVar{Name: "OCTELIUM_SPIFFE_TRUST_DOMAIN", Value: "test.local"})
				} else {
					assert.Empty(t, job.Spec.Template.Spec.Volumes)
				}
			})
		}
	}
}

func TestCertificateCommandsE2E(t *testing.T) {
	for _, name := range []string{"certificate", "cert", "crt"} {
		for _, namespace := range []string{"", "engineering"} {
			t.Run(name+"/"+namespace, func(t *testing.T) {
				c, config := newTestKubernetes(t)
				cert, key := filepath.Join(t.TempDir(), "tls.crt"), filepath.Join(t.TempDir(), "tls.key")
				pairServer := httptest.NewTLSServer(nil)
				pairServer.Close()
				certificate := pairServer.TLS.Certificates[0]
				certPEM, keyPEM := testCertificatePEM(t, certificate)
				require.NoError(t, os.WriteFile(cert, certPEM, 0600))
				require.NoError(t, os.WriteFile(key, keyPEM, 0600))
				for range 2 {
					_, err := executeTestCommand(t, context.Background(), name, "example.com", "--kubeconfig="+config, "--cert="+cert, "--key="+key, "--namespace="+namespace)
					require.NoError(t, err)
				}
				secretName := "cert-cluster"
				if namespace != "" {
					secretName = "cert-ns-" + namespace
				}
				secret, err := c.CoreV1().Secrets("octelium").Get(context.Background(), secretName, k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, k8scorev1.SecretTypeTLS, secret.Type)
				assert.Equal(t, certPEM, secret.Data[k8scorev1.TLSCertKey])
				assert.Equal(t, keyPEM, secret.Data[k8scorev1.TLSPrivateKeyKey])
			})
		}
	}
}

func testCertificatePEM(t *testing.T, pair tls.Certificate) ([]byte, []byte) {
	t.Helper()
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}

func TestUninstallCommandE2E(t *testing.T) {
	c, config := newTestKubernetes(t, &k8scorev1.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium"}}, &k8scorev1.Namespace{ObjectMeta: k8smetav1.ObjectMeta{Name: "other"}})
	out, err := executeTestCommand(t, context.Background(), "uninstall", "example.com", "--kubeconfig="+config)
	require.NoError(t, err)
	assert.Contains(t, out, "uninstalled")
	_, err = c.CoreV1().Namespaces().Get(context.Background(), "octelium", k8smetav1.GetOptions{})
	assert.True(t, k8serr.IsNotFound(err))
	_, err = c.CoreV1().Namespaces().Get(context.Background(), "other", k8smetav1.GetOptions{})
	assert.NoError(t, err)
}

func newTestCoreServer(t *testing.T, handler func(context.Context, *metav1.GetOptions) (*corev1.Region, error)) context.Context {
	t.Helper()
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "test-access")
	t.Setenv("OCTELIUM_PRODUCTION", "true")
	t.Setenv("OCTELIUM_DEV", "false")
	t.Setenv("OCTELIUM_INSECURE_TLS", "true")
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
			assert.True(t, strings.HasSuffix(info.FullMethod, "/GetRegion"))
			return handler(ctx, req.(*metav1.GetOptions))
		}))
	corev1.RegisterMainServiceServer(srv, &corev1.UnimplementedMainServiceServer{})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestUpgradeWaitCommandE2E(t *testing.T) {
	for _, transient := range []bool{false, true} {
		t.Run(fmt.Sprintf("transient=%t", transient), func(t *testing.T) {
			var calls atomic.Int32
			ctx := newTestCoreServer(t, func(ctx context.Context, req *metav1.GetOptions) (*corev1.Region, error) {
				assert.Equal(t, "default", req.Name)
				n := calls.Add(1)
				if n == 1 {
					return &corev1.Region{Status: &corev1.Region_Status{Version: "1.0.0"}}, nil
				}
				if transient && n == 2 {
					return &corev1.Region{Status: &corev1.Region_Status{Version: "1.0.0"}}, nil
				}
				if transient && n == 3 {
					return nil, status.Error(codes.NotFound, "region is reloading")
				}
				return &corev1.Region{Status: &corev1.Region_Status{Version: "1.2.3"}}, nil
			})
			c, config := newTestKubernetes(t)
			out, err := executeTestCommand(t, ctx, "upgrade", "example.invalid", "--kubeconfig="+config, "--version=1.2.3", "--wait")
			require.NoError(t, err)
			assert.Contains(t, out, "Cluster has been upgraded")
			jobs, err := c.BatchV1().Jobs("octelium").List(ctx, k8smetav1.ListOptions{})
			require.NoError(t, err)
			assert.Len(t, jobs.Items, 1)
			assert.GreaterOrEqual(t, calls.Load(), int32(2))
		})
	}
}

func TestCommandHelpAndArguments(t *testing.T) {
	for _, name := range []string{"init", "upgrade", "install-package", "certificate", "cert", "crt", "uninstall"} {
		t.Run(name, func(t *testing.T) {
			out, err := executeTestCommand(t, context.Background(), name, "--help")
			require.NoError(t, err)
			assert.Contains(t, out, "[DOMAIN]")
			assert.Contains(t, out, "--kubeconfig")
			assert.Contains(t, out, "--kubecontext")
			for _, args := range [][]string{{name}, {name, "one", "two"}} {
				_, err := executeTestCommand(t, context.Background(), args...)
				assert.Error(t, err)
			}
		})
	}
	_, err := executeTestCommand(t, context.Background(), "init", "example.com")
	assert.Error(t, err)
	out, err := executeTestCommand(t, context.Background(), "version", "--out=json")
	require.NoError(t, err)
	assert.True(t, json.Valid([]byte(out)))
}

func TestCommandErrorsE2E(t *testing.T) {
	for _, command := range []string{"init", "upgrade", "install-package", "certificate", "uninstall"} {
		t.Run(command+"/kubeconfig", func(t *testing.T) {
			args := []string{command, "example.com", "--kubeconfig=" + filepath.Join(t.TempDir(), "missing")}
			if command == "init" {
				args = append(args, "--bootstrap="+newTestBootstrap(t))
			}
			_, err := executeTestCommand(t, context.Background(), args...)
			assert.ErrorContains(t, err, "does not exist")
		})
	}
	for _, pkg := range []string{"", "unknown"} {
		c, config := newTestKubernetes(t)
		_, err := executeTestCommand(t, context.Background(), "install-package", "example.com", "--kubeconfig="+config, "--package="+pkg)
		assert.Error(t, err)
		assert.Empty(t, c.Actions())
	}
	for _, command := range []string{"init", "upgrade", "install-package", "certificate", "uninstall"} {
		t.Run(command+"/api", func(t *testing.T) {
			c, config := newTestKubernetes(t)
			c.PrependReactor("*", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "test", fmt.Errorf("not permitted"))
			})
			args := []string{command, "example.com", "--kubeconfig=" + config}
			switch command {
			case "init":
				args = append(args, "--bootstrap="+newTestBootstrap(t))
			case "install-package":
				args = append(args, "--package=cordium")
			case "certificate":
				path := filepath.Join(t.TempDir(), "cert")
				require.NoError(t, os.WriteFile(path, []byte("fixture"), 0600))
				args = append(args, "--cert="+path, "--key="+path)
			}
			_, err := executeTestCommand(t, context.Background(), args...)
			assert.True(t, k8serr.IsForbidden(err), "%v", err)
		})
	}
	for _, data := range []string{"[invalid YAML", "{}", "spec: {primaryStorage: {postgresql: {host: postgres}}}"} {
		c, config := newTestKubernetes(t)
		path := filepath.Join(t.TempDir(), "bootstrap")
		require.NoError(t, os.WriteFile(path, []byte(data), 0600))
		_, err := executeTestCommand(t, context.Background(), "init", "example.com", "--kubeconfig="+config, "--bootstrap="+path)
		assert.Error(t, err)
		assert.Empty(t, c.Actions())
	}
	for _, keyExists := range []bool{false, true} {
		c, config := newTestKubernetes(t)
		path := filepath.Join(t.TempDir(), "missing")
		if keyExists {
			require.NoError(t, os.WriteFile(path, []byte("fixture"), 0600))
		}
		_, err := executeTestCommand(t, context.Background(), "cert", "example.com", "--kubeconfig="+config, "--cert="+path, "--key="+filepath.Join(t.TempDir(), "missing"))
		assert.Error(t, err)
		assert.Empty(t, c.Actions())
	}
	ctx := newTestCoreServer(t, func(ctx context.Context, req *metav1.GetOptions) (*corev1.Region, error) {
		return nil, status.Error(codes.PermissionDenied, "not permitted")
	})
	_, config := newTestKubernetes(t)
	_, err := executeTestCommand(t, ctx, "upgrade", "example.invalid", "--kubeconfig="+config, "--wait")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestInitInputErrorsE2E(t *testing.T) {
	for _, stdin := range []bool{false, true} {
		t.Run(fmt.Sprintf("stdin=%t", stdin), func(t *testing.T) {
			c, config := newTestKubernetes(t)
			path := filepath.Join(t.TempDir(), "missing")
			if stdin {
				f, err := os.Create(filepath.Join(t.TempDir(), "stdin"))
				require.NoError(t, err)
				require.NoError(t, f.Close())
				previous := os.Stdin
				os.Stdin = f
				t.Cleanup(func() { os.Stdin = previous })
				path = "-"
			}
			_, err := executeTestCommand(t, context.Background(), "init", "example.com", "--kubeconfig="+config, "--bootstrap="+path)
			assert.Error(t, err)
			assert.Empty(t, c.Actions())
		})
	}
}

func TestInvalidKubernetesTLSConfigE2E(t *testing.T) {
	config := filepath.Join(t.TempDir(), "kubeconfig")
	require.NoError(t, os.WriteFile(config, []byte("apiVersion: v1\nkind: Config\ncurrent-context: test\nclusters:\n- name: test\n  cluster: {server: 'https://127.0.0.1:1', certificate-authority-data: bm90IGEgY2VydA==}\ncontexts:\n- name: test\n  context: {cluster: test}\n"), 0600))
	for _, command := range []string{"init", "upgrade", "install-package", "certificate", "uninstall"} {
		t.Run(command, func(t *testing.T) {
			args := []string{command, "example.com", "--kubeconfig=" + config}
			if command == "init" {
				args = append(args, "--bootstrap="+newTestBootstrap(t))
			}
			_, err := executeTestCommand(t, context.Background(), args...)
			assert.ErrorContains(t, err, "certificate")
		})
	}
}

func TestUpgradeWaitAuthenticationFailureE2E(t *testing.T) {
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_AUTH_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_ASSERTION", "unsupported-type")
	c, config := newTestKubernetes(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := executeTestCommand(t, ctx, "upgrade", "example.invalid", "--kubeconfig="+config, "--wait")
	assert.Error(t, err)
	jobs, err := c.BatchV1().Jobs("octelium").List(context.Background(), k8smetav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, jobs.Items, 1)
}
