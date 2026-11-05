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
	"github.com/google/uuid"
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
	batchv1 "k8s.io/api/batch/v1"
	k8scorev1 "k8s.io/api/core/v1"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	k8smeta "k8s.io/apimachinery/pkg/api/meta"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
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
		kind := map[string]string{"secrets": "Secret", "configmaps": "ConfigMap", "jobs": "Job", "pods": "Pod", "serviceaccounts": "ServiceAccount", "clusterroles": "ClusterRole", "clusterrolebindings": "ClusterRoleBinding", "namespaces": "Namespace"}[resource]
		if kind == "" {
			http.NotFound(w, r)
			return
		}
		gvr, gvk := gv.WithResource(resource), gv.WithKind(kind)
		if r.Method == http.MethodGet && name == "" {
			gvk.Kind += "List"
		}
		obj, err := scheme.Scheme.New(gvk)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var action k8stesting.Action
		switch r.Method {
		case http.MethodGet:
			if name == "" {
				action = k8stesting.NewListAction(gvr, gv.WithKind(kind), namespace, k8smetav1.ListOptions{LabelSelector: r.URL.Query().Get("labelSelector"), FieldSelector: r.URL.Query().Get("fieldSelector")})
			} else {
				action = k8stesting.NewGetAction(gvr, namespace, name)
			}
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
				accessor.SetUID(types.UID(uuid.NewString()))
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
				c.PrependReactor("update", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
					assert.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "init-token", Namespace: "octelium"}, Data: map[string][]byte{"data": []byte("admin-token")}}))
					job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job)
					job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
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
				if args[0] == "install-package" {
					assert.Regexp(t, "^octelium-genesis-"+command+"-"+pkg+"-[a-z0-9]{6}$", job.Name)
				} else {
					assert.Regexp(t, "^octelium-genesis-upgrade-[a-z0-9]{6}$", job.Name)
				}
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

func TestConflictingGenesisCommandsE2E(t *testing.T) {
	for _, pair := range [][2][]string{
		{{"upgrade", "example.com", "--version=1.2.3"}, {"upgrade", "example.com", "--version=2.0.0"}},
		{{"upgrade", "example.com"}, {"install-package", "example.com", "--package=cordium"}},
		{{"install-package", "example.com", "--package=octeliumee"}, {"upgrade", "example.com"}},
		{{"install-package", "example.com", "--package=octeliumee"}, {"install-package", "example.com", "--package=cordium"}},
	} {
		t.Run(strings.Join(pair[0], " ")+"/"+strings.Join(pair[1], " "), func(t *testing.T) {
			c, config := newTestKubernetes(t)
			_, err := executeTestCommand(t, t.Context(), append(slices.Clone(pair[0]), "--kubeconfig="+config)...)
			require.NoError(t, err)
			before, err := c.BatchV1().Jobs("octelium").List(t.Context(), k8smetav1.ListOptions{})
			require.NoError(t, err)
			require.Len(t, before.Items, 1)
			_, err = executeTestCommand(t, t.Context(), append(slices.Clone(pair[1]), "--kubeconfig="+config)...)
			require.ErrorContains(t, err, "still active")
			after, err := c.BatchV1().Jobs("octelium").List(t.Context(), k8smetav1.ListOptions{})
			require.NoError(t, err)
			assert.Equal(t, before, after)
		})
	}
}

func newBlockedGenesisJob(t *testing.T, name, namespace string) (*batchv1.Job, *k8scorev1.Pod) {
	t.Helper()
	labels := map[string]string{"octelium.com/component": "genesis"}
	job := &batchv1.Job{
		ObjectMeta: k8smetav1.ObjectMeta{Name: name, Namespace: namespace, UID: types.UID(uuid.NewString()), ResourceVersion: "1", Labels: labels},
		Status:     batchv1.JobStatus{Active: 1},
	}
	pod := &k8scorev1.Pod{
		ObjectMeta: k8smetav1.ObjectMeta{
			Name: name + "-worker", Namespace: namespace, Labels: labels,
			OwnerReferences: []k8smetav1.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: name, UID: job.UID, Controller: new(true)}},
		},
		Status: k8scorev1.PodStatus{Phase: k8scorev1.PodPending, ContainerStatuses: []k8scorev1.ContainerStatus{
			{Name: "genesis", State: k8scorev1.ContainerState{Waiting: &k8scorev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "manifest unknown"}}},
		}},
	}
	return job, pod
}

func collectGenesisJobPods(t *testing.T, c *fake.Clientset, pod *k8scorev1.Pod) {
	t.Helper()
	c.PrependReactor("delete", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.DeleteAction).GetName() == pod.OwnerReferences[0].Name {
			assert.NoError(t, c.Tracker().Delete(k8scorev1.SchemeGroupVersion.WithResource("pods"), pod.Namespace, pod.Name))
		}
		return false, nil, nil
	})
}

func TestBlockedGenesisJobIsReplacedE2E(t *testing.T) {
	for _, args := range [][]string{
		{"upgrade", "example.com", "--version=2.0.0"},
		{"install-package", "example.com", "--package=octeliumee", "--version=2.0.0"},
		{"install-package", "example.com", "--package=cordium", "--upgrade", "--version=2.0.0"},
	} {
		for _, namespace := range []string{"default", "octelium"} {
			t.Run(strings.Join(args, " ")+"/"+namespace, func(t *testing.T) {
				blocked, pod := newBlockedGenesisJob(t, "octelium-genesis-upgrade-typo", namespace)
				c, config := newTestKubernetes(t, blocked, pod)
				collectGenesisJobPods(t, c, pod)
				out, err := executeTestCommand(t, t.Context(), append(slices.Clone(args), "--kubeconfig="+config)...)
				require.NoError(t, err)
				assert.Contains(t, out, "Removing the genesis Job "+namespace+"/"+blocked.Name)
				assert.Contains(t, out, "started")
				_, err = c.BatchV1().Jobs(namespace).Get(t.Context(), blocked.Name, k8smetav1.GetOptions{})
				assert.True(t, k8serr.IsNotFound(err), "%+v", err)
				_, err = c.CoreV1().Pods(namespace).Get(t.Context(), pod.Name, k8smetav1.GetOptions{})
				assert.True(t, k8serr.IsNotFound(err), "%+v", err)
				jobs, err := c.BatchV1().Jobs("octelium").List(t.Context(), k8smetav1.ListOptions{})
				require.NoError(t, err)
				require.Len(t, jobs.Items, 1)
				assert.Contains(t, jobs.Items[0].Spec.Template.Spec.Containers[0].Image, ":2.0.0")
			})
		}
	}
}

func TestBlockedInitializationIsReplacedE2E(t *testing.T) {
	blocked, pod := newBlockedGenesisJob(t, "octelium-genesis", "default")
	c, config := newTestKubernetes(t, blocked, pod)
	collectGenesisJobPods(t, c, pod)
	c.PrependReactor("update", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		assert.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "init-token", Namespace: "octelium"}, Data: map[string][]byte{"data": []byte("admin-token")}}))
		job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
		return false, nil, nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	out, err := executeTestCommand(t, ctx, "init", "example.com", "--bootstrap="+newTestBootstrap(t), "--kubeconfig="+config, "--version=1.2.3")
	require.NoError(t, err)
	assert.Contains(t, out, "Removing the genesis Job default/octelium-genesis")
	job, err := c.BatchV1().Jobs("default").Get(ctx, "octelium-genesis", k8smetav1.GetOptions{})
	require.NoError(t, err)
	assert.NotEqual(t, blocked.UID, job.UID)
	assert.Contains(t, job.Spec.Template.Spec.Containers[0].Image, "octelium-genesis:1.2.3")
}

func TestActiveGenesisJobIsNotReplacedE2E(t *testing.T) {
	active, pod := newBlockedGenesisJob(t, "octelium-genesis-upgrade-active", "octelium")
	pod.Status = k8scorev1.PodStatus{Phase: k8scorev1.PodRunning}
	c, config := newTestKubernetes(t, active, pod)
	_, err := executeTestCommand(t, t.Context(), "upgrade", "example.com", "--version=2.0.0", "--kubeconfig="+config)
	require.ErrorContains(t, err, "still active")
	jobs, err := c.BatchV1().Jobs("octelium").List(t.Context(), k8smetav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, jobs.Items, 1)
	assert.Equal(t, active.UID, jobs.Items[0].UID)
	for _, action := range c.Actions() {
		assert.NotEqual(t, "delete", action.GetVerb())
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
				calls.Add(1)
				return nil, status.Error(codes.PermissionDenied, "Public API must not be used to wait for upgrades")
			})
			c, config := newTestKubernetes(t)
			c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
				return false, nil, nil
			})
			var reads atomic.Int32
			c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				n := reads.Add(1)
				if transient && n == 1 {
					return true, nil, k8serr.NewServiceUnavailable("Temporary API outage")
				}
				return false, nil, nil
			})
			out, err := executeTestCommand(t, ctx, "upgrade", "example.invalid", "--kubeconfig="+config, "--version=1.2.3", "--wait")
			require.NoError(t, err)
			assert.Contains(t, out, "Cluster has been upgraded")
			jobs, err := c.BatchV1().Jobs("octelium").List(ctx, k8smetav1.ListOptions{})
			require.NoError(t, err)
			assert.Len(t, jobs.Items, 1)
			assert.Zero(t, calls.Load())
			if transient {
				assert.Equal(t, int32(2), reads.Load())
			} else {
				assert.Equal(t, int32(1), reads.Load())
			}
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
	c, config := newTestKubernetes(t)
	c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "test", fmt.Errorf("not permitted"))
	})
	c.PrependReactor("list", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.ListAction).GetListRestrictions().Fields.String() != "" {
			return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "test", fmt.Errorf("not permitted"))
		}
		return false, nil, nil
	})
	_, err := executeTestCommand(t, t.Context(), "upgrade", "example.invalid", "--kubeconfig="+config, "--wait")
	assert.True(t, k8serr.IsForbidden(err), "%v", err)
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

func TestUpgradeWaitWithoutClusterAuthenticationE2E(t *testing.T) {
	t.Setenv("OCTELIUM_ACCESS_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_PROXY_SOCKET", "")
	t.Setenv("OCTELIUM_AUTH_TOKEN", "")
	t.Setenv("OCTELIUM_AUTH_ASSERTION", "unsupported-type")
	c, config := newTestKubernetes(t)
	c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
		return false, nil, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := executeTestCommand(t, ctx, "upgrade", "example.invalid", "--kubeconfig="+config, "--wait")
	require.NoError(t, err)
	jobs, err := c.BatchV1().Jobs("octelium").List(context.Background(), k8smetav1.ListOptions{})
	require.NoError(t, err)
	assert.Len(t, jobs.Items, 1)
}

func TestInitCompletionE2E(t *testing.T) {
	for _, state := range []string{"legacy-success", "owned-success", "failed-after-publication", "empty-token", "wrong-initialization", "incomplete-checkpoint", "replaced-job", "deleted-job", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials", "token")
			t.Setenv("OCTELIUM_AUTH_TOKEN_SAVE_PATH", path)
			c, config := newTestKubernetes(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			started := false
			c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				if !started {
					return false, nil, nil
				}
				a := action.(k8stesting.GetAction)
				switch state {
				case "deleted-job":
					return true, nil, k8serr.NewNotFound(action.GetResource().GroupResource(), a.GetName())
				case "replaced-job":
					object, err := c.Tracker().Get(action.GetResource(), action.GetNamespace(), a.GetName())
					if err != nil {
						return true, nil, err
					}
					job := object.(*batchv1.Job).DeepCopy()
					job.UID = "replacement"
					return true, job, nil
				case "cancelled":
					cancel()
					return true, nil, context.Canceled
				}
				return false, nil, nil
			})
			c.PrependReactor("update", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job)
				started = true
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
				if state == "failed-after-publication" {
					job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
				}
				token := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "init-token", Namespace: "octelium"}, Data: map[string][]byte{"data": []byte("new-admin-token")}}
				if state == "empty-token" {
					token.Data = nil
				}
				if state == "owned-success" || state == "wrong-initialization" || state == "incomplete-checkpoint" {
					token.Annotations = map[string]string{"octelium.com/genesis-init-id": "init-id"}
					checkpoint := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-genesis-init", Namespace: "octelium", Annotations: map[string]string{"octelium.com/genesis-init-complete": "true"}}, Data: map[string][]byte{"id": []byte("init-id")}}
					if state == "wrong-initialization" {
						checkpoint.Data["id"] = []byte("other-initialization")
					}
					if state == "incomplete-checkpoint" {
						checkpoint.Annotations = nil
					}
					assert.NoError(t, c.Tracker().Add(checkpoint))
				}
				assert.NoError(t, c.Tracker().Add(token))
				return false, nil, nil
			})
			output, err := executeTestCommand(t, ctx, "init", "example.com", "--bootstrap="+newTestBootstrap(t), "--kubeconfig="+config, "--kubecontext=local", "--version=1.2.3")
			if state == "legacy-success" || state == "owned-success" {
				require.NoError(t, err, output)
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, "new-admin-token", string(data))
			} else {
				require.Error(t, err)
				_, fileErr := os.Stat(path)
				assert.True(t, os.IsNotExist(fileErr))
				assert.NotContains(t, output, "new-admin-token")
				assert.NotContains(t, err.Error(), "new-admin-token")
				assert.NotContains(t, output, "Cluster installation is now complete")
				if state == "cancelled" {
					assert.ErrorIs(t, err, context.Canceled)
				}
			}
		})
	}
}

func TestInitBootstrapRepairE2E(t *testing.T) {
	for _, state := range []string{"preflight-only", "checkpoint-only", "postgres-started", "redis-started", "response-lost"} {
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credentials", "token")
			t.Setenv("OCTELIUM_AUTH_TOKEN_SAVE_PATH", path)
			c, config := newTestKubernetes(t)
			var starts, inputWrites atomic.Int32
			c.PrependReactor("create", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				secret := action.(k8stesting.CreateAction).GetObject().(*k8scorev1.Secret)
				secret.ResourceVersion = "1"
				return false, nil, nil
			})
			c.PrependReactor("update", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
				secret := action.(k8stesting.UpdateAction).GetObject().(*k8scorev1.Secret)
				if secret.Name != "octelium-init" || action.GetNamespace() != "default" {
					return false, nil, nil
				}
				count := inputWrites.Add(1)
				secret.ResourceVersion = "2"
				if state == "response-lost" && count == 1 {
					assert.NoError(t, c.Tracker().Update(action.GetResource(), secret.DeepCopy(), action.GetNamespace()))
					return true, nil, k8serr.NewServiceUnavailable("response lost after bootstrap update")
				}
				return false, nil, nil
			})
			c.PrependReactor("update", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				job := action.(k8stesting.UpdateAction).GetObject().(*batchv1.Job)
				if job.Spec.Suspend != nil && *job.Spec.Suspend {
					return false, nil, nil
				}
				if starts.Add(1) == 1 {
					job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
					return false, nil, nil
				}
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
				token := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "init-token", Namespace: "octelium"}, Data: map[string][]byte{"data": []byte("new-admin-token")}}
				if state == "checkpoint-only" {
					object, err := c.Tracker().Get(k8scorev1.SchemeGroupVersion.WithResource("secrets"), "octelium", "octelium-genesis-init")
					if assert.NoError(t, err) {
						checkpoint := object.(*k8scorev1.Secret).DeepCopy()
						checkpoint.Annotations = map[string]string{"octelium.com/genesis-init-complete": "true"}
						checkpoint.Data["id"] = []byte("new-init-id")
						assert.NoError(t, c.Tracker().Update(k8scorev1.SchemeGroupVersion.WithResource("secrets"), checkpoint, "octelium"))
					}
					token.Annotations = map[string]string{"octelium.com/genesis-init-id": "new-init-id"}
				}
				assert.NoError(t, c.Tracker().Add(token))
				return false, nil, nil
			})
			bootstrapPath := newTestBootstrap(t)
			contents, err := os.ReadFile(bootstrapPath)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(bootstrapPath, []byte(strings.ReplaceAll(string(contents), "host: postgres,", "host: wrong.example,")), 0600))
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			args := []string{"init", "example.com", "--bootstrap=" + bootstrapPath, "--kubeconfig=" + config, "--kubecontext=local", "--version=1.2.3"}
			output, err := executeTestCommand(t, ctx, args...)
			require.Error(t, err)
			assert.NotContains(t, output, "Cluster installation is now complete")
			_, err = os.Stat(path)
			require.True(t, os.IsNotExist(err))
			original, err := c.CoreV1().Secrets("default").Get(t.Context(), "octelium-init", k8smetav1.GetOptions{})
			require.NoError(t, err)
			switch state {
			case "checkpoint-only":
				require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{
					ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-genesis-init", Namespace: "octelium", UID: "previous-checkpoint"},
					Data:       map[string][]byte{"id": []byte("previous-init-id"), "version": []byte("1"), "input-hash": []byte(strings.Repeat("0", 64))},
				}))
			case "postgres-started", "redis-started":
				name := "octelium-postgres"
				if state == "redis-started" {
					name = "octelium-redis"
				}
				require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: name, Namespace: "octelium", UID: "existing-storage"}, Data: map[string][]byte{"value": []byte("preserved")}}))
			}
			require.NoError(t, os.WriteFile(bootstrapPath, []byte(strings.ReplaceAll(string(contents), "host: postgres,", "host: corrected.example,")), 0600))
			output, err = executeTestCommand(t, ctx, args...)
			if state == "postgres-started" || state == "redis-started" {
				require.ErrorContains(t, err, "bootstrap differs")
				assert.NotContains(t, output, "new-admin-token")
				assert.Zero(t, inputWrites.Load())
				current, err := c.CoreV1().Secrets("default").Get(t.Context(), original.Name, k8smetav1.GetOptions{})
				require.NoError(t, err)
				assert.Equal(t, original, current)
				return
			}
			require.NoError(t, err, output)
			token, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, "new-admin-token", string(token))
			assert.Equal(t, int32(1), inputWrites.Load())
			current, err := c.CoreV1().Secrets("default").Get(t.Context(), original.Name, k8smetav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, original.UID, current.UID)
			bootstrap := &cbootstrapv1.Config{}
			require.NoError(t, pbutils.Unmarshal(current.Data["bootstrap"], bootstrap))
			assert.Equal(t, "corrected.example", bootstrap.Spec.PrimaryStorage.GetPostgresql().Host)
		})
	}
}

func TestInitCommandRejectsInvalidPasswordReferencesE2E(t *testing.T) {
	for _, storage := range []string{"postgres", "redis"} {
		for _, ref := range []string{"{}", "{name: ''}", "{name: Credentials}", "{name: credentials, namespace: a/b}", "{name: credentials, key: a/b}"} {
			for _, stdin := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/stdin=%t", storage, ref, stdin), func(t *testing.T) {
					c, config := newTestKubernetes(t)
					pg, redis := "password: private-postgres-value", "password: private-redis-value"
					if storage == "postgres" {
						pg = "passwordFromSecret: " + ref
					} else {
						redis = "passwordFromSecret: " + ref
					}
					bootstrap := filepath.Join(t.TempDir(), "bootstrap.yaml")
					require.NoError(t, os.WriteFile(bootstrap, []byte(fmt.Sprintf("spec:\n  primaryStorage:\n    postgresql: {host: postgres, username: installer, %s}\n  secondaryStorage:\n    redis: {host: redis, %s}\n", pg, redis)), 0600))
					if stdin {
						file, err := os.Open(bootstrap)
						require.NoError(t, err)
						previous := os.Stdin
						os.Stdin = file
						t.Cleanup(func() { os.Stdin = previous; file.Close() })
						bootstrap = "-"
					}
					credential := filepath.Join(t.TempDir(), "initial-token")
					t.Setenv("OCTELIUM_AUTH_TOKEN_SAVE_PATH", credential)
					output, err := executeTestCommand(t, t.Context(), "init", "example.com", "--bootstrap="+bootstrap, "--kubeconfig="+config, "--version=1.2.3")
					require.ErrorContains(t, err, "passwordFromSecret")
					assert.Empty(t, c.Actions())
					assert.NoFileExists(t, credential)
					for _, value := range []string{"private-postgres-value", "private-redis-value"} {
						assert.NotContains(t, output, value)
						assert.NotContains(t, err.Error(), value)
					}
				})
			}
		}
	}
}

func TestUpgradeAndPackageConfigurationRetryE2E(t *testing.T) {
	for _, command := range []string{"upgrade", "install-package"} {
		for _, stage := range []string{"transient", "forbidden", "corrupt", "missing-key", "legacy-missing"} {
			t.Run(command+"/"+stage, func(t *testing.T) {
				c, config := newTestKubernetes(t)
				if stage != "legacy-missing" {
					cm := &k8scorev1.ConfigMap{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-installation", Namespace: "octelium"}, Data: map[string]string{"installation.json": `{"spiffe":{"enable":true,"trustDomain":"test.local","csiDriver":{"name":"custom.csi"}}}`}}
					if stage == "corrupt" {
						cm.Data["installation.json"] = "{invalid"
					}
					if stage == "missing-key" {
						cm.Data = nil
					}
					require.NoError(t, c.Tracker().Add(cm))
				}
				failed := false
				c.PrependReactor("get", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if stage == "forbidden" {
						return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "octelium-installation", fmt.Errorf("permission denied"))
					}
					if stage == "transient" && !failed {
						failed = true
						return true, nil, k8serr.NewServiceUnavailable("temporary installation metadata outage")
					}
					return false, nil, nil
				})
				args := []string{command, "example.com", "--kubeconfig=" + config, "--version=1.2.3"}
				if command == "install-package" {
					args = append(args, "--package=cordium", "--upgrade")
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				out, err := executeTestCommand(t, ctx, args...)
				jobs, listErr := c.BatchV1().Jobs("octelium").List(t.Context(), k8smetav1.ListOptions{})
				require.NoError(t, listErr)
				if stage == "transient" || stage == "legacy-missing" {
					require.NoError(t, err, out)
					require.Len(t, jobs.Items, 1)
					if stage == "transient" {
						assert.True(t, failed)
						assert.Equal(t, "custom.csi", jobs.Items[0].Spec.Template.Spec.Volumes[0].CSI.Driver)
					} else {
						assert.Empty(t, jobs.Items[0].Spec.Template.Spec.Volumes)
					}
				} else {
					require.Error(t, err)
					assert.Empty(t, jobs.Items)
					assert.NotContains(t, out, "has started")
				}
			})
		}
	}
}

func TestCommandClusterTargetE2E(t *testing.T) {
	for _, command := range []string{"upgrade", "install-package/cordium", "upgrade-package/octeliumee"} {
		for _, state := range []string{"bound", "legacy", "secret-forbidden", "wrong-domain", "wrong-bootstrap", "wrong-region", "corrupt-region", "partial-identity", "transient", "lost-create-response"} {
			t.Run(command+"/"+state, func(t *testing.T) {
				c, config := newTestKubernetes(t)
				annotations := map[string]string{
					"octelium.com/genesis-cluster-uid": "cluster-uid", "octelium.com/genesis-domain": "example.com",
					"octelium.com/genesis-region-uid": "region-uid", "octelium.com/genesis-region-name": "west", "octelium.com/genesis-namespace-uid": "namespace-uid",
				}
				if state == "legacy" || state == "secret-forbidden" {
					annotations = nil
				}
				if state == "partial-identity" {
					delete(annotations, "octelium.com/genesis-namespace-uid")
				}
				require.NoError(t, c.Tracker().Add(&k8scorev1.ConfigMap{
					ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-installation", Namespace: "octelium", Annotations: annotations},
					Data:       map[string]string{"installation.json": `{"spiffe":{"enable":true,"csiDriver":{"name":"custom.csi"}}}`},
				}))
				bootstrap := &k8scorev1.Secret{ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "octelium"}, Data: map[string][]byte{
					"domain": []byte("example.com"), "region": pbutils.MarshalMust(&corev1.Region{Metadata: &metav1.Metadata{Name: "west"}}),
				}}
				if state == "wrong-bootstrap" {
					bootstrap.Data["domain"] = []byte("another.example")
				}
				if state == "wrong-region" {
					bootstrap.Data["region"] = pbutils.MarshalMust(&corev1.Region{Metadata: &metav1.Metadata{Name: "east"}})
				}
				if state == "corrupt-region" {
					bootstrap.Data["region"] = []byte{0xff}
				}
				require.NoError(t, c.Tracker().Add(bootstrap))
				failed := false
				c.PrependReactor("get", "secrets", func(action k8stesting.Action) (bool, runtime.Object, error) {
					if state == "secret-forbidden" {
						return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "octelium-init", fmt.Errorf("legacy restricted role"))
					}
					if state == "transient" && !failed {
						failed = true
						return true, nil, k8serr.NewServiceUnavailable("short bootstrap read outage")
					}
					return false, nil, nil
				})
				if state == "lost-create-response" {
					c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
						job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
						job.UID = "accepted-target-job"
						require.NoError(t, c.Tracker().Create(action.GetResource(), job, action.GetNamespace()))
						return true, nil, k8serr.NewServiceUnavailable("response lost after commit")
					})
				}
				domain := "example.com"
				if state == "wrong-domain" {
					domain = "another.example"
				}
				args := []string{"upgrade", domain, "--kubeconfig=" + config, "--version=1.2.3"}
				if command != "upgrade" {
					args[0] = "install-package"
					pkg := "cordium"
					if command == "upgrade-package/octeliumee" {
						pkg = "octeliumee"
						args = append(args, "--upgrade")
					}
					args = append(args, "--package="+pkg)
				}
				out, err := executeTestCommand(t, t.Context(), args...)
				blocked := state == "wrong-domain" || state == "wrong-bootstrap" || state == "wrong-region" || state == "corrupt-region" || state == "partial-identity"
				if blocked {
					require.Error(t, err)
					assert.NotContains(t, out, "has started")
					for _, action := range c.Actions() {
						assert.Contains(t, []string{"get", "list"}, action.GetVerb())
					}
				} else {
					require.NoError(t, err, out)
				}
				jobs, listErr := c.BatchV1().Jobs("octelium").List(t.Context(), k8smetav1.ListOptions{})
				require.NoError(t, listErr)
				if blocked {
					assert.Empty(t, jobs.Items)
					return
				}
				require.Len(t, jobs.Items, 1)
				job := jobs.Items[0]
				assert.Nil(t, job.Spec.Suspend)
				assert.Equal(t, "custom.csi", job.Spec.Template.Spec.Volumes[0].CSI.Driver)
				env := map[string]string{}
				for _, value := range job.Spec.Template.Spec.Containers[0].Env {
					env[value.Name] = value.Value
				}
				if state == "secret-forbidden" {
					assert.Equal(t, "default", env["OCTELIUM_REGION_NAME"])
				} else {
					assert.Equal(t, "west", env["OCTELIUM_REGION_NAME"])
				}
				if annotations != nil {
					assert.Equal(t, "cluster-uid", env["OCTELIUM_GENESIS_CLUSTER_UID"])
					assert.Equal(t, "region-uid", env["OCTELIUM_GENESIS_REGION_UID"])
					assert.Equal(t, "namespace-uid", env["OCTELIUM_GENESIS_NAMESPACE_UID"])
				} else {
					assert.NotContains(t, env, "OCTELIUM_GENESIS_CLUSTER_UID")
				}
				if state == "transient" {
					assert.True(t, failed)
				}
			})
		}
	}
}

func TestUpgradeCompletionE2E(t *testing.T) {
	for _, state := range []string{"already-complete", "same-version", "secondary-region", "legacy-cluster", "lost-create-response", "list-only-role", "failed-job", "failed-with-target-version", "pending-with-unrelated-version", "replaced-job", "deleted-job", "deleting-job", "cancelled", "retrying-pod"} {
		t.Run(state, func(t *testing.T) {
			var publicCalls atomic.Int32
			ctx := newTestCoreServer(t, func(_ context.Context, _ *metav1.GetOptions) (*corev1.Region, error) {
				n := publicCalls.Add(1)
				version := "1.2.3"
				if state == "pending-with-unrelated-version" {
					version = "1.0.0"
					if n > 1 {
						version = "1.1.0"
					}
				}
				return &corev1.Region{Status: &corev1.Region_Status{Version: version}}, nil
			})
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if state == "pending-with-unrelated-version" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 3*time.Second)
				defer deadlineCancel()
			}
			c, config := newTestKubernetes(t)
			if state == "secondary-region" || state == "legacy-cluster" {
				region := "default"
				if state == "secondary-region" {
					region = "europe"
				}
				require.NoError(t, c.Tracker().Add(&k8scorev1.Secret{
					ObjectMeta: k8smetav1.ObjectMeta{Name: "octelium-init", Namespace: "octelium"},
					Data:       map[string][]byte{"region": pbutils.MarshalMust(&corev1.Region{Metadata: &metav1.Metadata{Name: region}})},
				}))
			}
			var submitted atomic.Pointer[batchv1.Job]
			var reads atomic.Int32
			c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
				job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
				switch state {
				case "failed-job", "failed-with-target-version":
					job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue, Reason: "BackoffLimitExceeded"}}
				case "pending-with-unrelated-version", "retrying-pod":
					job.Status = batchv1.JobStatus{Failed: 1}
				}
				submitted.Store(job.DeepCopy())
				if state == "lost-create-response" {
					assert.NoError(t, c.Tracker().Create(action.GetResource(), job, job.Namespace))
					return true, nil, k8serr.NewServiceUnavailable("Response lost after persisting Job")
				}
				return false, nil, nil
			})
			c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				n := reads.Add(1)
				accepted := submitted.Load()
				if accepted == nil {
					return false, nil, nil
				}
				assert.Equal(t, accepted.Namespace, action.GetNamespace())
				assert.Equal(t, accepted.Name, action.(k8stesting.GetAction).GetName())
				job := accepted.DeepCopy()
				switch state {
				case "list-only-role":
					return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), job.Name, fmt.Errorf("only list is permitted"))
				case "replaced-job":
					job.UID = "replacement"
					return true, job, nil
				case "deleted-job":
					return true, nil, k8serr.NewNotFound(action.GetResource().GroupResource(), job.Name)
				case "deleting-job":
					job.DeletionTimestamp = new(k8smetav1.Now())
					return true, job, nil
				case "cancelled":
					cancel()
					return true, nil, context.Canceled
				case "retrying-pod":
					if n > 1 {
						job.Status = batchv1.JobStatus{Succeeded: 1, Conditions: []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}}
					}
					return true, job, nil
				}
				return false, nil, nil
			})
			out, err := executeTestCommand(t, ctx, "upgrade", "example.invalid", "--kubeconfig="+config, "--version=1.2.3", "--wait")
			switch state {
			case "failed-job", "failed-with-target-version", "pending-with-unrelated-version", "replaced-job", "deleted-job", "deleting-job", "cancelled":
				require.Error(t, err)
				assert.NotContains(t, out, "Cluster has been upgraded")
				if state == "cancelled" {
					assert.ErrorIs(t, err, context.Canceled)
				}
				if state == "pending-with-unrelated-version" {
					assert.ErrorIs(t, err, context.DeadlineExceeded)
				}
			default:
				require.NoError(t, err, out)
				assert.Contains(t, out, "Cluster has been upgraded")
			}
			assert.Zero(t, publicCalls.Load())
			accepted := submitted.Load()
			require.NotNil(t, accepted)
			assert.NotEmpty(t, accepted.UID)
			assert.Regexp(t, "^octelium-genesis-upgrade-[a-z0-9]{6}$", accepted.Name)
			assert.Nil(t, accepted.Spec.Suspend)
			assert.Equal(t, []string{"upgrade"}, accepted.Spec.Template.Spec.Containers[0].Args)
			assert.Contains(t, accepted.Spec.Template.Spec.Containers[0].Image, "octelium-genesis:1.2.3")
			for _, action := range c.Actions() {
				assert.NotEqual(t, "update", action.GetVerb())
				assert.NotEqual(t, "delete", action.GetVerb())
			}
		})
	}
}

func TestUpgradeWaitKubernetesAuthorizationFailureE2E(t *testing.T) {
	c, config := newTestKubernetes(t)
	c.PrependReactor("get", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "test", fmt.Errorf("permission denied"))
	})
	c.PrependReactor("list", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.(k8stesting.ListAction).GetListRestrictions().Fields.String() != "" {
			return true, nil, k8serr.NewForbidden(action.GetResource().GroupResource(), "test", fmt.Errorf("permission denied"))
		}
		return false, nil, nil
	})
	out, err := executeTestCommand(t, t.Context(), "upgrade", "example.invalid", "--kubeconfig="+config, "--wait")
	require.True(t, k8serr.IsForbidden(err), "%v", err)
	assert.NotContains(t, out, "Cluster has been upgraded")
}

func TestUpgradeWaitWithoutPublicAPIE2E(t *testing.T) {
	var publicCalls atomic.Int32
	ctx := newTestCoreServer(t, func(context.Context, *metav1.GetOptions) (*corev1.Region, error) {
		publicCalls.Add(1)
		return nil, status.Error(codes.Unavailable, "Public API is temporarily unavailable during rollout")
	})
	c, config := newTestKubernetes(t)
	c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobComplete, Status: k8scorev1.ConditionTrue}}
		return false, nil, nil
	})
	out, err := executeTestCommand(t, ctx, "upgrade", "example.invalid", "--kubeconfig="+config, "--wait")
	require.NoError(t, err)
	assert.Contains(t, out, "Cluster has been upgraded")
	assert.Zero(t, publicCalls.Load())
}

func TestUpgradeWithoutWaitDoesNotObserveJobE2E(t *testing.T) {
	c, config := newTestKubernetes(t)
	c.PrependReactor("create", "jobs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		job := action.(k8stesting.CreateAction).GetObject().(*batchv1.Job)
		job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: k8scorev1.ConditionTrue}}
		return false, nil, nil
	})
	out, err := executeTestCommand(t, t.Context(), "upgrade", "example.invalid", "--kubeconfig="+config)
	require.NoError(t, err)
	assert.Contains(t, out, "Upgrading the Cluster has started")
	assert.NotContains(t, out, "Cluster has been upgraded")
	for _, action := range c.Actions() {
		assert.False(t, action.Matches("get", "jobs"))
		assert.NotEqual(t, "delete", action.GetVerb())
	}
}

func TestUpgradeCancelledBeforeSubmissionE2E(t *testing.T) {
	c, config := newTestKubernetes(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out, err := executeTestCommand(t, ctx, "upgrade", "example.invalid", "--kubeconfig="+config, "--wait")
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, c.Actions())
	assert.NotContains(t, out, "Upgrading the Cluster has started")
	assert.NotContains(t, out, "Cluster has been upgraded")
}
