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

package initcmd

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/octelium/octelium/apis/cluster/cbootstrapv1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newKubeConfigFile(t *testing.T) string {
	ret := path.Join(t.TempDir(), "config")
	assert.Nil(t, os.WriteFile(ret, []byte("apiVersion: v1\nkind: Config\n"), 0600))
	return ret
}

func TestValidateBootstrap(t *testing.T) {
	newBootstrap := func(t *testing.T) *cbootstrapv1.Config {
		bs := &cbootstrapv1.Config{}
		require.NoError(t, pbutils.UnmarshalYAML([]byte("spec:\n  primaryStorage:\n    postgresql: {host: postgres.storage.svc, username: installer, password: postgres-secret}\n  secondaryStorage:\n    redis: {host: redis.storage.svc, password: redis-secret}\n"), bs))
		return bs
	}
	for _, tc := range []struct {
		name   string
		change func(*cbootstrapv1.Config)
		want   string
	}{
		{"missing spec", func(bs *cbootstrapv1.Config) { bs.Spec = nil }, "Nil bootstrap spec"},
		{"missing primary storage", func(bs *cbootstrapv1.Config) { bs.Spec.PrimaryStorage = nil }, "No Postgres"},
		{"missing postgres", func(bs *cbootstrapv1.Config) { bs.Spec.PrimaryStorage.Type = nil }, "No Postgres"},
		{"empty postgres host", func(bs *cbootstrapv1.Config) { bs.Spec.PrimaryStorage.GetPostgresql().Host = "" }, "Empty postgres host"},
		{"empty postgres username", func(bs *cbootstrapv1.Config) { bs.Spec.PrimaryStorage.GetPostgresql().Username = "" }, "Empty postgres user"},
		{"missing postgres password", func(bs *cbootstrapv1.Config) { bs.Spec.PrimaryStorage.GetPostgresql().PasswordType = nil }, "either password or passwordFromSecret"},
		{"empty postgres password", func(bs *cbootstrapv1.Config) {
			bs.Spec.PrimaryStorage.GetPostgresql().PasswordType = &cbootstrapv1.Config_Spec_PrimaryStorage_Postgresql_Password{}
		}, "Empty postgres password"},
		{"invalid postgres port", func(bs *cbootstrapv1.Config) { bs.Spec.PrimaryStorage.GetPostgresql().Port = 65536 }, "Invalid postgres port"},
		{"invalid postgres host", func(bs *cbootstrapv1.Config) { bs.Spec.PrimaryStorage.GetPostgresql().Host = "https://postgres:5432" }, "Invalid postgres host"},
		{"missing secondary storage", func(bs *cbootstrapv1.Config) { bs.Spec.SecondaryStorage = nil }, "No Redis"},
		{"missing redis", func(bs *cbootstrapv1.Config) { bs.Spec.SecondaryStorage.Type = nil }, "No Redis"},
		{"empty redis host", func(bs *cbootstrapv1.Config) { bs.Spec.SecondaryStorage.GetRedis().Host = "" }, "Empty redis host"},
		{"missing redis password", func(bs *cbootstrapv1.Config) { bs.Spec.SecondaryStorage.GetRedis().PasswordType = nil }, "either password or passwordFromSecret"},
		{"empty redis password", func(bs *cbootstrapv1.Config) {
			bs.Spec.SecondaryStorage.GetRedis().PasswordType = &cbootstrapv1.Config_Spec_SecondaryStorage_Redis_Password{}
		}, "Empty redis password"},
		{"invalid redis port", func(bs *cbootstrapv1.Config) { bs.Spec.SecondaryStorage.GetRedis().Port = 65536 }, "Invalid redis port"},
		{"invalid redis host", func(bs *cbootstrapv1.Config) { bs.Spec.SecondaryStorage.GetRedis().Host = "redis host" }, "Invalid redis host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bs := newBootstrap(t)
			tc.change(bs)
			require.ErrorContains(t, validateBootstrap(bs), tc.want)
		})
	}
	assert.ErrorContains(t, validateBootstrap(nil), "Nil bootstrap spec")
	for _, host := range []string{"localhost", "postgres.storage.svc", "192.0.2.10", "2001:db8::1"} {
		for _, port := range []int32{0, 1, 5432, 65535} {
			t.Run(fmt.Sprintf("%s:%d", host, port), func(t *testing.T) {
				bs := newBootstrap(t)
				bs.Spec.PrimaryStorage.GetPostgresql().Host = host
				bs.Spec.SecondaryStorage.GetRedis().Host = host
				bs.Spec.PrimaryStorage.GetPostgresql().Port = port
				bs.Spec.SecondaryStorage.GetRedis().Port = port
				assert.NoError(t, validateBootstrap(bs))
			})
		}
	}
	for _, ref := range []string{"{name: credentials}", "{name: credentials, namespace: storage, key: custom}"} {
		bs := &cbootstrapv1.Config{}
		require.NoError(t, pbutils.UnmarshalYAML([]byte(fmt.Sprintf("spec:\n  primaryStorage:\n    postgresql: {host: postgres, username: installer, passwordFromSecret: %s}\n  secondaryStorage:\n    redis: {host: redis, passwordFromSecret: %s}\n", ref, ref)), bs))
		assert.NoError(t, validateBootstrap(bs))
	}
}

func TestKubeConfigFallbackAndInvalidFiles(t *testing.T) {
	t.Setenv("KUBECONFIG", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	config := path.Join(home, ".kube", "config")
	require.NoError(t, os.MkdirAll(path.Dir(config), 0700))
	require.NoError(t, os.WriteFile(config, []byte("apiVersion: v1\nkind: Config\n"), 0600))
	got, err := getKubeConfigFilePath("")
	require.NoError(t, err)
	assert.Equal(t, config, got)
	for _, data := range []string{"[invalid yaml", "apiVersion: v1\nkind: Config\n", "apiVersion: v1\nkind: Config\ncurrent-context: missing\n"} {
		require.NoError(t, os.WriteFile(config, []byte(data), 0600))
		_, err := BuildConfigFromFlags("", "")
		assert.Error(t, err)
	}
	_, err = BuildConfigFromFlags("", t.TempDir())
	assert.Error(t, err)
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	_, err = getKubeConfigFilePath("")
	assert.Error(t, err)
}

func TestGetKubeConfigFilePath(t *testing.T) {

	t.Run("an existent explicit path is used as-is", func(t *testing.T) {
		kubeConfigPath := newKubeConfigFile(t)
		t.Setenv("KUBECONFIG", newKubeConfigFile(t))

		ret, err := getKubeConfigFilePath(kubeConfigPath)
		assert.Nil(t, err)
		assert.Equal(t, kubeConfigPath, ret)
	})

	t.Run("a nonexistent explicit path does not fall back", func(t *testing.T) {
		envPath := newKubeConfigFile(t)
		t.Setenv("KUBECONFIG", envPath)

		ret, err := getKubeConfigFilePath(path.Join(t.TempDir(), "does-not-exist"))
		assert.NotNil(t, err)
		assert.Empty(t, ret)
		assert.NotEqual(t, envPath, ret)
	})

	t.Run("an unreadable explicit path does not fall back", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows does not support Unix directory permissions")
		}
		if os.Geteuid() == 0 {
			t.Skip("the root User can stat files inside an unreadable directory")
		}

		dir := t.TempDir()
		kubeConfigPath := path.Join(dir, "config")
		assert.Nil(t, os.WriteFile(kubeConfigPath, []byte("apiVersion: v1\n"), 0600))
		assert.Nil(t, os.Chmod(dir, 0000))
		t.Cleanup(func() {
			os.Chmod(dir, 0700)
		})

		envPath := newKubeConfigFile(t)
		t.Setenv("KUBECONFIG", envPath)

		ret, err := getKubeConfigFilePath(kubeConfigPath)
		assert.NotNil(t, err)
		assert.Empty(t, ret)
		assert.NotEqual(t, envPath, ret)
	})

	t.Run("KUBECONFIG is used when no explicit path is set", func(t *testing.T) {
		envPath := newKubeConfigFile(t)
		t.Setenv("KUBECONFIG", envPath)

		ret, err := getKubeConfigFilePath("")
		assert.Nil(t, err)
		assert.Equal(t, envPath, ret)
	})

	t.Run("no path at all is an error", func(t *testing.T) {
		t.Setenv("KUBECONFIG", "")
		t.Setenv("HOME", t.TempDir())
		t.Setenv("USERPROFILE", t.TempDir())

		ret, err := getKubeConfigFilePath("")
		assert.NotNil(t, err)
		assert.Empty(t, ret)
	})
}

func TestBuildConfigFromFlags(t *testing.T) {

	kubeConfigPath := path.Join(t.TempDir(), "config")
	assert.Nil(t, os.WriteFile(kubeConfigPath, []byte(`apiVersion: v1
kind: Config
current-context: ctx-1
clusters:
- name: cluster-1
  cluster:
    server: https://cluster-1.example.com
- name: cluster-2
  cluster:
    server: https://cluster-2.example.com
contexts:
- name: ctx-1
  context:
    cluster: cluster-1
- name: ctx-2
  context:
    cluster: cluster-2
`), 0600))

	t.Run("the current context is used when no kubecontext is set", func(t *testing.T) {
		cfg, err := BuildConfigFromFlags("", kubeConfigPath)
		assert.Nil(t, err)
		assert.Equal(t, "https://cluster-1.example.com", cfg.Host)
	})

	t.Run("the kubecontext overrides the current context", func(t *testing.T) {
		cfg, err := BuildConfigFromFlags("ctx-2", kubeConfigPath)
		assert.Nil(t, err)
		assert.Equal(t, "https://cluster-2.example.com", cfg.Host)
	})

	t.Run("an unknown kubecontext is an error", func(t *testing.T) {
		_, err := BuildConfigFromFlags("ctx-does-not-exist", kubeConfigPath)
		assert.NotNil(t, err)
	})

	t.Run("a nonexistent kubeconfig path is an error", func(t *testing.T) {
		t.Setenv("KUBECONFIG", kubeConfigPath)

		_, err := BuildConfigFromFlags("", path.Join(t.TempDir(), "does-not-exist"))
		assert.NotNil(t, err)
	})
}
