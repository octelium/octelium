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
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newKubeConfigFile(t *testing.T) string {
	ret := path.Join(t.TempDir(), "config")
	assert.Nil(t, os.WriteFile(ret, []byte("apiVersion: v1\nkind: Config\n"), 0600))
	return ret
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
