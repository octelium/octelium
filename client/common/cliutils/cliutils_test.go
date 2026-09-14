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
	"testing"

	"github.com/stretchr/testify/assert"
)

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
