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

package resources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/stretchr/testify/assert"
)

func TestLoadResources(t *testing.T) {

	yamlFile := `
kind: User
metadata:
 name: usr1
spec:
 type: HUMAN


---
kind: Namespace
metadata:
 name: ns1
spec: {}

---
kind: Service
metadata:
 name: svc1
spec:
 port: 8080
 config:
  upstream:
   url: https://example.com
`

	rscList, err := loadResources(strings.NewReader(yamlFile), "file.yaml", ucorev1.NewObject)
	assert.Nil(t, err, "%+v", err)

	assert.Equal(t, 3, len(rscList))

	assert.Equal(t, "usr1", rscList[0].(*corev1.User).Metadata.Name)
	assert.Equal(t, "ns1", rscList[1].(*corev1.Namespace).Metadata.Name)
	assert.Equal(t, "https://example.com", rscList[2].(*corev1.Service).Spec.GetConfig().GetUpstream().GetUrl())
}

func TestLoadResourcesUnknownField(t *testing.T) {

	yamlFile := `
kind: Service
metadata:
 name: svc1
spec:
 config:
  upstream:
   url: https://example.com
   urll: https://example.com
`

	rscList, err := loadResources(strings.NewReader(yamlFile), "file.yaml", ucorev1.NewObject)
	assert.Nil(t, err, "%+v", err)

	assert.Equal(t, 1, len(rscList))
	assert.Equal(t, "svc1", rscList[0].(*corev1.Service).Metadata.Name)
	assert.Equal(t, "https://example.com",
		rscList[0].(*corev1.Service).Spec.GetConfig().GetUpstream().GetUrl())
}

func TestLoadResourcesInvalidKind(t *testing.T) {

	yamlFile := `
kind: User
metadata:
 name: usr1
spec:
 type: HUMAN

---
kind: Users
metadata:
 name: usr2
spec: {}
`

	_, err := loadResources(strings.NewReader(yamlFile), "file.yaml", ucorev1.NewObject)
	assert.NotNil(t, err)
	assert.True(t, strings.Contains(err.Error(), "document 2"), "%+v", err)
}

func TestLoadResourcesPaths(t *testing.T) {

	yamlFile := `
kind: User
metadata:
 name: usr1
spec:
 type: HUMAN
`

	dir := t.TempDir()

	assert.Nil(t, os.WriteFile(filepath.Join(dir, "usr.yaml"), []byte(yamlFile), 0644))
	assert.Nil(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a Resource"), 0644))

	rscList, err := LoadCoreResources(dir)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 1, len(rscList))
	assert.Equal(t, "usr1", rscList[0].(*corev1.User).Metadata.Name)

	rscList, err = LoadCoreResources(filepath.Join(dir, "usr.yaml"))
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 1, len(rscList))

	rscList, err = LoadCoreResources(t.TempDir())
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 0, len(rscList))

	_, err = LoadCoreResources(filepath.Join(dir, "does-not-exist.yaml"))
	assert.NotNil(t, err)
}

func TestValidateResources(t *testing.T) {

	yamlFile := `
kind: User
metadata:
 name: usr1
spec:
 type: HUMAN

---
kind: User
metadata:
 name: usr2
spec:
 typ: HUMAN

---
kind: User
metadata:
 name: usr3
spec:
 type: HUMANN

---
kind: Service
metadata:
 name: svc1
spec:
 port: abc

---
metadata:
 name: usr4
spec: {}

---
kind: Users
metadata:
 name: usr5
spec: {}

---
kind: Namespace
metadata:
 name: ns1
spec: {}
`

	rscList, errs := validateResources(strings.NewReader(yamlFile), "file.yaml", ucorev1.NewObject)

	assert.Equal(t, 2, len(rscList))
	assert.Equal(t, "usr1", rscList[0].(*corev1.User).Metadata.Name)
	assert.Equal(t, "ns1", rscList[1].(*corev1.Namespace).Metadata.Name)

	assert.Equal(t, 5, len(errs))
	assert.True(t, strings.Contains(errs[0].Error(), "User `usr2` at file.yaml (document 2)"), "%+v", errs[0])
	assert.True(t, strings.Contains(errs[0].Error(), "typ"), "%+v", errs[0])
	assert.True(t, strings.Contains(errs[1].Error(), "User `usr3` at file.yaml (document 3)"), "%+v", errs[1])
	assert.True(t, strings.Contains(errs[1].Error(), "HUMANN"), "%+v", errs[1])
	assert.True(t, strings.Contains(errs[2].Error(), "Service `svc1` at file.yaml (document 4)"), "%+v", errs[2])
	assert.True(t, strings.Contains(errs[3].Error(), "Resource at file.yaml (document 5)"), "%+v", errs[3])
	assert.True(t, strings.Contains(errs[4].Error(), "Users `usr5` at file.yaml (document 6)"), "%+v", errs[4])
}

func TestValidateResourcesInvalidYAML(t *testing.T) {

	yamlFile := `
kind: User
metadata:
 name: usr1
spec:
 type: HUMAN

---
kind: User
metadata:
 name: [usr2
`

	rscList, errs := validateResources(strings.NewReader(yamlFile), "file.yaml", ucorev1.NewObject)

	assert.Equal(t, 1, len(rscList))
	assert.Equal(t, "usr1", rscList[0].(*corev1.User).Metadata.Name)

	assert.Equal(t, 1, len(errs))
	assert.True(t, strings.Contains(errs[0].Error(), "Could not decode yaml item in file.yaml"), "%+v", errs[0])
}

func TestValidateResourcesPaths(t *testing.T) {

	dir := t.TempDir()

	assert.Nil(t, os.WriteFile(filepath.Join(dir, "usr.yaml"), []byte(`
kind: User
metadata:
 name: usr1
spec:
 type: HUMAN
`), 0644))

	assert.Nil(t, os.MkdirAll(filepath.Join(dir, "svc"), 0755))
	assert.Nil(t, os.WriteFile(filepath.Join(dir, "svc", "svc.yaml"), []byte(`
kind: Service
metadata:
 name: svc1
spec:
 port: abc
`), 0644))

	rscList, errs, err := ValidateCoreResources(dir)
	assert.Nil(t, err, "%+v", err)
	assert.Equal(t, 1, len(rscList))
	assert.Equal(t, "usr1", rscList[0].(*corev1.User).Metadata.Name)
	assert.Equal(t, 1, len(errs))
	assert.True(t, strings.Contains(errs[0].Error(), filepath.Join(dir, "svc", "svc.yaml")), "%+v", errs[0])

	_, _, err = ValidateCoreResources(filepath.Join(dir, "does-not-exist.yaml"))
	assert.NotNil(t, err)
}
