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
	"github.com/pkg/errors"
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
	assert.True(t, strings.HasPrefix(errs[0].Error(), "Invalid User `usr2` at file.yaml:13:2: "), "%+v", errs[0])
	assert.True(t, strings.Contains(errs[0].Error(), `"typ"`), "%+v", errs[0])
	assert.True(t, strings.HasPrefix(errs[1].Error(), "Invalid User `usr3` at file.yaml:20:2: "), "%+v", errs[1])
	assert.True(t, strings.Contains(errs[1].Error(), `"HUMANN"`), "%+v", errs[1])
	assert.True(t, strings.HasPrefix(errs[2].Error(), "Invalid Service `svc1` at file.yaml:27:2: "), "%+v", errs[2])
	assert.True(t, strings.Contains(errs[2].Error(), `"abc"`), "%+v", errs[2])
	assert.True(t, strings.HasPrefix(errs[3].Error(), "Invalid Resource at file.yaml:30:1: "), "%+v", errs[3])
	assert.True(t, strings.HasPrefix(errs[4].Error(), "Invalid Users `usr5` at file.yaml:35:1: "), "%+v", errs[4])

	for _, err := range errs {
		assert.False(t, strings.Contains(err.Error(), "(line"), "%+v", err)
		assert.False(t, strings.Contains(err.Error(), "proto:"), "%+v", err)
	}
}

func TestValidateResourcesNodeErrs(t *testing.T) {

	yamlFile := `
kind: Service
metadata:
 name: svc1
spec:
 port: abc
 portt: 8080
 config:
  upstream:
   urll: https://example.com

---
kind: Policy
metadata:
 name: pol1
spec:
 rules:
  - effect: ALLOW
  - effect: ALLOWW

---
kind: Service
metadata:
 name: svc2
spec:
 config:
  upstream: &upstream
   url: https://example.com
   urll: https://example.com

---
kind: Service
metadata:
 name: svc3
spec:
 config:
  upstream:
   url: https://example.com
   container: {}
`

	rscList, errs := validateResources(strings.NewReader(yamlFile), "file.yaml", ucorev1.NewObject)

	assert.Equal(t, 0, len(rscList))
	assert.Equal(t, 6, len(errs))

	assert.True(t, strings.HasPrefix(errs[0].Error(), "Invalid Service `svc1` at file.yaml:6:2: "), "%+v", errs[0])
	assert.True(t, strings.Contains(errs[0].Error(), `"abc"`), "%+v", errs[0])
	assert.True(t, strings.HasPrefix(errs[1].Error(), "Invalid Service `svc1` at file.yaml:7:2: "), "%+v", errs[1])
	assert.True(t, strings.Contains(errs[1].Error(), `"portt"`), "%+v", errs[1])
	assert.True(t, strings.HasPrefix(errs[2].Error(), "Invalid Service `svc1` at file.yaml:10:4: "), "%+v", errs[2])
	assert.True(t, strings.Contains(errs[2].Error(), `"urll"`), "%+v", errs[2])

	assert.True(t, strings.HasPrefix(errs[3].Error(), "Invalid Policy `pol1` at file.yaml:19:5: "), "%+v", errs[3])
	assert.True(t, strings.Contains(errs[3].Error(), `"ALLOWW"`), "%+v", errs[3])

	assert.True(t, strings.HasPrefix(errs[4].Error(), "Invalid Service `svc2` at file.yaml:29:4: "), "%+v", errs[4])
	assert.True(t, strings.Contains(errs[4].Error(), `"urll"`), "%+v", errs[4])

	assert.True(t, strings.HasPrefix(errs[5].Error(), "Invalid Service `svc3` at file.yaml:37:3: "), "%+v", errs[5])
	assert.True(t, strings.Contains(errs[5].Error(), "oneof"), "%+v", errs[5])

	for _, err := range errs {
		assert.False(t, strings.Contains(err.Error(), "(line"), "%+v", err)
	}
}

func TestValidateResourcesMergeKey(t *testing.T) {

	yamlFile := `
kind: Policy
metadata:
 name: pol1
spec:
 rules:
  - &rule
   effect: ALLOW
   condition:
    match: ctx.user.spec.type == "HUMAN"
  - <<: *rule
    effect: DENY
  - <<: *rule
    effectt: DENY
`

	rscList, errs := validateResources(strings.NewReader(yamlFile), "file.yaml", ucorev1.NewObject)

	assert.Equal(t, 0, len(rscList))
	assert.Equal(t, 1, len(errs))
	assert.True(t, strings.HasPrefix(errs[0].Error(), "Invalid Policy `pol1` at file.yaml:14:5: "), "%+v", errs[0])
	assert.True(t, strings.Contains(errs[0].Error(), `"effectt"`), "%+v", errs[0])

	rscList, errs = validateResources(strings.NewReader(strings.ReplaceAll(yamlFile, "effectt", "effect")),
		"file.yaml", ucorev1.NewObject)
	assert.Equal(t, 0, len(errs), "%+v", errs)
	assert.Equal(t, 3, len(rscList[0].(*corev1.Policy).Spec.Rules))
	assert.Equal(t, corev1.Policy_Spec_Rule_DENY, rscList[0].(*corev1.Policy).Spec.Rules[1].Effect)
	assert.Equal(t, `ctx.user.spec.type == "HUMAN"`,
		rscList[0].(*corev1.Policy).Spec.Rules[1].Condition.GetMatch())
}

func TestValidateResourcesDocuments(t *testing.T) {

	yamlFile := `
kind: User
metadata:
 name: usr1
spec:
 type: HUMAN
---
---
~
---
- kind: User
---
kind: Group
metadata:
 name: grp1
spec: {}
`

	rscList, errs := validateResources(strings.NewReader(yamlFile), "file.yaml", ucorev1.NewObject)

	assert.Equal(t, 2, len(rscList))
	assert.Equal(t, "usr1", rscList[0].(*corev1.User).Metadata.Name)
	assert.Equal(t, "grp1", rscList[1].(*corev1.Group).Metadata.Name)

	assert.Equal(t, 1, len(errs))
	assert.True(t, strings.HasPrefix(errs[0].Error(), "Could not decode yaml item at file.yaml:11:1: "), "%+v", errs[0])
}

func TestGetErrMessage(t *testing.T) {

	assert.Equal(t, `unknown field "typ"`,
		getErrMessage(errors.New(`proto: (line 1:51): unknown field "typ"`)))
	assert.Equal(t, `unknown field "typ"`,
		getErrMessage(errors.New("proto:\u00a0(line 1:51):\u00a0unknown field \"typ\"")))
	assert.Equal(t, `Invalid kind: Users`,
		getErrMessage(errors.New(`Invalid kind: Users`)))
	assert.Equal(t, `proto: unknown field "typ"`,
		getErrMessage(errors.New(`proto: unknown field "typ"`)))
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
