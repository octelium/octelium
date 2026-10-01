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

package validate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateResources(t *testing.T) {

	dir := t.TempDir()

	usrPath := filepath.Join(dir, "usr.yaml")
	assert.Nil(t, os.WriteFile(usrPath, []byte(`
kind: User
metadata:
 name: usr1
spec:
 type: HUMAN

---
kind: Group
metadata:
 name: grp1
spec: {}
`), 0644))

	{
		rscList, errs, err := validateResources([]string{usrPath})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 2, len(rscList))
		assert.Equal(t, 0, len(errs))

		assert.Nil(t, doCmd(Cmd, []string{usrPath}))
	}

	invalidPath := filepath.Join(dir, "invalid.yaml")
	assert.Nil(t, os.WriteFile(invalidPath, []byte(`
kind: User
metadata:
 name: usr1
spec:
 type: WORKLOAD

---
kind: Service
metadata:
 name: svc1
spec:
 port: 8080
 portt: 8081

---
kind: Device
metadata:
 name: dev1
spec: {}
`), 0644))

	{
		rscList, errs, err := validateResources([]string{dir})
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 4, len(rscList))
		assert.Equal(t, 3, len(errs))
		assert.True(t, strings.Contains(errs[0].Error(), "Service `svc1`"), "%+v", errs[0])
		assert.True(t, strings.Contains(errs[1].Error(), "Device `dev1`"), "%+v", errs[1])
		assert.True(t, strings.Contains(errs[2].Error(), "User `usr1`"), "%+v", errs[2])

		assert.NotNil(t, doCmd(Cmd, []string{dir}))
		assert.NotNil(t, doCmd(Cmd, []string{usrPath, invalidPath}))
	}

	{
		_, _, err := validateResources([]string{filepath.Join(dir, "does-not-exist.yaml")})
		assert.NotNil(t, err)

		assert.NotNil(t, doCmd(Cmd, []string{t.TempDir()}))
	}
}
