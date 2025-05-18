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

	rscList, err := loadResources(strings.NewReader(yamlFile), ucorev1.NewObject)
	assert.Nil(t, err, "%+v", err)

	assert.Equal(t, 3, len(rscList))

	assert.Equal(t, "usr1", rscList[0].(*corev1.User).Metadata.Name)
	assert.Equal(t, "ns1", rscList[1].(*corev1.Namespace).Metadata.Name)
	assert.Equal(t, "https://example.com", rscList[2].(*corev1.Service).Spec.GetConfig().GetUpstream().GetUrl())
}
