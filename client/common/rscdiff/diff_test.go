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

package rscdiff

import (
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/stretchr/testify/assert"
)

func TestDiff(t *testing.T) {

	currentItems := []umetav1.ResourceObjectI{
		&corev1.User{
			Metadata: &metav1.Metadata{
				Name: "usr1",
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_HUMAN,
			},
		},

		&corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1",
			},
			Spec: &corev1.Service_Spec{
				Port: 8080,
			},
		},
		&corev1.Namespace{
			Metadata: &metav1.Metadata{
				Name: "ns1",
			},
			Spec: &corev1.Namespace_Spec{},
		},
	}

	desiredItems := []umetav1.ResourceObjectI{
		&corev1.User{
			Metadata: &metav1.Metadata{
				Name: "usr1",
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_HUMAN,
			},
		},

		&corev1.User{
			Metadata: &metav1.Metadata{
				Name: "usr2",
			},
			Spec: &corev1.User_Spec{
				Type: corev1.User_Spec_HUMAN,
			},
		},

		&corev1.Service{
			Metadata: &metav1.Metadata{
				Name: "svc1",
			},
			Spec: &corev1.Service_Spec{
				Port: 8081,
			},
		},
	}

	diffCtl := &diffCtl{
		currentItems: currentItems,
		desiredItems: desiredItems,
	}

	diffCtl.setDiff()

	assert.Equal(t, "usr2", diffCtl.createItems[0].GetMetadata().Name)
	assert.Equal(t, "svc1", diffCtl.updateItems[0].GetMetadata().Name)
	assert.Equal(t, "ns1", diffCtl.deleteItems[0].GetMetadata().Name)
}
