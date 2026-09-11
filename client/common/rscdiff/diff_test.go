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
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
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

func TestDiffUnsetSpec(t *testing.T) {

	currentItems := []umetav1.ResourceObjectI{
		&corev1.Group{
			Metadata: &metav1.Metadata{
				Name: "grp1",
			},
			Spec: &corev1.Group_Spec{},
		},
		&corev1.Group{
			Metadata: &metav1.Metadata{
				Name: "grp2",
			},
			Spec: &corev1.Group_Spec{
				Authorization: &corev1.Group_Spec_Authorization{
					Policies: []string{"allow-all"},
				},
			},
		},
	}

	desiredItems := []umetav1.ResourceObjectI{
		&corev1.Group{
			Metadata: &metav1.Metadata{
				Name: "grp1",
			},
		},
		&corev1.Group{
			Metadata: &metav1.Metadata{
				Name: "grp2",
			},
		},
	}

	diffCtl := &diffCtl{
		kind:         ucorev1.KindGroup,
		currentItems: currentItems,
		desiredItems: desiredItems,
	}

	diffCtl.setDiff()

	assert.Equal(t, 0, len(diffCtl.createItems))
	assert.Equal(t, 0, len(diffCtl.deleteItems))
	assert.Equal(t, 1, len(diffCtl.updateItems))
	assert.Equal(t, "grp2", diffCtl.updateItems[0].GetMetadata().Name)
}

func TestCheckDuplicateItems(t *testing.T) {

	diffCtl := &diffCtl{
		api:  ucorev1.API,
		kind: ucorev1.KindService,
		desiredItems: []umetav1.ResourceObjectI{
			&corev1.Service{
				Kind: ucorev1.KindService,
				Metadata: &metav1.Metadata{
					Name: "svc1",
				},
				Spec: &corev1.Service_Spec{},
			},
			&corev1.Service{
				Kind: ucorev1.KindService,
				Metadata: &metav1.Metadata{
					Name: "svc2.ns1",
				},
				Spec: &corev1.Service_Spec{},
			},
		},
	}

	assert.Nil(t, diffCtl.checkDuplicateItems())

	diffCtl.desiredItems = append(diffCtl.desiredItems, &corev1.Service{
		Kind: ucorev1.KindService,
		Metadata: &metav1.Metadata{
			Name: "svc1.default",
		},
		Spec: &corev1.Service_Spec{},
	})

	assert.NotNil(t, diffCtl.checkDuplicateItems())
}
