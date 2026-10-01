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
	"context"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
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

type fakeMainServiceClient struct {
	corev1.MainServiceClient

	createCount int
	updateCount int
	deleteCount int
}

func (c *fakeMainServiceClient) CreateUser(ctx context.Context,
	req *corev1.User, opts ...grpc.CallOption) (*corev1.User, error) {
	c.createCount++
	return req, nil
}

func (c *fakeMainServiceClient) UpdateUser(ctx context.Context,
	req *corev1.User, opts ...grpc.CallOption) (*corev1.User, error) {
	c.updateCount++
	return req, nil
}

func (c *fakeMainServiceClient) DeleteUser(ctx context.Context,
	req *metav1.DeleteOptions, opts ...grpc.CallOption) (*metav1.OperationResult, error) {
	c.deleteCount++
	return &metav1.OperationResult{}, nil
}

func TestApplyDryRun(t *testing.T) {

	ctx := context.Background()

	newUser := func(name string, typ corev1.User_Spec_Type) *corev1.User {
		return &corev1.User{
			Kind: ucorev1.KindUser,
			Metadata: &metav1.Metadata{
				Name: name,
			},
			Spec: &corev1.User_Spec{
				Type: typ,
			},
		}
	}

	currentItems := []umetav1.ResourceObjectI{
		newUser("usr1", corev1.User_Spec_HUMAN),
		newUser("usr2", corev1.User_Spec_HUMAN),
		newUser("usr3", corev1.User_Spec_HUMAN),
	}

	desiredItems := []umetav1.ResourceObjectI{
		newUser("usr1", corev1.User_Spec_HUMAN),
		newUser("usr2", corev1.User_Spec_WORKLOAD),
		newUser("usr4", corev1.User_Spec_HUMAN),
	}

	for _, doDelete := range []bool{false, true} {
		for _, dryRun := range []bool{false, true} {
			fakeC := &fakeMainServiceClient{}

			diffCtl, err := NewDiffCtl(ucorev1.API, ucorev1.KindUser, fakeC,
				nil, nil, desiredItems, doDelete, dryRun)
			assert.Nil(t, err, "%+v", err)

			diffCtl.currentItems = currentItems
			diffCtl.setDiff()

			ret := &DiffCtlResponse{}

			err = diffCtl.Apply(ctx, ret)
			assert.Nil(t, err, "%+v", err)

			err = diffCtl.Prune(ctx, ret)
			assert.Nil(t, err, "%+v", err)

			assert.Equal(t, 1, ret.CountCreated)
			assert.Equal(t, 1, ret.CountUpdated)
			if doDelete {
				assert.Equal(t, 1, ret.CountDeleted)
			} else {
				assert.Equal(t, 0, ret.CountDeleted)
			}

			if dryRun {
				assert.Equal(t, 0, fakeC.createCount)
				assert.Equal(t, 0, fakeC.updateCount)
				assert.Equal(t, 0, fakeC.deleteCount)
			} else {
				assert.Equal(t, ret.CountCreated, fakeC.createCount)
				assert.Equal(t, ret.CountUpdated, fakeC.updateCount)
				assert.Equal(t, ret.CountDeleted, fakeC.deleteCount)
			}
		}
	}
}

func TestCheckDuplicateCoreResources(t *testing.T) {

	newSvc := func(name string) *corev1.Service {
		return &corev1.Service{
			Kind: ucorev1.KindService,
			Metadata: &metav1.Metadata{
				Name: name,
			},
			Spec: &corev1.Service_Spec{},
		}
	}

	kinds := []string{ucorev1.KindUser, ucorev1.KindGroup, ucorev1.KindService}

	desiredItems := []umetav1.ResourceObjectI{
		newSvc("svc1"),
		newSvc("svc2.ns1"),
		&corev1.User{
			Kind: ucorev1.KindUser,
			Metadata: &metav1.Metadata{
				Name: "usr1",
			},
			Spec: &corev1.User_Spec{},
		},
		&corev1.Group{
			Kind: ucorev1.KindGroup,
			Metadata: &metav1.Metadata{
				Name: "usr1",
			},
			Spec: &corev1.Group_Spec{},
		},
	}

	assert.Equal(t, 0, len(CheckDuplicateCoreResources(kinds, desiredItems)))

	desiredItems = append(desiredItems, newSvc("svc1.default"), newSvc("svc1"))

	errs := CheckDuplicateCoreResources(kinds, desiredItems)
	assert.Equal(t, 1, len(errs))
	assert.True(t, strings.Contains(errs[0].Error(), "svc1.default"), "%+v", errs[0])

	assert.Equal(t, 0, len(CheckDuplicateCoreResources([]string{ucorev1.KindUser}, desiredItems)))
}
