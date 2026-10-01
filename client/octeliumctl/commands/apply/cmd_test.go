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

package apply

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func TestGetResourceKinds(t *testing.T) {

	setArgs := func(includes, excludes []string, includeSecret bool) {
		cmdArgs.ResourceIncludes = includes
		cmdArgs.ResourceExcludes = excludes
		cmdArgs.IncludeSecret = includeSecret
	}

	{
		setArgs(nil, nil, false)
		kinds, err := getResourceKinds()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, defaultResourceNames, kinds)
	}

	{
		setArgs([]string{ucorev1.KindGroup, ucorev1.KindUser}, nil, false)
		kinds, err := getResourceKinds()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, []string{ucorev1.KindGroup, ucorev1.KindUser}, kinds)
	}

	{
		setArgs([]string{ucorev1.KindUser, ucorev1.KindGroup}, nil, false)
		kinds, err := getResourceKinds()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, []string{ucorev1.KindGroup, ucorev1.KindUser}, kinds)
	}

	{
		setArgs(nil, []string{ucorev1.KindService}, false)
		kinds, err := getResourceKinds()
		assert.Nil(t, err, "%+v", err)
		assert.False(t, isInList(kinds, ucorev1.KindService))
		assert.True(t, isInList(kinds, ucorev1.KindUser))
	}

	{
		setArgs(nil, nil, true)
		kinds, err := getResourceKinds()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, ucorev1.KindSecret, kinds[0])
	}

	{
		setArgs(nil, []string{ucorev1.KindSecret}, true)
		kinds, err := getResourceKinds()
		assert.Nil(t, err, "%+v", err)
		assert.False(t, isInList(kinds, ucorev1.KindSecret))
	}

	{
		setArgs([]string{ucorev1.KindSecret}, nil, false)
		kinds, err := getResourceKinds()
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, []string{ucorev1.KindSecret}, kinds)
	}

	for _, arg := range []string{"user", "Users", "ClusterConfig", "Device"} {
		setArgs([]string{arg}, nil, false)
		_, err := getResourceKinds()
		assert.NotNil(t, err, "include %s", arg)

		setArgs(nil, []string{arg}, false)
		_, err = getResourceKinds()
		assert.NotNil(t, err, "exclude %s", arg)
	}

	setArgs(nil, nil, false)
}

func TestGetClusterConfig(t *testing.T) {

	newCC := func() *corev1.ClusterConfig {
		return &corev1.ClusterConfig{
			Kind: ucorev1.KindClusterConfig,
			Metadata: &metav1.Metadata{
				Name: "default",
			},
			Spec: &corev1.ClusterConfig_Spec{},
		}
	}

	rscList := []umetav1.ResourceObjectI{
		&corev1.User{
			Kind: ucorev1.KindUser,
			Metadata: &metav1.Metadata{
				Name: "usr1",
			},
			Spec: &corev1.User_Spec{},
		},
	}

	cc, err := getClusterConfig(rscList)
	assert.Nil(t, err, "%+v", err)
	assert.Nil(t, cc)

	rscList = append(rscList, newCC())

	cc, err = getClusterConfig(rscList)
	assert.Nil(t, err, "%+v", err)
	assert.NotNil(t, cc)

	rscList = append(rscList, newCC())

	_, err = getClusterConfig(rscList)
	assert.NotNil(t, err)
}

func TestValidateResources(t *testing.T) {

	newCC := func() *corev1.ClusterConfig {
		return &corev1.ClusterConfig{
			Kind: ucorev1.KindClusterConfig,
			Metadata: &metav1.Metadata{
				Name: "default",
			},
			Spec: &corev1.ClusterConfig_Spec{},
		}
	}

	newUser := func(name string) *corev1.User {
		return &corev1.User{
			Kind: ucorev1.KindUser,
			Metadata: &metav1.Metadata{
				Name: name,
			},
			Spec: &corev1.User_Spec{},
		}
	}

	rscList := []umetav1.ResourceObjectI{
		newCC(),
		newUser("usr1"),
		newUser("usr2"),
		&corev1.Secret{
			Kind: ucorev1.KindSecret,
			Metadata: &metav1.Metadata{
				Name: "sec1",
			},
			Spec: &corev1.Secret_Spec{},
		},
	}

	assert.Equal(t, 0, len(ValidateResources(rscList)))

	rscList = append(rscList, &corev1.Device{
		Kind: ucorev1.KindDevice,
		Metadata: &metav1.Metadata{
			Name: "dev1",
		},
		Spec: &corev1.Device_Spec{},
	})

	errs := ValidateResources(rscList)
	assert.Equal(t, 1, len(errs))
	assert.True(t, strings.Contains(errs[0].Error(), "Device `dev1`"), "%+v", errs[0])

	rscList = append(rscList, newCC(), newUser("usr1"))

	errs = ValidateResources(rscList)
	assert.Equal(t, 3, len(errs))
	assert.True(t, strings.Contains(errs[1].Error(), "ClusterConfig"), "%+v", errs[1])
	assert.True(t, strings.Contains(errs[2].Error(), "User `usr1`"), "%+v", errs[2])
}

func TestGetCmpMetadata(t *testing.T) {

	cc := &corev1.ClusterConfig{
		Metadata: &metav1.Metadata{
			Name:        "default",
			DisplayName: "Cluster",
		},
	}

	curCC := &corev1.ClusterConfig{
		Metadata: &metav1.Metadata{
			Name:            "default",
			DisplayName:     "Cluster",
			Uid:             "9f0b0f4a",
			ResourceVersion: "01",
		},
	}

	assert.True(t, pbutils.IsEqual(getCmpMetadata(cc), getCmpMetadata(curCC)))

	cc.Metadata.DisplayName = "Cluster 01"

	assert.False(t, pbutils.IsEqual(getCmpMetadata(cc), getCmpMetadata(curCC)))

	assert.True(t, pbutils.IsEqual(
		getCmpMetadata(&corev1.ClusterConfig{}), getCmpMetadata(&corev1.ClusterConfig{})))
}

type fakeMainServiceClient struct {
	corev1.MainServiceClient

	cc          *corev1.ClusterConfig
	updateCount int
}

func (c *fakeMainServiceClient) GetClusterConfig(ctx context.Context,
	req *corev1.GetClusterConfigRequest, opts ...grpc.CallOption) (*corev1.ClusterConfig, error) {
	return c.cc, nil
}

func (c *fakeMainServiceClient) UpdateClusterConfig(ctx context.Context,
	req *corev1.ClusterConfig, opts ...grpc.CallOption) (*corev1.ClusterConfig, error) {
	c.updateCount++
	c.cc = req
	return req, nil
}

func TestApplyClusterConfig(t *testing.T) {

	ctx := context.Background()

	newCC := func(displayName string) *corev1.ClusterConfig {
		return &corev1.ClusterConfig{
			Kind: ucorev1.KindClusterConfig,
			Metadata: &metav1.Metadata{
				Name:        "default",
				DisplayName: displayName,
			},
			Spec: &corev1.ClusterConfig_Spec{},
		}
	}

	{
		cmdArgs.DryRun = false
		fakeC := &fakeMainServiceClient{
			cc: newCC("Cluster"),
		}

		err := applyClusterConfig(ctx, fakeC, newCC("Cluster"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, fakeC.updateCount)

		err = applyClusterConfig(ctx, fakeC, newCC("Cluster 01"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 1, fakeC.updateCount)
		assert.Equal(t, "Cluster 01", fakeC.cc.Metadata.DisplayName)
	}

	{
		cmdArgs.DryRun = true
		fakeC := &fakeMainServiceClient{
			cc: newCC("Cluster"),
		}

		err := applyClusterConfig(ctx, fakeC, newCC("Cluster"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, fakeC.updateCount)

		err = applyClusterConfig(ctx, fakeC, newCC("Cluster 01"))
		assert.Nil(t, err, "%+v", err)
		assert.Equal(t, 0, fakeC.updateCount)
		assert.Equal(t, "Cluster", fakeC.cc.Metadata.DisplayName)
	}

	cmdArgs.DryRun = false
}

func TestSupportedResourceKindsAreUsable(t *testing.T) {

	client := reflect.ValueOf(corev1.NewMainServiceClient(nil))

	for _, kind := range supportedResourceNames {
		obj, err := ucorev1.NewObject(kind)
		assert.Nil(t, err, "kind %s: %+v", kind, err)
		assert.NotNil(t, obj, "kind %s", kind)

		listOpts, err := ucorev1.NewObjectListOptions(kind)
		assert.Nil(t, err, "kind %s: %+v", kind, err)
		assert.NotNil(t, listOpts, "kind %s", kind)

		for _, verb := range []string{"List", "Create", "Update", "Delete"} {
			assert.True(t, client.MethodByName(verb+kind).IsValid(),
				"the Cluster API has no %s%s method", verb, kind)
		}
	}
}
