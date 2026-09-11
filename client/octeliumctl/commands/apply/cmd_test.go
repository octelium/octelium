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
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/pkg/apiutils/ucorev1"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/stretchr/testify/assert"
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
