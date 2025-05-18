/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package apivalidation

import (
	"testing"

	"github.com/octelium/octelium/apis/main/corev1"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/common/tests"
	"github.com/octelium/octelium/cluster/common/vutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/grpcerr"
	"github.com/octelium/octelium/pkg/utils/utilrand"
	"github.com/stretchr/testify/assert"
)

func TestValidateCommon(t *testing.T) {

	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		invalids := []umetav1.ResourceObjectI{
			nil,
			&corev1.Device{},
			&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
			},
		}

		for _, valid := range invalids {
			err := ValidateCommon(valid, nil)
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsInvalidArg(err))
		}
	}

	{
		invalids := []umetav1.ResourceObjectI{
			&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
				Spec: &corev1.Namespace_Spec{},
			},
		}

		for _, valid := range invalids {
			err := ValidateCommon(valid, &ValidateCommonOpts{
				ValidateMetadataOpts: ValidateMetadataOpts{
					ParentsMust: 1,
				},
			})
			assert.NotNil(t, err)
			assert.True(t, grpcerr.IsInvalidArg(err))
		}
	}

	{
		valids := []umetav1.ResourceObjectI{
			&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
				},
				Spec: &corev1.Namespace_Spec{},
			},
		}

		for _, valid := range valids {
			assert.Nil(t, ValidateCommon(valid, nil))
		}
	}

	{
		{
			assert.Nil(t, ValidateCommon(&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
					Tags: []string{"tag1"},
				},
				Spec: &corev1.Namespace_Spec{},
			}, nil))
		}

		{
			assert.NotNil(t, ValidateCommon(&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
					Tags: []string{"tag1", "Tag2"},
				},
				Spec: &corev1.Namespace_Spec{},
			}, nil))
		}

		{
			assert.NotNil(t, ValidateCommon(&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
					Tags: []string{"tag1", ""},
				},
				Spec: &corev1.Namespace_Spec{},
			}, nil))
		}

		{
			assert.NotNil(t, ValidateCommon(&corev1.Namespace{
				Metadata: &metav1.Metadata{
					Name: utilrand.GetRandomStringCanonical(8),
					Tags: []string{"tag1", "tag2", "tag1"},
				},
				Spec: &corev1.Namespace_Spec{},
			}, nil))
		}
	}
}

func TestValidateName(t *testing.T) {
	type tstCase struct {
		arg         string
		parentsMust uint64
		parentsMax  uint64
	}

	invalids := []tstCase{
		{},
		{
			arg: "Arg01",
		},
		{
			arg: "arg:abc",
		},
		{
			arg: utilrand.GetRandomStringCanonical(60),
		},
		{
			arg: utilrand.GetRandomStringCanonical(41),
		},
		{
			arg: "arg-",
		},
		{
			arg: "arg_",
		},
		{
			arg: "arg--abc",
		},
		{
			arg: ".",
		},
		{
			arg: "..",
		},
		{
			arg: "...",
		},
		{
			arg: "a.b",
		},
		{
			arg: "arg.",
		},
		{
			arg: "arg.abc.",
		},
		{
			arg:         "arg.abc.",
			parentsMust: 1,
		},
		{
			arg:         "arg",
			parentsMust: 1,
		},
		{
			arg:         "arg.abc",
			parentsMust: 2,
		},
	}

	for _, invalid := range invalids {
		assert.NotNil(t, validateName(invalid.arg, invalid.parentsMust, invalid.parentsMax))
	}
}

func TestCheckGetOptions(t *testing.T) {
	{
		assert.NotNil(t, CheckGetOptions(nil, nil))
	}
	{
		assert.NotNil(t, CheckGetOptions(&metav1.GetOptions{}, nil))
	}
	{
		assert.NotNil(t, CheckGetOptions(&metav1.GetOptions{
			Uid: utilrand.GetRandomStringCanonical(8),
		}, nil))
	}

	{
		assert.Nil(t, CheckGetOptions(&metav1.GetOptions{
			Name: utilrand.GetRandomStringCanonical(8),
		}, nil))
	}

	{
		assert.Nil(t, CheckGetOptions(&metav1.GetOptions{
			Uid: vutils.UUIDv4(),
		}, nil))
	}

	{
		assert.Nil(t, CheckGetOptions(&metav1.GetOptions{
			Name: utilrand.GetRandomStringCanonical(8),
			Uid:  vutils.UUIDv4(),
		}, nil))
	}
}

func TestGetNameAndParents(t *testing.T) {

	tst, err := tests.Initialize(nil)

	assert.Nil(t, err)
	t.Cleanup(func() {
		tst.Destroy()
	})

	{
		ret, err := GetNameAndParents("aa.bb.cc.dd")
		assert.Nil(t, err)
		assert.Equal(t, 4, len(ret))
		assert.Equal(t, "aa.bb.cc.dd", ret[0])
		assert.Equal(t, "bb.cc.dd", ret[1])
		assert.Equal(t, "cc.dd", ret[2])
		assert.Equal(t, "dd", ret[3])
	}

	{
		ret, err := GetNameAndParents("abc")
		assert.Nil(t, err)
		assert.Equal(t, 1, len(ret))
		assert.Equal(t, "abc", ret[0])
	}

	{
		_, err := GetNameAndParents("")
		assert.NotNil(t, err)
	}
}
