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

package deviceinfo

import (
	"context"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDeviceInfoFromCtx(t *testing.T) {
	info := &DeviceInfo{
		ID:           "abcdef",
		Hostname:     "phone",
		SerialNumber: "1234",
	}

	ret, err := GetDeviceInfo(WithDeviceInfo(context.Background(), info))
	assert.Nil(t, err)
	assert.Equal(t, info, ret)
}

func TestHashID(t *testing.T) {
	rgx := regexp.MustCompile(`^[a-f0-9]{64}$`)

	for _, arg := range []string{
		"3f2a8c1e-7b4d-4e6a-9c2f-1d5e8b7a6c43",
		"3F2A8C1E-7B4D-4E6A-9C2F-1D5E8B7A6C43",
		"abcdef",
	} {
		ret := HashID(arg)
		assert.True(t, rgx.MatchString(ret), "arg: %s", arg)
		assert.Equal(t, ret, HashID(arg))
	}

	assert.NotEqual(t, HashID("abc"), HashID("abd"))
	assert.Equal(t,
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", HashID("abc"))
}
