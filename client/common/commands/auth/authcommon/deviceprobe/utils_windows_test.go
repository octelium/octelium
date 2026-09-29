//go:build windows

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

package deviceprobe

import (
	"strconv"
	"testing"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows/registry"
)

func TestSplitHive(t *testing.T) {
	{
		hive, pth, err := splitHive(`HKLM\SOFTWARE\Vendor`)
		assert.Nil(t, err)
		assert.Equal(t, registry.LOCAL_MACHINE, hive)
		assert.Equal(t, `SOFTWARE\Vendor`, pth)
	}

	{
		hive, pth, err := splitHive(`HKEY_CURRENT_USER/Software/Vendor`)
		assert.Nil(t, err)
		assert.Equal(t, registry.CURRENT_USER, hive)
		assert.Equal(t, `Software\Vendor`, pth)
	}

	_, _, err := splitHive(`HKLM`)
	assert.NotNil(t, err)

	_, _, err = splitHive(`HKXX\SOFTWARE`)
	assert.NotNil(t, err)
}

func TestReadRegistry(t *testing.T) {
	key := `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`

	{
		res := readRegistry("probe", &authv1.DeviceProbe_ReadRegistry{
			Key:  key,
			Name: "ProductName",
		})
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		assert.NotEmpty(t, res.GetText())
		assert.NotContains(t, res.GetText(), "\x00")
	}

	{
		res := readRegistry("probe", &authv1.DeviceProbe_ReadRegistry{
			Key:  key,
			Name: "CurrentMajorVersionNumber",
		})
		assert.Equal(t, authv1.DeviceProbeResult_OK, res.Status)
		_, err := strconv.ParseUint(res.GetText(), 10, 64)
		assert.Nil(t, err)
	}

	{
		res := readRegistry("probe", &authv1.DeviceProbe_ReadRegistry{
			Key:  key,
			Name: "OcteliumMissingValue",
		})
		assert.Equal(t, authv1.DeviceProbeResult_NOT_FOUND, res.Status)
	}

	{
		res := readRegistry("probe", &authv1.DeviceProbe_ReadRegistry{
			Key:  `HKLM\SOFTWARE\OcteliumMissingKey`,
			Name: "Name",
		})
		assert.Equal(t, authv1.DeviceProbeResult_NOT_FOUND, res.Status)
	}
}
