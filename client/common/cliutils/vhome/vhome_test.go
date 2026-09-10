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

package vhome

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetOcteliumHomeFromUserHome(t *testing.T) {
	{
		_, err := GetOcteliumHomeFromUserHome("")
		assert.NotNil(t, err)
	}

	{
		ret, err := GetOcteliumHomeFromUserHome("/home/usr1")
		assert.Nil(t, err)

		switch runtime.GOOS {
		case "darwin":
			assert.Equal(t, "/home/usr1/Library/Application Support/octelium", ret)
		case "windows":
			assert.Equal(t, "/home/usr1/AppData/Roaming/Octelium", ret)
		default:
			assert.Equal(t, "/home/usr1/.config/octelium", ret)
		}
	}

	if runtime.GOOS == "linux" {
		t.Setenv("XDG_CONFIG_HOME", "")

		usrHome, err := os.UserHomeDir()
		assert.Nil(t, err)

		octeliumHome, err := GetOcteliumHome()
		assert.Nil(t, err)

		ret, err := GetOcteliumHomeFromUserHome(usrHome)
		assert.Nil(t, err)
		assert.Equal(t, octeliumHome, ret)
	}
}
