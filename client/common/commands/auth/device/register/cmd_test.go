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

package register

import (
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/octelium/octelium/apis/main/authv1"
	"github.com/stretchr/testify/assert"
)

func TestGetOSType(t *testing.T) {
	switch runtime.GOOS {
	case "linux":
		assert.Equal(t, authv1.RegisterDeviceBeginRequest_Info_LINUX, getOSType())
	case "darwin":
		assert.Equal(t, authv1.RegisterDeviceBeginRequest_Info_MAC, getOSType())
	case "windows":
		assert.Equal(t, authv1.RegisterDeviceBeginRequest_Info_WINDOWS, getOSType())
	case "android":
		assert.Equal(t, authv1.RegisterDeviceBeginRequest_Info_ANDROID, getOSType())
	case "ios":
		assert.Equal(t, authv1.RegisterDeviceBeginRequest_Info_IOS, getOSType())
	}
}

func TestGetHostname(t *testing.T) {
	tests := []struct {
		arg      string
		expected string
	}{
		{"", ""},
		{"  Pixel 8 Pro ", "Pixel 8 Pro"},
		{strings.Repeat("a", 32), strings.Repeat("a", 32)},
		{strings.Repeat("a", 40), strings.Repeat("a", 32)},
		{strings.Repeat("a", 31) + "é", strings.Repeat("a", 31)},
		{strings.Repeat("a", 30) + "é" + "b", strings.Repeat("a", 30) + "é"},
		{strings.Repeat("a", 31) + " " + "bbbb", strings.Repeat("a", 31)},
		{strings.Repeat("日本", 10), strings.Repeat("日本", 5)},
	}

	for _, tc := range tests {
		ret := getHostname(tc.arg)
		assert.Equal(t, tc.expected, ret, "arg: %q", tc.arg)
		assert.LessOrEqual(t, len(ret), maxHostnameLen)
		assert.True(t, utf8.ValidString(ret))
	}
}
