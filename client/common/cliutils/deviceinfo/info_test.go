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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsInvalidSerialNumber(t *testing.T) {
	tests := []struct {
		arg     string
		invalid bool
	}{
		{"", true},
		{"   ", true},
		{"12345", true},
		{"0", true},
		{"000000000000", true},
		{"FFFFFFFF", true},
		{"Default string", true},
		{"To Be Filled By O.E.M.", true},
		{"System Serial Number", true},
		{"Chassis Serial Number", true},
		{"Not Specified", true},
		{"0123456789", true},
		{"123456789", true},
		{"None", true},
		{"UNKNOWN", true},
		{"C02XK1ABJHD3", false},
		{"  PF2ABCDE ", false},
		{"VMware-56 4d 12 34", false},
		{"0000000001", false},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.invalid, isInvalidSerialNumber(tc.arg), "arg: %q", tc.arg)
	}
}

func TestIsUsableMacAddress(t *testing.T) {
	tests := []struct {
		arg    string
		usable bool
	}{
		{"00:1a:2b:3c:4d:5e", true},
		{"a4:83:e7:12:34:56", true},
		{"02:42:ac:11:00:02", false},
		{"da:a1:19:12:34:56", false},
		{"01:00:5e:00:00:01", false},
		{"ff:ff:ff:ff:ff:ff", false},
		{"00:00:00:00:00:00", false},
		{"00:00:00:00:fe:80:00:00:00:00:00:00:02:00:5e:10:00:00:00:01", false},
	}

	for _, tc := range tests {
		hw, err := net.ParseMAC(tc.arg)
		assert.Nil(t, err)
		assert.Equal(t, tc.usable, isUsableMacAddress(hw), "arg: %s", tc.arg)
	}

	assert.False(t, isUsableMacAddress(nil))
}

func TestGetDeviceInfo(t *testing.T) {
	info, err := GetDeviceInfo(context.Background())
	if err != nil {
		t.Skipf("Could not get the device info in this environment: %+v", err)
	}

	assert.Equal(t, 64, len(info.ID))

	if info.SerialNumber != "" {
		assert.False(t, isInvalidSerialNumber(info.SerialNumber))
	}

	for _, addr := range info.MacAddresses {
		hw, err := net.ParseMAC(addr)
		assert.Nil(t, err)
		assert.True(t, isUsableMacAddress(hw))
	}

	macs, err := GetMacAddresses()
	assert.Nil(t, err)
	assert.Equal(t, info.MacAddresses, macs)
}
