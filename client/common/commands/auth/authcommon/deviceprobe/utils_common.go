//go:build !windows

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
	"os"

	"github.com/octelium/octelium/apis/main/authv1"
)

func isElevated() bool {
	return os.Geteuid() == 0
}

func readRegistry(probeID string, _ *authv1.DeviceProbe_ReadRegistry) *authv1.DeviceProbeResult {
	return probeStatus(probeID, authv1.DeviceProbeResult_UNSUPPORTED,
		"registry probe not supported on this platform")
}

func getCommandEnv() []string {
	return []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
	}
}
