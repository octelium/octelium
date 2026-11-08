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

package cliutils

import (
	"fmt"
	"regexp"
	"runtime"

	"github.com/octelium/octelium/pkg/utils/ldflags"
)

type OcteliumCommonVersion struct {
	ReleaseVersion string `json:"releaseVersion,omitempty"`
	BuildDate      string `json:"buildDate,omitempty"`
	GitCommit      string `json:"gitCommit,omitempty"`
	GoVersion      string `json:"goVersion,omitempty"`
	APIVersion     string `json:"apiVersion,omitempty"`
}

func GetOcteliumCommonVersion() *OcteliumCommonVersion {

	ret := &OcteliumCommonVersion{
		ReleaseVersion: ldflags.SemVer,
		GoVersion:      runtime.Version(),
		GitCommit:      ldflags.GitCommit,
		APIVersion:     "v1",
	}

	return ret
}

var rgxGitCommit = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

func GetUserAgent() string {
	return fmt.Sprintf("octelium-cli/%s", getUserAgentVersion())
}

func getUserAgentVersion() string {
	if ldflags.SemVer != "" {
		return ldflags.SemVer
	}

	if rgxGitCommit.MatchString(ldflags.GitCommit) {
		return fmt.Sprintf("v0.0.0-dev+%s", ldflags.GitCommit[:min(len(ldflags.GitCommit), 12)])
	}

	return "v0.0.0-dev"
}
