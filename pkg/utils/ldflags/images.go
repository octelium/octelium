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

package ldflags

import (
	"fmt"
	"regexp"
)

var ImageRegistry = ""
var ImageRegistryPrefix = ""

var rgxSemVer = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
var rgxSemVer2 = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func getImageVersion() string {
	if GitTag != "" && rgxSemVer.MatchString(GitTag) {
		return GitTag[1:]
	}

	if GitTag != "" && rgxSemVer2.MatchString(GitTag) {
		return GitTag
	}

	if GitBranch != "" {
		return GitBranch
	}

	return "latest"
}

func GetVersion() string {
	return getImageVersion()
}

func getImageURL(imageName string, version string) string {
	if version == "" {
		version = getImageVersion()
	}

	if ImageRegistry == "" && ImageRegistryPrefix == "" {
		return fmt.Sprintf("%s:%s", imageName, version)
	}

	if ImageRegistryPrefix == "" {
		return fmt.Sprintf("%s/%s:%s", ImageRegistry, imageName, version)
	}

	return fmt.Sprintf("%s/%s/%s:%s", ImageRegistry, ImageRegistryPrefix, imageName, version)
}

func GetImage(imageName string, version string) string {
	return getImageURL(imageName, version)
}
