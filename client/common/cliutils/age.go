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
	"time"

	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	utils_types "github.com/octelium/octelium/pkg/utils/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func GetAgeFromTimestamp(arg string) (string, error) {

	t, err := time.Parse(time.RFC3339Nano, arg)
	if err != nil {
		return "", err
	}
	return utils_types.HumanDuration(time.Since(t)), nil
}

func GetAgeFromTimestampMust(arg string) string {

	t, err := time.Parse(time.RFC3339Nano, arg)
	if err != nil {
		return ""
	}

	return utils_types.HumanDuration(time.Since(t))
}

func GetResourceAge(arg umetav1.ResourceObjectI) string {

	if arg == nil || arg.GetMetadata() == nil {
		return ""
	}

	return utils_types.HumanDuration(time.Since(arg.GetMetadata().CreatedAt.AsTime()))
}

func PrintExpiresAt(arg *timestamppb.Timestamp) string {
	if arg == nil {
		return ""
	}

	return utils_types.HumanDuration(arg.AsTime().Sub(time.Now()))
}
