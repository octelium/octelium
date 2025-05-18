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

package utils_types

func Int64ToPtr(arg int64) *int64 {
	return &arg
}

func IntToPtr(arg int) *int {
	return &arg
}

func Int32ToPtr(arg int32) *int32 {
	return &arg
}

func Float64ToPtr(arg float64) *float64 {
	return &arg
}

func BoolToPtr(arg bool) *bool {
	return &arg
}

func StrToPtr(arg string) *string {
	return &arg
}
