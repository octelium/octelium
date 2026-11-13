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

package ipc

import (
	"context"

	"golang.org/x/sys/windows"
)

func HasLoginSession(_ context.Context, pr *Principal) (bool, error) {
	return pr.isInteractive, pr.isInteractiveErr
}

func isInteractiveToken(token windows.Token) (bool, error) {
	groups, err := token.GetTokenGroups()
	if err != nil {
		return false, err
	}

	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_ENABLED != 0 &&
			group.Sid.IsWellKnown(windows.WinInteractiveSid) {
			return true, nil
		}
	}

	return false, nil
}
