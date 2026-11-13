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
	"os/exec"
	"strings"

	"github.com/pkg/errors"
)

const maxSessionIDLen = 64

var loginctlPath = "loginctl"

func HasLoginSession(ctx context.Context, pr *Principal) (bool, error) {
	out, err := runLoginctl(ctx, "--property=Sessions", "show-user", pr.ID)
	if err != nil {
		if _, err := runLoginctl(ctx, "--no-legend", "list-sessions"); err != nil {
			return false, errors.Errorf("Could not list the login sessions via loginctl: %+v", err)
		}

		return false, nil
	}

	for _, sessionID := range strings.Fields(getLoginctlProperty(out, "Sessions")) {
		if !isValidSessionID(sessionID) {
			continue
		}

		out, err := runLoginctl(ctx, "--property=Class", "show-session", sessionID)
		if err != nil {
			continue
		}

		if isUserSessionClass(getLoginctlProperty(out, "Class")) {
			return true, nil
		}
	}

	return false, nil
}

func runLoginctl(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, loginctlPath, append([]string{"--no-pager"}, args...)...).Output()
}

func getLoginctlProperty(out []byte, name string) string {
	for line := range strings.Lines(string(out)) {
		if ret, ok := strings.CutPrefix(strings.TrimSpace(line), name+"="); ok {
			return ret
		}
	}

	return ""
}

func isValidSessionID(arg string) bool {
	if arg == "" || len(arg) > maxSessionIDLen {
		return false
	}

	for _, c := range arg {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return false
		}
	}

	return true
}

func isUserSessionClass(class string) bool {
	return class == "user" || strings.HasPrefix(class, "user-")
}
