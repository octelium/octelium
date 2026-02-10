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

package connect

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

func doRunDetached(args []string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}

	escapedArgs := make([]string, len(args))
	for i, arg := range args {
		escapedArgs[i] = shellEscape(arg)
	}

	innerCommand := fmt.Sprintf("%s %s > /dev/null 2>&1 &",
		shellEscape(executable),
		strings.Join(escapedArgs, " "),
	)

	script := fmt.Sprintf("do shell script %q with administrator privileges", innerCommand)

	zap.L().Debug("detached cmd", zap.String("cmd", script))

	cmd := exec.Command("osascript", "-e", script)
	return cmd.Run()
}

func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
