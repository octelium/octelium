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
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/manifoldco/promptui"
	"github.com/octelium/octelium/pkg/utils/ldflags"
	"github.com/pkg/errors"
)

func doRunDetached(args []string) error {

	if ldflags.IsProduction() {
		return errors.Errorf(`Detached mode is not available for MacOS. Use "sudo -E octelium connect" instead.`)
	}

	executable, err := os.Executable()
	if err != nil {
		return err
	}

	shellCommand := fmt.Sprintf(
		"nohup sudo -S %s %s > /dev/null 2>&1 &",
		executable,
		strings.Join(args, " "),
	)

	cmd := exec.Command("bash", "-c", shellCommand)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	defer stdin.Close()

	if err := cmd.Start(); err != nil {
		return err
	}

	prompt := promptui.Prompt{
		Label:       "Enter root password",
		HideEntered: true,
		Mask:        '*',
	}

	res, err := prompt.Run()
	if err != nil {
		return err
	}

	if _, err := stdin.Write([]byte(res)); err != nil {
		return err
	}

	return nil
}

var tmplScript = `
#!/bin/bash
cmd="{{.Cmd}}"
eval "${cmd}" &>/dev/null & disown;
`

type tmplArgs struct {
	Cmd string
}

func getScript(args *tmplArgs) ([]byte, error) {
	t, err := template.New("macos-detached").Parse(tmplScript)
	if err != nil {
		return nil, err
	}

	var tpl bytes.Buffer

	if err := t.Execute(&tpl, args); err != nil {
		return nil, err
	}

	return tpl.Bytes(), nil
}
