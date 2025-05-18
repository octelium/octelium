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
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func doRunDetached(args []string) error {

	executable, err := os.Executable()
	if err != nil {
		return err
	}

	cmd := []string{executable}
	cmd = append(cmd, args...)

	tmpfile, err := ioutil.TempFile("", "octelium-detached")
	if err != nil {
		return err
	}

	zap.S().Debugf("tmp file = %s", tmpfile.Name())

	tempfPath := tmpfile.Name()

	scriptContent, err := getScript(&tmplArgs{
		Cmd: strings.Join(cmd, " "),
	})
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(tempfPath, scriptContent, 0700); err != nil {
		return err
	}

	if out, err := exec.Command("sudo", "chown", "root", tempfPath).CombinedOutput(); err != nil {
		return errors.Errorf("Could not chown: %+v. %s", err, out)
	}

	if out, err := exec.Command("sudo", "chmod", "700", tempfPath).CombinedOutput(); err != nil {
		return errors.Errorf("Could not chmod: %+v. %s", err, out)
	}

	if out, err := exec.Command("sudo", tempfPath).CombinedOutput(); err != nil {
		return errors.Errorf("Could not run detached script: %+v. %s", err, out)
	}

	tmpfile.Close()
	os.Remove(tempfPath)

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
